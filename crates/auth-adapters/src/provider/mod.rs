//! External identity provider adapters (`internal/adapter/out/provider`).
//!
//! Google and GitHub implement the [`IdentityProvider`] port with `reqwest`. They
//! mirror the Go adapters: the same form fields and headers, any status `>= 400`
//! is an error, no ID-token verification, and the same `fmt.Errorf` texts, since
//! those can reach clients as a 502 `error_description`.
//!
//! [`IdentityProvider`]: auth_core::ports::IdentityProvider

mod authorize_url;
mod github;
mod google;

use std::error::Error as StdError;
use std::time::Duration;

use auth_core::ports::ProviderError;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

pub use authorize_url::{
    GITHUB_AUTHORIZE_URL, GOOGLE_AUTHORIZE_URL, github_authorization_url, google_authorization_url,
    provider_authorization_url,
};
pub use github::{GITHUB_API_BASE_URL, GITHUB_TOKEN_URL, GitHubProvider};
pub use google::{GOOGLE_TOKEN_URL, GOOGLE_USERINFO_URL, GoogleProvider};

/// Go's `http.Client{Timeout: 10 * time.Second}`.
pub const PROVIDER_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Sent on every provider request. GitHub's REST API rejects requests without a
/// `User-Agent`; Go sent `Go-http-client/1.1`.
const USER_AGENT: &str = "auth-server";

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

fn http_client() -> Result<reqwest::Client, ProviderError> {
    reqwest::Client::builder()
        .timeout(PROVIDER_HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|error| ProviderError::new(error_chain(&error)))
}

/// Go's `firstNonEmpty`.
fn first_non_empty<'a>(first: &'a str, second: &'a str) -> &'a str {
    if first.is_empty() { second } else { first }
}

/// Go's `url.QueryEscape`: unreserved bytes stay, space becomes `+`, every
/// other byte is `%XX` with upper-case hex.
pub(crate) fn go_query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    out
}

/// Go's `url.Values.Encode` for single-valued keys: sorted by key, `k=v` joined
/// with `&`, both sides `QueryEscape`d.
pub(crate) fn go_encode_values(pairs: &[(&str, &str)]) -> String {
    let mut sorted: Vec<&(&str, &str)> = pairs.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    let mut out = String::new();
    for (key, value) in sorted {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&go_query_escape(key));
        out.push('=');
        out.push_str(&go_query_escape(value));
    }
    out
}

/// Joins an error and its sources with `": "`, like Go's wrapped error text.
fn error_chain(error: &(dyn StdError + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        let inner_text = inner.to_string();
        if !text.ends_with(&inner_text) {
            text.push_str(": ");
            text.push_str(&inner_text);
        }
        source = inner.source();
    }
    text
}

/// Go's `*url.Error` text for a failed `client.Do`: `Post "https://...": <cause>`.
fn transport_error(method: &str, url: &str, error: reqwest::Error) -> ProviderError {
    let error = error.without_url();
    let cause = if error.is_timeout() {
        "context deadline exceeded (Client.Timeout exceeded while awaiting headers)".to_owned()
    } else {
        error_chain(&error)
    };
    ProviderError::new(format!("{method} \"{url}\": {cause}"))
}

/// Go's `resp.Status` (`"400 Bad Request"`). Go builds it from `StatusText` for
/// HTTP/2 responses (Google and GitHub), which leaves `"599 "` for unknown codes.
fn go_status(status: StatusCode) -> String {
    format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default()
    )
}

/// `if resp.StatusCode >= http.StatusBadRequest { return fmt.Errorf("<prefix>: %s", resp.Status) }`.
fn check_status(status: StatusCode, prefix: &str) -> Result<(), ProviderError> {
    if status.as_u16() >= 400 {
        return Err(ProviderError::new(format!(
            "{prefix}: {}",
            go_status(status)
        )));
    }
    Ok(())
}

/// Reads the body and decodes it like Go's `json.NewDecoder(body).Decode(&v)`:
/// only the first JSON value is read (trailing bytes are ignored), an empty
/// body is `EOF`, and a top-level `null` leaves the zero value.
async fn decode_json<T: DeserializeOwned + Default>(
    response: reqwest::Response,
) -> Result<T, ProviderError> {
    let body = response
        .bytes()
        .await
        .map_err(|error| ProviderError::new(error_chain(&error.without_url())))?;
    decode_first_json(&body)
}

fn decode_first_json<T: DeserializeOwned + Default>(body: &[u8]) -> Result<T, ProviderError> {
    let mut stream = serde_json::Deserializer::from_slice(body).into_iter::<Option<T>>();
    match stream.next() {
        None => Err(ProviderError::new("EOF")),
        Some(Ok(value)) => Ok(value.unwrap_or_default()),
        Some(Err(error)) if error.is_eof() => Err(ProviderError::new("unexpected EOF")),
        Some(Err(error)) => Err(ProviderError::new(error.to_string())),
    }
}

/// `struct{ AccessToken string \`json:"access_token"\` }`. A provider error
/// object (`{"error": ...}`) decodes to an empty token, as in Go.
#[derive(Debug, Default, serde::Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_escape_matches_go() {
        assert_eq!(go_query_escape("a b+c*~/:"), "a+b%2Bc%2A~%2F%3A");
        assert_eq!(go_query_escape("ไทย"), "%E0%B9%84%E0%B8%97%E0%B8%A2");
    }

    #[test]
    fn values_are_sorted_by_key() {
        assert_eq!(
            go_encode_values(&[("b", "2"), ("a", "x y"), ("c", "")]),
            "a=x+y&b=2&c="
        );
    }

    #[test]
    fn status_text_matches_go() {
        assert_eq!(go_status(StatusCode::BAD_REQUEST), "400 Bad Request");
        assert_eq!(
            go_status(StatusCode::from_u16(599).unwrap_or(StatusCode::OK)),
            "599 "
        );
        assert!(check_status(StatusCode::from_u16(399).unwrap_or(StatusCode::OK), "x").is_ok());
        assert_eq!(
            check_status(StatusCode::UNAUTHORIZED, "github user fetch failed")
                .err()
                .map(|error| error.to_string()),
            Some("github user fetch failed: 401 Unauthorized".to_owned())
        );
    }

    #[test]
    fn decoder_mirrors_go_json_decoder() {
        let token: TokenResponse =
            decode_first_json(br#"{"access_token":"t"} trailing"#).unwrap_or_default();
        assert_eq!(token.access_token.as_deref(), Some("t"));
        let null: TokenResponse = decode_first_json(b"null").unwrap_or_default();
        assert_eq!(null.access_token, None);
        let field_null: TokenResponse =
            decode_first_json(br#"{"access_token":null}"#).unwrap_or_default();
        assert_eq!(field_null.access_token, None);
        assert_eq!(
            decode_first_json::<TokenResponse>(b"  ")
                .map_err(|error| error.to_string())
                .err(),
            Some("EOF".to_owned())
        );
        assert_eq!(
            decode_first_json::<TokenResponse>(br#"{"access_token":"#)
                .map_err(|error| error.to_string())
                .err(),
            Some("unexpected EOF".to_owned())
        );
        assert!(decode_first_json::<TokenResponse>(b"[1]").is_err());
    }
}
