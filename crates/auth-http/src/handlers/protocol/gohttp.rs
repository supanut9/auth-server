//! Go `net/http`, `net/url` and `fmt` behavior the protocol handlers rely
//! on: form and query parsing (`url.ParseQuery`, gin `PostForm`/`Query`),
//! `Request.BasicAuth`, `http.Redirect`, `splitProtocolList`, `time.Time`
//! JSON rendering and `fmt.Sprint` of decoded JWT claims.

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::Serializer;
use serde_json::{Value, json};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::{go_url, json::json_response};

/// Go `http.defaultMaxMemory`-independent cap on urlencoded bodies
/// (`net/http` `maxFormSize`, 10 MB).
const MAX_FORM_SIZE: usize = 10 << 20;

/// Parsed form or query values in request order (Go `url.Values`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values(Vec<(String, String)>);

impl Values {
    /// Go `Values.Get` / gin `PostForm` / `Query`: the first value, or `""`.
    #[must_use]
    pub fn get(&self, key: &str) -> &str {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map_or("", |(_, value)| value.as_str())
    }
}

/// Go `url.ParseQuery`: `&`-separated pairs, a pair holding `;` is dropped,
/// empty pairs are skipped, a pair whose key or value does not unescape is
/// dropped, everything else is kept (Go returns the error alongside the
/// valid pairs; gin ignores it). Invalid UTF-8 becomes U+FFFD.
#[must_use]
pub fn parse_query(raw: &str) -> Values {
    let mut values = Vec::new();
    for pair in raw.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Ok(key), Ok(value)) = (go_url::query_unescape(key), go_url::query_unescape(value))
        else {
            continue;
        };
        values.push((key, value));
    }
    Values(values)
}

/// gin `c.Query`: the request URL's query values.
#[must_use]
pub fn url_query(uri: &Uri) -> Values {
    uri.query().map(parse_query).unwrap_or_default()
}

/// gin `c.PostForm` values: the body of an
/// `application/x-www-form-urlencoded` request (media type matched like
/// `mime.ParseMediaType`, so parameters and case are ignored). Any other
/// content type, a body over 10 MB or a read error yields no values, as Go
/// does.
///
/// Deviation: `multipart/form-data` bodies are not parsed (Go's
/// `ParseMultipartForm` would read their fields).
pub async fn post_form(headers: &HeaderMap, body: Body) -> Values {
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if media_type != "application/x-www-form-urlencoded" {
        return Values::default();
    }
    match to_bytes(body, MAX_FORM_SIZE).await {
        Ok(bytes) => parse_query(&String::from_utf8_lossy(&bytes)),
        Err(_) => Values::default(),
    }
}

/// Go `Request.BasicAuth`: `Basic ` (ASCII case-insensitive) followed by
/// standard padded base64 of `user:pass`. Neither part is URL-decoded.
/// `None` when the header is absent or malformed.
#[must_use]
pub fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.as_bytes();
    const PREFIX: &[u8] = b"Basic ";
    if raw.len() < PREFIX.len() || !raw[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let decoded = decode_std_base64(&raw[PREFIX.len()..])?;
    let decoded = String::from_utf8_lossy(&decoded);
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

fn std_base64_value(byte: u8) -> Option<u32> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Go `base64.StdEncoding.DecodeString`: padding required, `\r` and `\n`
/// ignored anywhere, non-zero trailing bits accepted.
fn decode_std_base64(input: &[u8]) -> Option<Vec<u8>> {
    let data: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    if !data.len().is_multiple_of(4) {
        return None;
    }
    let quanta = data.len() / 4;
    let mut out = Vec::with_capacity(quanta * 3);
    for (index, chunk) in data.as_chunks::<4>().0.iter().enumerate() {
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && index + 1 != quanta) {
            return None;
        }
        let mut word = 0_u32;
        for (position, &byte) in chunk.iter().enumerate() {
            let value = if position < 4 - pad {
                std_base64_value(byte)?
            } else {
                0
            };
            word |= value << (18 - 6 * position);
        }
        let bytes = word.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

/// Go `splitProtocolList` (`router.go`): split on space, comma, `\n` and
/// `\t`, trim, drop empties, dedupe keeping the first occurrence. Not
/// sorted.
#[must_use]
pub fn split_protocol_list(raw: &str) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    for field in raw.split([' ', ',', '\n', '\t']) {
        let trimmed = field.trim();
        if trimmed.is_empty() || values.iter().any(|seen| seen == trimmed) {
            continue;
        }
        values.push(trimmed.to_owned());
    }
    values
}

/// The decoded path segment at `index` (gin `c.Param` for a `:name` at
/// that position). Segments are split on the decoded path, which is what
/// the router matched.
#[must_use]
pub fn path_segment(uri: &Uri, index: usize) -> String {
    let raw = uri.path();
    let decoded = go_url::unescape_path(raw).unwrap_or_else(|_| raw.to_owned());
    decoded.split('/').nth(index).unwrap_or_default().to_owned()
}

/// Go `hexEscapeNonASCII` (`http.Redirect`'s `Location`).
#[must_use]
pub fn hex_escape_non_ascii(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &byte in s.as_bytes() {
        if byte >= 0x80 {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

/// Go `htmlEscape` (`http.Redirect` body).
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// gin `c.Redirect(http.StatusFound, location)` for a `GET` request whose
/// `location` is absolute (every protocol redirect target is): `Location`
/// with non-ASCII bytes escaped, `text/html` content type and Go's small
/// HTML body.
#[must_use]
pub fn found(location: &str) -> Response {
    let body = format!("<a href=\"{}\">Found</a>.\n\n", html_escape(location));
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(&hex_escape_non_ascii(location)) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// `{"error": code}` with `status`.
#[must_use]
pub fn error_json(status: StatusCode, code: &str) -> Response {
    json_response(status, &json!({ "error": code }))
}

/// gin `c.Status(http.StatusOK)` with nothing written: empty body, no
/// content type.
#[must_use]
pub fn empty_ok() -> Response {
    StatusCode::OK.into_response()
}

/// Go `time.Time` JSON text (`RFC3339Nano`: trailing fractional zeros
/// trimmed), always rendered in UTC (accepted deviation: Go used the
/// process time zone).
///
/// # Errors
/// Years outside `0..=9999`, where Go's `MarshalJSON` fails too.
pub fn format_go_time(value: OffsetDateTime) -> Result<String, time::error::Format> {
    value.to_offset(UtcOffset::UTC).format(&Rfc3339)
}

/// `serialize_with` for a Go `time.Time` field.
///
/// # Errors
/// See [`format_go_time`].
pub fn serialize_time<S: Serializer>(
    value: &OffsetDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let text = format_go_time(*value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&text)
}

/// `serialize_with` for a Go `*time.Time` field (`null` when unset).
///
/// # Errors
/// See [`format_go_time`].
pub fn serialize_optional_time<S: Serializer>(
    value: &Option<OffsetDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serialize_time(value, serializer),
        None => serializer.serialize_none(),
    }
}

/// Go `stringClaim`: a string claim verbatim, anything else through
/// `fmt.Sprint` of the `encoding/json`-decoded value (numbers are
/// `float64`).
#[must_use]
pub fn string_claim(claims: &serde_json::Map<String, Value>, key: &str) -> String {
    claims.get(key).map(go_sprint).unwrap_or_default()
}

/// Go `fmt.Sprint` of an `encoding/json`-decoded value.
#[must_use]
pub fn go_sprint(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.as_f64().map(go_float).unwrap_or_default(),
        Value::String(text) => text.clone(),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(go_sprint).collect();
            format!("[{}]", parts.join(" "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(key, item)| format!("{key}:{}", go_sprint(item)))
                .collect();
            format!("map[{}]", parts.join(" "))
        }
    }
}

/// Go `%v` of a `float64` (`strconv.FormatFloat(f, 'g', -1, 64)`): shortest
/// digits, exponent form (`1.7e+09`) when the decimal exponent is `< -4` or
/// `>= 6`, Go's shortest-`%g` threshold.
fn go_float(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() { "-0" } else { "0" }.to_owned();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or_default();
    if !(-4..6).contains(&exponent) {
        let sign = if exponent < 0 { '-' } else { '+' };
        return format!("{mantissa}e{sign}{:02}", exponent.unsigned_abs());
    }
    format!("{value}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_matches_go() {
        let values = parse_query("a=1&a=2&b=x+y%20z&;c=1&d=%zz&=e&f&&g=%41");
        assert_eq!(values.get("a"), "1");
        assert_eq!(values.get("b"), "x y z");
        assert_eq!(values.get("c"), "");
        assert_eq!(values.get("d"), "");
        assert_eq!(values.get(""), "e");
        assert_eq!(values.get("f"), "");
        assert_eq!(values.get("g"), "A");
        assert_eq!(values.0.len(), 6);
    }

    #[test]
    fn std_base64_like_go() {
        assert_eq!(decode_std_base64(b"YTpi").unwrap(), b"a:b");
        assert_eq!(decode_std_base64(b"YTpiYw==").unwrap(), b"a:bc");
        assert_eq!(decode_std_base64(b"YTpiYwQ=").unwrap(), b"a:bc\x04");
        assert_eq!(decode_std_base64(b"YTpi\r\nYw==").unwrap(), b"a:bc");
        assert_eq!(decode_std_base64(b"").unwrap(), b"");
        assert!(decode_std_base64(b"YTpiYw").is_none());
        assert!(decode_std_base64(b"YT==YTpi").is_none());
        assert!(decode_std_base64(b"Y===").is_none());
        assert!(decode_std_base64(b"YTp-").is_none());
        assert!(decode_std_base64(b" YTpi").is_none());
    }

    #[test]
    fn basic_auth_like_go() {
        let headers = |value: &str| {
            let mut map = HeaderMap::new();
            map.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            map
        };
        // "client%3Aid:s%40cret:x" stays undecoded; the first colon splits.
        assert_eq!(
            basic_auth(&headers("bAsIc Y2xpZW50JTNBaWQ6cyU0MGNyZXQ6eA==")),
            Some(("client%3Aid".to_owned(), "s%40cret:x".to_owned()))
        );
        assert_eq!(basic_auth(&headers("Basic bm9jb2xvbg==")), None);
        assert_eq!(basic_auth(&headers("Basic")), None);
        assert_eq!(basic_auth(&headers("Bearer YTpi")), None);
        assert_eq!(basic_auth(&headers("Basic  YTpi")), None);
        assert_eq!(basic_auth(&HeaderMap::new()), None);
    }

    #[test]
    fn split_protocol_list_keeps_first_seen_order() {
        assert_eq!(
            split_protocol_list(" b,a\tb\n c ,,a"),
            ["b", "a", "c"].map(str::to_owned)
        );
        assert!(split_protocol_list("").is_empty());
    }

    #[test]
    fn go_sprint_matches_fmt() {
        assert_eq!(go_sprint(&json!("x")), "x");
        assert_eq!(go_sprint(&json!(true)), "true");
        assert_eq!(go_sprint(&Value::Null), "<nil>");
        assert_eq!(go_sprint(&json!(1_700_000_000)), "1.7e+09");
        assert_eq!(go_sprint(&json!(123_456)), "123456");
        assert_eq!(go_sprint(&json!(1_000_000)), "1e+06");
        assert_eq!(go_sprint(&json!(0.5)), "0.5");
        assert_eq!(go_sprint(&json!(0.00001)), "1e-05");
        assert_eq!(go_sprint(&json!(-2.5)), "-2.5");
        assert_eq!(go_sprint(&json!(0)), "0");
        assert_eq!(go_sprint(&json!(["a", 1])), "[a 1]");
        assert_eq!(go_sprint(&json!({"b": 1, "a": "x"})), "map[a:x b:1]");
    }

    #[test]
    fn go_time_rendering() {
        use time::macros::datetime;
        assert_eq!(
            format_go_time(datetime!(2026-11-26 01:02:03.120 +07:00)).unwrap(),
            "2026-11-25T18:02:03.12Z"
        );
        assert_eq!(
            format_go_time(datetime!(0001-01-01 0:00 UTC)).unwrap(),
            "0001-01-01T00:00:00Z"
        );
    }

    #[test]
    fn redirect_escaping() {
        assert_eq!(
            hex_escape_non_ascii("https://a.example/é?x=<"),
            "https://a.example/%C3%A9?x=<"
        );
        let response = found("https://a.example/?a=1&b='x'");
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://a.example/?a=1&b='x'"
        );
    }
}
