//! Authorization-request validation (Go `internal/application/oauth/validate.go`).
//!
//! The same check runs on `/v1/oauth2/authorize` (a UX gate that fails fast on
//! broken client configs) and on every flow action endpoint (`/login/*`,
//! `/otp/*`, `/consent/*`, provider callbacks), where it is the security gate:
//! the OAuth params travel in user-controlled URLs and bodies, so each action
//! re-verifies them.
//!
//! Check order matters and matches Go exactly. The client is resolved first,
//! because only a registered `redirect_uri` may receive error redirects. Every
//! failure up to and including the redirect URI checks is fatal (render
//! server-side); every later failure is recoverable (redirect with `?error=`).
//! See [`ValidationError::is_fatal`].

use std::sync::Arc;

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use super::ValidationError;
use crate::domain::{ClientId, ClientType, OAuthClient, Scopes};
use crate::ports::OAuthClientRepository;

/// The only supported `response_type` (no implicit or hybrid flows).
const RESPONSE_TYPE_CODE: &str = "code";
/// PKCE methods; `plain` is only allowed for confidential clients.
const PKCE_S256: &str = "S256";
const PKCE_PLAIN: &str = "plain";
/// RFC 7636 §4.2 `code_challenge` length bounds, in bytes.
const CODE_CHALLENGE_MIN_LEN: usize = 43;
const CODE_CHALLENGE_MAX_LEN: usize = 128;

/// Raw OAuth 2.0 / OIDC authorization-request params (Go `oauth.Request`).
///
/// Every field is the string as received; empty means absent. This is the
/// union of what any caller (the authorize redirect, a flow action body, a
/// provider-state envelope) carries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// Raw scope string as received; canonical after validation.
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    /// Normalized after validation (`plain` when a challenge came without one).
    pub code_challenge_method: String,
    pub prompt: String,
}

/// A request verified against the client registry (Go `oauth.Validated`).
///
/// Only [`validate`] builds one, so holding it proves the checks passed.
/// [`Self::request`] is canonical: `scope` is the sorted, deduplicated,
/// space-joined scope set and `code_challenge_method` is normalized. Other
/// fields are passed through untouched (Go does not trim them either).
#[derive(Debug, Clone)]
pub struct ValidatedAuthorizeRequest {
    client: OAuthClient,
    scopes: Scopes,
    request: AuthorizeRequest,
}

impl ValidatedAuthorizeRequest {
    /// The registered client, as loaded by the repository.
    #[must_use]
    pub fn client(&self) -> &OAuthClient {
        &self.client
    }

    /// Parsed, deduplicated, sorted request scopes (never empty).
    #[must_use]
    pub fn scopes(&self) -> &Scopes {
        &self.scopes
    }

    /// The canonical request.
    #[must_use]
    pub fn request(&self) -> &AuthorizeRequest {
        &self.request
    }

    /// Splits into `(client, scopes, canonical request)`.
    #[must_use]
    pub fn into_parts(self) -> (OAuthClient, Scopes, AuthorizeRequest) {
        (self.client, self.scopes, self.request)
    }
}

/// Authorization-request validation service over the client registry.
#[derive(Clone)]
pub struct AuthorizeRequestValidator {
    clients: Arc<dyn OAuthClientRepository>,
}

impl AuthorizeRequestValidator {
    #[must_use]
    pub fn new(clients: Arc<dyn OAuthClientRepository>) -> Self {
        Self { clients }
    }

    /// See [`validate`].
    ///
    /// # Errors
    ///
    /// Returns the first failed check, as [`validate`] does.
    pub async fn validate(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<ValidatedAuthorizeRequest, ValidationError> {
        validate(self.clients.as_ref(), request).await
    }
}

impl std::fmt::Debug for AuthorizeRequestValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeRequestValidator")
            .finish_non_exhaustive()
    }
}

/// Validates an authorization request against its registered client (Go
/// `oauth.Validate`). The client lookup is the only side effect.
///
/// # Errors
///
/// Returns the first failed check, in Go's order:
///
/// Fatal:
/// 1. empty `client_id` → [`ValidationError::ClientIdRequired`]
/// 2. any lookup failure, including transport errors → [`ValidationError::UnknownClient`]
/// 3. status not empty or `active` → [`ValidationError::ClientNotActive`]
/// 4. empty `redirect_uri` → [`ValidationError::RedirectUriRequired`]
/// 5. not an exact, case-sensitive registered URI → [`ValidationError::RedirectUriNotRegistered`]
/// 6. no scheme or host per Go `url.Parse` → [`ValidationError::RedirectUriNotAbsolute`]
///
/// Recoverable:
/// 7. empty `response_type` → [`ValidationError::ResponseTypeRequired`]
/// 8. `response_type` other than `code` → [`ValidationError::UnsupportedResponseType`]
/// 9. empty `state` → [`ValidationError::StateRequired`]
/// 10. no scopes → [`ValidationError::ScopeRequired`]
/// 11. a scope outside the client's allowed scopes → [`ValidationError::ScopeNotAllowed`]
/// 12. `openid` without `nonce` → [`ValidationError::NonceRequired`]
/// 13. public client without `code_challenge` → [`ValidationError::CodeChallengeRequired`]
/// 14. with a challenge, a method other than `S256`/`plain` → [`ValidationError::UnsupportedCodeChallengeMethod`]
/// 15. public client using `plain` → [`ValidationError::PublicClientRequiresS256`]
/// 16. challenge not 43–128 bytes → [`ValidationError::CodeChallengeLength`]
/// 17. challenge not unpadded base64url → [`ValidationError::CodeChallengeEncoding`]
pub async fn validate(
    clients: &dyn OAuthClientRepository,
    request: &AuthorizeRequest,
) -> Result<ValidatedAuthorizeRequest, ValidationError> {
    if request.client_id.is_empty() {
        return Err(ValidationError::ClientIdRequired);
    }

    let client = clients
        .find_by_client_id(&ClientId::new(request.client_id.as_str()))
        .await
        .map_err(|_| ValidationError::UnknownClient)?;

    check_request(client, request)
}

/// Everything after the client lookup; pure.
fn check_request(
    client: OAuthClient,
    request: &AuthorizeRequest,
) -> Result<ValidatedAuthorizeRequest, ValidationError> {
    if !client.status.is_usable() {
        return Err(ValidationError::ClientNotActive);
    }

    if request.redirect_uri.is_empty() {
        return Err(ValidationError::RedirectUriRequired);
    }
    if !client.has_redirect_uri(&request.redirect_uri) {
        return Err(ValidationError::RedirectUriNotRegistered);
    }
    if !go_url::has_scheme_and_host(&request.redirect_uri) {
        return Err(ValidationError::RedirectUriNotAbsolute);
    }

    // The redirect URI is trusted from here on: every failure is recoverable.

    if request.response_type.is_empty() {
        return Err(ValidationError::ResponseTypeRequired);
    }
    if request.response_type != RESPONSE_TYPE_CODE {
        return Err(ValidationError::UnsupportedResponseType);
    }

    if request.state.is_empty() {
        return Err(ValidationError::StateRequired);
    }

    let scopes = Scopes::parse(&request.scope);
    if scopes.is_empty() {
        return Err(ValidationError::ScopeRequired);
    }
    if !scopes.is_subset_of(&client.allowed_scope_set()) {
        return Err(ValidationError::ScopeNotAllowed);
    }

    if scopes.contains("openid") && request.nonce.is_empty() {
        return Err(ValidationError::NonceRequired);
    }

    let method = if request.code_challenge_method.is_empty() && !request.code_challenge.is_empty() {
        PKCE_PLAIN
    } else {
        request.code_challenge_method.as_str()
    };
    let is_public = client.client_type == ClientType::Public;
    if is_public && request.code_challenge.is_empty() {
        return Err(ValidationError::CodeChallengeRequired);
    }
    if !request.code_challenge.is_empty() {
        if method != PKCE_S256 && method != PKCE_PLAIN {
            return Err(ValidationError::UnsupportedCodeChallengeMethod);
        }
        if is_public && method == PKCE_PLAIN {
            return Err(ValidationError::PublicClientRequiresS256);
        }
        let len = request.code_challenge.len();
        if !(CODE_CHALLENGE_MIN_LEN..=CODE_CHALLENGE_MAX_LEN).contains(&len) {
            return Err(ValidationError::CodeChallengeLength);
        }
        if !is_go_raw_url_base64(&request.code_challenge) {
            return Err(ValidationError::CodeChallengeEncoding);
        }
    }

    let mut canonical = request.clone();
    canonical.code_challenge_method = method.to_owned();
    canonical.scope = scopes.to_string();

    Ok(ValidatedAuthorizeRequest {
        client,
        scopes,
        request: canonical,
    })
}

/// Go's `base64.RawURLEncoding` is lenient: non-zero trailing bits are
/// accepted (the encoding is not `Strict()`).
const GO_RAW_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// True when `base64.RawURLEncoding.DecodeString(value)` succeeds in Go.
///
/// Go's decoder skips `\r` and `\n` anywhere in the input, so they are
/// removed first. `=` is an invalid character for the unpadded encoding.
fn is_go_raw_url_base64(value: &str) -> bool {
    if value.contains(['\r', '\n']) {
        let stripped: String = value
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n'))
            .collect();
        GO_RAW_URL.decode(stripped).is_ok()
    } else {
        GO_RAW_URL.decode(value).is_ok()
    }
}

/// The subset of Go 1.26 `net/url.Parse` needed to answer "does this parse
/// with a non-empty `Scheme` and `Host`?".
///
/// Mirrors `Parse`, `parse` (non-request mode), `getScheme`, `parseAuthority`,
/// `parseHost` (with the Go 1.26 `urlstrictcolons=1` default), `validUserinfo`,
/// `unescape`, `setPath` and `setFragment`. Any error path collapses to
/// `false`, so error ordering inside `url.Parse` is irrelevant. The query is
/// never validated, as in Go.
mod go_url {
    use std::net::Ipv6Addr;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Host,
        Zone,
        UserPassword,
        Path,
        Fragment,
    }

    pub(super) fn has_scheme_and_host(raw: &str) -> bool {
        // `Parse` cuts the fragment off first; the CTL check only sees the rest.
        let (url, fragment) = raw.split_once('#').unwrap_or((raw, ""));
        if url.bytes().any(|b| b < b' ' || b == 0x7f) {
            return false;
        }
        let Some((scheme, rest)) = scheme(url) else {
            return false;
        };
        // Both `ForceQuery` and `strings.Cut(rest, "?")` keep what precedes
        // the first `?`.
        let rest = rest.split_once('?').map_or(rest, |(before, _)| before);
        // Without `//` the URL is opaque (`scheme:rest`) or has an omitted
        // host (`scheme:/path`): either way `Host` is empty.
        let Some(after_slashes) = rest.strip_prefix("//") else {
            return false;
        };
        let (authority, path) = after_slashes
            .find('/')
            .map_or((after_slashes, ""), |i| after_slashes.split_at(i));
        let scheme = scheme.to_ascii_lowercase();
        let Some(host) = parse_authority(&scheme, authority) else {
            return false;
        };
        if host.is_empty() || unescape(path, Mode::Path).is_none() {
            return false;
        }
        fragment.is_empty() || unescape(fragment, Mode::Fragment).is_some()
    }

    /// `getScheme`: `Some` only for a non-empty scheme followed by `:`.
    fn scheme(url: &str) -> Option<(&str, &str)> {
        for (i, c) in url.bytes().enumerate() {
            match c {
                b'a'..=b'z' | b'A'..=b'Z' => {}
                b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
                // A leading ':' is Go's "missing protocol scheme" error.
                b':' if i > 0 => return Some((&url[..i], &url[i + 1..])),
                _ => return None,
            }
        }
        None
    }

    /// `parseAuthority`: returns the unescaped host.
    fn parse_authority(scheme: &str, authority: &str) -> Option<Vec<u8>> {
        let Some(at) = authority.rfind('@') else {
            return parse_host(scheme, authority);
        };
        let host = parse_host(scheme, &authority[at + 1..])?;
        let userinfo = &authority[..at];
        if !valid_userinfo(userinfo) {
            return None;
        }
        // Go unescapes user and password separately around the first ':';
        // a valid `%XX` never spans a ':', so one pass is equivalent.
        unescape(userinfo, Mode::UserPassword)?;
        Some(host)
    }

    /// `parseHost` with `urlstrictcolons=1` (Go 1.26 default for a
    /// `go 1.26` module).
    fn parse_host(scheme: &str, host: &str) -> Option<Vec<u8>> {
        match host.rfind('[') {
            Some(0) => parse_ip_literal(host),
            Some(_) => None,
            None => {
                if let Some(first) = host.find(':') {
                    let last = host.rfind(':').unwrap_or(first);
                    let strict = scheme == "http" || scheme == "https";
                    let colon = if last != first && !strict {
                        last
                    } else {
                        first
                    };
                    if !valid_optional_port(&host[colon..]) {
                        return None;
                    }
                }
                unescape(host, Mode::Host)
            }
        }
    }

    /// The `[...]` branch of `parseHost` (RFC 3986 IP-literal, RFC 6874 zone).
    fn parse_ip_literal(host: &str) -> Option<Vec<u8>> {
        let close = host.rfind(']')?;
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return None;
        }
        unescape(colon_port, Mode::Host)?;
        let hostname = &host[1..close];
        let unescaped = match hostname.find("%25") {
            Some(zone) => {
                let mut out = unescape(&hostname[..zone], Mode::Host)?;
                out.extend(unescape(&hostname[zone..], Mode::Zone)?);
                out
            }
            None => unescape(hostname, Mode::Host)?,
        };
        is_ipv6_literal(&unescaped).then_some(unescaped)
    }

    /// `netip.ParseAddr(s)` succeeds and is not plain IPv4.
    ///
    /// `ParseAddr` dispatches on the first `.`, `:` or `%`; only `:` (IPv6)
    /// can pass, since IPv4 either fails or is rejected as `Is4`. The
    /// address part is checked with `std::net::Ipv6Addr`.
    fn is_ipv6_literal(value: &[u8]) -> bool {
        if value.iter().find(|b| matches!(b, b'.' | b':' | b'%')) != Some(&b':') {
            return false;
        }
        let address = match value.iter().position(|&b| b == b'%') {
            // An explicit zone must be non-empty.
            Some(i) if i + 1 == value.len() => return false,
            Some(i) => &value[..i],
            None => value,
        };
        std::str::from_utf8(address).is_ok_and(|a| a.parse::<Ipv6Addr>().is_ok())
    }

    /// `validOptionalPort`: empty or `:` followed by ASCII digits.
    fn valid_optional_port(port: &str) -> bool {
        port.is_empty()
            || port
                .strip_prefix(':')
                .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
    }

    /// `validUserinfo` (runes; anything non-ASCII fails).
    fn valid_userinfo(userinfo: &str) -> bool {
        userinfo.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '.'
                        | '_'
                        | ':'
                        | '~'
                        | '!'
                        | '$'
                        | '&'
                        | '\''
                        | '('
                        | ')'
                        | '*'
                        | '+'
                        | ','
                        | ';'
                        | '='
                        | '%'
                        | '@'
                )
        })
    }

    /// `shouldEscape(c, encodeHost)` (identical for `encodeZone`).
    fn should_escape_host(c: u8) -> bool {
        !(c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'!' | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'['
                    | b']'
                    | b'<'
                    | b'>'
                    | b'"'
                    | b'-'
                    | b'_'
                    | b'.'
                    | b'~'
            ))
    }

    fn unhex(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        }
    }

    /// `unescape` for the non-query modes (`+` is kept as-is).
    fn unescape(value: &str, mode: Mode) -> Option<Vec<u8>> {
        let s = value.as_bytes();
        let mut out = Vec::with_capacity(s.len());
        let mut i = 0;
        while i < s.len() {
            let c = s[i];
            if c == b'%' {
                if i + 2 >= s.len()
                    || !s[i + 1].is_ascii_hexdigit()
                    || !s[i + 2].is_ascii_hexdigit()
                {
                    return None;
                }
                let decoded = (unhex(s[i + 1]) << 4) | unhex(s[i + 2]);
                let is_percent = &s[i..i + 3] == b"%25";
                // Hosts may only %-encode non-ASCII bytes (and "%25").
                if mode == Mode::Host && unhex(s[i + 1]) < 8 && !is_percent {
                    return None;
                }
                if mode == Mode::Zone
                    && !is_percent
                    && decoded != b' '
                    && should_escape_host(decoded)
                {
                    return None;
                }
                out.push(decoded);
                i += 3;
            } else {
                if matches!(mode, Mode::Host | Mode::Zone) && c < 0x80 && should_escape_host(c) {
                    return None;
                }
                out.push(c);
                i += 1;
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{go_url, is_go_raw_url_base64};

    /// Each expectation was produced by Go 1.26.2:
    /// `u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != ""`.
    #[test]
    fn absolute_url_matches_go_url_parse() {
        let cases: &[(&str, bool)] = &[
            ("https://trading.example.com/cb", true),
            ("http://localhost:3000/callback", true),
            ("com.example.app://callback", true),
            ("com.example.app:/callback", false),
            ("myapp:callback", false),
            ("/cb", false),
            ("//example.com/cb", false),
            ("example.com/cb", false),
            ("", false),
            ("https://", false),
            ("https:///cb", false),
            ("https://user:pass@example.com/cb", true),
            ("https://user@@example.com/cb", true),
            ("https://us er@example.com/", false),
            ("https://exa mple.com/", false),
            ("https://example.com:8080/cb", true),
            ("https://example.com:80a/cb", false),
            ("https://example.com:/cb", true),
            ("https://:80/cb", true),
            ("https://a:1:2/cb", false),
            ("foo://a:1:2/cb", true),
            ("foo://a:x:2/cb", true),
            ("HTTP://a:1:2/cb", false),
            ("https://[::1]:8080/cb", true),
            ("https://[::1/cb", false),
            ("https://[127.0.0.1]/cb", false),
            ("https://[::ffff:127.0.0.1]/cb", true),
            ("https://[fe80::1%25en0]/cb", true),
            ("https://[fe80::1%en0]/cb", false),
            ("https://[fe80::1%25]/cb", false),
            ("https://a[::1]/cb", false),
            ("https://[::1]x/cb", false),
            ("https://ex%41mple.com/", false),
            ("https://ex%C3%A9mple.com/", true),
            ("https://例え.jp/cb", true),
            ("https://example.com/c%zzb", false),
            ("https://example.com/cb?x=%zz", true),
            ("https://example.com/cb#frag%zz", false),
            ("https://example.com/cb#%0A", true),
            ("https://example.com/cb#\n", true),
            ("https://example.com/c\nb", false),
            ("https://example.com/c\x7fb", false),
            ("https://example.com/c b", true),
            ("HTTPS://EXAMPLE.COM/CB", true),
            ("1https://a/", false),
            ("ht_tp://a/", false),
            (":https://a/", false),
            ("https://a?b/", true),
            ("https://a#b", true),
            ("https://a%2", false),
            ("https://a/%2", false),
            ("https://ex^ample.com/", false),
            ("https://ex_ample.com/", true),
            ("https://ex\"ample.com/", true),
            ("https://a%25b/", true),
            ("https://u%zz@a/", false),
            ("https://[::1%25%41]/", true),
            ("https://[::1%25%2F]/", false),
            ("https://[::1%25%20]/", true),
            ("https://[::1%25%C3%A9]/", false),
            ("https://[v1.x]/", false),
            ("https://[::1]:/", true),
            ("https://[1:2:3:4:5:6:7::]/", true),
            ("https://[::1:2:3:4:5:6:7]/", true),
            ("https://[1:2:3:4:5:6:7:8:9]/", false),
            ("https://[::ffff:01.2.3.4]/", false),
            ("https://[12345::]/", false),
            ("https://[::]/", true),
            ("https://[]/", false),
            ("https://[::1]]/", false),
            ("https://[::1]:80:90/", false),
            ("https://a/b#c#d", true),
            ("https://ü@a/", false),
            ("https://a@b@c/", true),
            ("https://a b@c/", false),
            ("https://a\tb/", false),
            ("https://a?#", true),
            ("https://?x", false),
            ("https://#x", false),
            ("https:?//a", false),
            ("https://a%zz?x", false),
            ("https://[1::2::3]/", false),
            ("https://[fe80::1%25en0%25x]/", true),
            ("https://[::1%25]/", false),
            ("https://[%3A%3A1]/", false),
            ("https://[0000:0:0:0:0:0:0:1]/", true),
            ("https://[::ffff:1.2.3]/", false),
            ("https://[1:2:3:4:5:6:1.2.3.4]/", true),
            ("https://[1:2:3:4:5:6:7:1.2.3.4]/", false),
            ("https://[::1.2.3.4]/", true),
            ("https://a{b}/", false),
            ("https://a|b/", false),
            ("https://a\\b/", false),
            ("https://a`b/", false),
            ("https://a<b>/", true),
            ("https://a~b/", true),
        ];
        for (raw, want) in cases {
            assert_eq!(go_url::has_scheme_and_host(raw), *want, "url {raw:?}");
        }
    }

    /// Each expectation was produced by Go 1.26.2
    /// `base64.RawURLEncoding.DecodeString`.
    #[test]
    fn base64_matches_go_raw_url_encoding() {
        let a = |n: usize| "A".repeat(n);
        let cases: Vec<(String, bool)> = vec![
            (a(43), true),
            (a(44), true),
            (a(45), false),
            // Non-zero trailing bits: Go's non-strict decoder accepts them.
            (a(42) + "B", true),
            (a(127) + "B", true),
            (a(42) + "=", false),
            (a(43) + "=", false),
            (a(41) + "==", false),
            (a(42) + "+", false),
            (a(42) + "/", false),
            (a(20) + " " + &a(22), false),
            // `\r` and `\n` are skipped anywhere.
            (a(20) + "\n" + &a(23), true),
            (a(20) + "\r\n" + &a(23), true),
            (a(20) + "\n" + &a(24), true),
            ("\n".to_owned() + &a(44), true),
            ("_-".repeat(64), true),
        ];
        for (value, want) in cases {
            assert_eq!(is_go_raw_url_base64(&value), want, "challenge {value:?}");
        }
    }
}
