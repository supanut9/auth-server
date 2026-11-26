//! Redirect targets of the flow handlers (Go `router.go`
//! `authorizationSuccessURL`, `oauthErrorURL`, `authUIRoute`,
//! `handlers_stateless.go preservedAuthorizeQuery`,
//! `handlers_provider_stateless.go oauthValuesFromRequest`).
//!
//! Go round-trips the client's redirect URI through `url.Parse` and
//! `URL.String`, replacing only `RawQuery`, so the rest of the URI (scheme
//! case, userinfo, path escaping, fragment) is rendered exactly as Go would.
//! [`GoUrl`] ports the parts of `net/url` this needs; validation is delegated
//! to [`crate::go_url::parse`], which keeps every check that can make Go's
//! `url.Parse` fail.
//!
//! Deviation: Go strings may hold invalid UTF-8 (a query value such as
//! `%FF`); here decoded values are Rust strings, so such bytes become U+FFFD
//! before they are re-encoded.

use std::collections::BTreeMap;

use auth_core::oauth::AuthorizeRequest;

use crate::go_url;

/// Go `url.Values`: keys sorted bytewise on encode, values in insertion
/// order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryValues(BTreeMap<String, Vec<String>>);

impl QueryValues {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Go `url.ParseQuery`, ignoring the error as `URL.Query()` does: pairs
    /// split on `&`; a pair holding `;` or failing to unescape is skipped.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut values = Self::new();
        for pair in raw.split('&') {
            if pair.is_empty() || pair.contains(';') {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let (Ok(key), Ok(value)) = (go_url::query_unescape(key), go_url::query_unescape(value))
            else {
                continue;
            };
            values.0.entry(key).or_default().push(value);
        }
        values
    }

    /// Go `Values.Get`: the first value, or `""`.
    #[must_use]
    pub fn get(&self, key: &str) -> &str {
        self.0
            .get(key)
            .and_then(|values| values.first())
            .map_or("", String::as_str)
    }

    /// Go `Values.Set`: replaces every value of `key`.
    pub fn set(&mut self, key: &str, value: &str) {
        self.0.insert(key.to_owned(), vec![value.to_owned()]);
    }

    /// Go `addIfPresent`: [`Self::set`] unless `value` is empty.
    pub fn set_if_present(&mut self, key: &str, value: &str) {
        if !value.is_empty() {
            self.set(key, value);
        }
    }

    /// Go `len(values) == 0`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Go `Values.Encode`: `QueryEscape(key)=QueryEscape(value)` pairs joined
    /// by `&`, keys sorted, `+` for spaces.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::new();
        for (key, values) in &self.0 {
            let key = go_url::query_escape(key);
            for value in values {
                if !out.is_empty() {
                    out.push('&');
                }
                out.push_str(&key);
                out.push('=');
                out.push_str(&go_url::query_escape(value));
            }
        }
        out
    }
}

/// The nine OAuth params forwarded between auth-server and auth-ui, in Go's
/// `addIfPresent` order.
pub const OAUTH_PARAMS: [&str; 9] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "prompt",
];

/// Go `preservedAuthorizeQuery`: only the nine OAuth params of the incoming
/// query (first value of each), empty ones skipped.
#[must_use]
pub fn preserved_authorize_query(query: &QueryValues) -> QueryValues {
    let mut out = QueryValues::new();
    for key in OAUTH_PARAMS {
        out.set_if_present(key, query.get(key));
    }
    out
}

/// Go `oauthValuesFromRequest` (also `authorizeRequestBody.toQuery`, whose
/// fields are the same nine params).
#[must_use]
pub fn oauth_values_from_request(request: &AuthorizeRequest) -> QueryValues {
    let mut out = QueryValues::new();
    for (key, value) in [
        ("response_type", &request.response_type),
        ("client_id", &request.client_id),
        ("redirect_uri", &request.redirect_uri),
        ("scope", &request.scope),
        ("state", &request.state),
        ("nonce", &request.nonce),
        ("code_challenge", &request.code_challenge),
        ("code_challenge_method", &request.code_challenge_method),
        ("prompt", &request.prompt),
    ] {
        out.set_if_present(key, value);
    }
    out
}

/// Go `authUIRoute`: `TrimRight(AUTH_UI_BASE_URL, "/") + path`, plus
/// `?` and the encoded query when it has any key.
#[must_use]
pub fn auth_ui_route(auth_ui_base_url: &str, path: &str, query: &QueryValues) -> String {
    let base = format!("{}{path}", auth_ui_base_url.trim_end_matches('/'));
    if query.is_empty() {
        base
    } else {
        format!("{base}?{}", query.encode())
    }
}

/// Go `redirectAuthUIError`'s target: auth-ui `/error` with the request's
/// OAuth params plus `error` and, when non-empty, `error_description`.
#[must_use]
pub fn auth_ui_error_route(
    auth_ui_base_url: &str,
    request: &AuthorizeRequest,
    error: &str,
    description: &str,
) -> String {
    let mut query = oauth_values_from_request(request);
    query.set("error", error);
    query.set_if_present("error_description", description);
    auth_ui_route(auth_ui_base_url, "/error", &query)
}

/// Go `authorizationSuccessURL`: `code` and (when non-empty) `state` set
/// into the redirect URI's query. `None` when the URI is empty or does not
/// parse.
#[must_use]
pub fn authorization_success_url(redirect_uri: &str, code: &str, state: &str) -> Option<String> {
    with_query(redirect_uri, |query| {
        query.set("code", code);
        query.set_if_present("state", state);
    })
}

/// Go `oauthErrorURL`: `error`, `error_description` and `state` (the last
/// two only when non-empty) set into the redirect URI's query. `None` when
/// the URI is empty or does not parse.
#[must_use]
pub fn oauth_error_url(
    redirect_uri: &str,
    state: &str,
    error: &str,
    description: &str,
) -> Option<String> {
    with_query(redirect_uri, |query| {
        query.set("error", error);
        query.set_if_present("error_description", description);
        query.set_if_present("state", state);
    })
}

fn with_query(redirect_uri: &str, update: impl FnOnce(&mut QueryValues)) -> Option<String> {
    if redirect_uri.is_empty() {
        return None;
    }
    let mut url = GoUrl::parse(redirect_uri)?;
    let mut query = QueryValues::parse(&url.raw_query);
    update(&mut query);
    url.raw_query = query.encode();
    Some(url.to_string())
}

/// The fields of a Go `*url.URL` that `URL.String` renders.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoUrl {
    scheme: String,
    opaque: String,
    /// `(username, password)`; `None` when the URL has no userinfo.
    user: Option<(String, Option<String>)>,
    host: String,
    omit_host: bool,
    path: String,
    raw_path: String,
    force_query: bool,
    pub raw_query: String,
    fragment: String,
    raw_fragment: String,
}

impl GoUrl {
    /// Go `url.Parse`; `None` exactly when Go returns an error.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        // Every error check (control bytes, scheme, authority, host, port,
        // userinfo, escapes) lives in `go_url::parse`; past it the splits
        // below cannot fail.
        let checked = go_url::parse(raw).ok()?;
        let (without_fragment, fragment) = match raw.split_once('#') {
            Some((before, after)) => (before, Some(after)),
            None => (raw, None),
        };
        let mut url = Self::default();
        if without_fragment == "*" {
            url.path = "*".to_owned();
        } else {
            url.scheme = checked.scheme;
            let rest = strip_scheme(without_fragment);
            let rest = if rest.ends_with('?') && rest.matches('?').count() == 1 {
                url.force_query = true;
                &rest[..rest.len() - 1]
            } else {
                match rest.split_once('?') {
                    Some((before, query)) => {
                        url.raw_query = query.to_owned();
                        before
                    }
                    None => rest,
                }
            };
            if !rest.starts_with('/') && !url.scheme.is_empty() {
                url.opaque = rest.to_owned();
            } else {
                let mut path = rest;
                if (!url.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
                    let authority_and_path = &rest[2..];
                    let (authority, remainder) = match authority_and_path.find('/') {
                        Some(i) => (&authority_and_path[..i], &authority_and_path[i..]),
                        None => (authority_and_path, ""),
                    };
                    url.user = authority
                        .rfind('@')
                        .map(|i| parse_userinfo(&authority[..i]));
                    url.host = checked.host;
                    path = remainder;
                } else if !url.scheme.is_empty() && rest.starts_with('/') {
                    url.omit_host = true;
                }
                url.set_path(path);
            }
        }
        if let Some(fragment) = fragment
            && !fragment.is_empty()
        {
            url.set_fragment(fragment);
        }
        Some(url)
    }

    /// Go `setPath`.
    fn set_path(&mut self, escaped: &str) {
        self.path = go_url::unescape_path(escaped).unwrap_or_default();
        self.raw_path = if escape(&self.path, Mode::Path) == escaped {
            String::new()
        } else {
            escaped.to_owned()
        };
    }

    /// Go `setFragment`.
    fn set_fragment(&mut self, escaped: &str) {
        self.fragment = unescape(escaped, Mode::Fragment).unwrap_or_default();
        self.raw_fragment = if escape(&self.fragment, Mode::Fragment) == escaped {
            String::new()
        } else {
            escaped.to_owned()
        };
    }

    /// Go `EscapedPath`.
    fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty()
            && valid_encoded(&self.raw_path, Mode::Path)
            && go_url::unescape_path(&self.raw_path).is_ok_and(|path| path == self.path)
        {
            return self.raw_path.clone();
        }
        if self.path == "*" {
            return "*".to_owned();
        }
        escape(&self.path, Mode::Path)
    }

    /// Go `EscapedFragment`.
    fn escaped_fragment(&self) -> String {
        if !self.raw_fragment.is_empty()
            && valid_encoded(&self.raw_fragment, Mode::Fragment)
            && unescape(&self.raw_fragment, Mode::Fragment).is_ok_and(|f| f == self.fragment)
        {
            return self.raw_fragment.clone();
        }
        escape(&self.fragment, Mode::Fragment)
    }
}

/// Go `URL.String`.
impl std::fmt::Display for GoUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = String::new();
        if !self.scheme.is_empty() {
            buf.push_str(&self.scheme);
            buf.push(':');
        }
        if self.opaque.is_empty() {
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && !(self.omit_host && self.host.is_empty() && self.user.is_none())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.push_str("//");
                }
                if let Some((username, password)) = &self.user {
                    buf.push_str(&escape(username, Mode::UserPassword));
                    if let Some(password) = password {
                        buf.push(':');
                        buf.push_str(&escape(password, Mode::UserPassword));
                    }
                    buf.push('@');
                }
                if !self.host.is_empty() {
                    buf.push_str(&escape(&self.host, Mode::Host));
                }
            }
            let path = self.escaped_path();
            if !path.is_empty() && !path.starts_with('/') && !self.host.is_empty() {
                buf.push('/');
            }
            if buf.is_empty() {
                let segment = path.split_once('/').map_or(path.as_str(), |(s, _)| s);
                if segment.contains(':') {
                    buf.push_str("./");
                }
            }
            buf.push_str(&path);
        } else {
            buf.push_str(&self.opaque);
        }
        if self.force_query || !self.raw_query.is_empty() {
            buf.push('?');
            buf.push_str(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            buf.push('#');
            buf.push_str(&self.escaped_fragment());
        }
        f.write_str(&buf)
    }
}

/// Go `getScheme`'s remainder (the scheme itself comes from
/// [`go_url::parse`], already validated and lowercased).
fn strip_scheme(raw: &str) -> &str {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i > 0 => return &raw[i + 1..],
            _ => return raw,
        }
    }
    raw
}

/// Go `parseAuthority`'s userinfo half (already validated).
fn parse_userinfo(userinfo: &str) -> (String, Option<String>) {
    match userinfo.split_once(':') {
        None => (
            unescape(userinfo, Mode::UserPassword).unwrap_or_default(),
            None,
        ),
        Some((username, password)) => (
            unescape(username, Mode::UserPassword).unwrap_or_default(),
            Some(unescape(password, Mode::UserPassword).unwrap_or_default()),
        ),
    }
}

/// Go `net/url` encoding modes used by `URL.String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    Host,
    UserPassword,
    Fragment,
}

/// Go `shouldEscape` for the modes above.
fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if mode == Mode::Host
        && matches!(
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
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => return c == b'?',
            Mode::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            Mode::Fragment => return false,
            Mode::Host => {}
        },
        _ => {}
    }
    !(mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*'))
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Go `escape` (no query mode, so no `+` for spaces).
fn escape(s: &str, mode: Mode) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if should_escape(c, mode) {
            out.push('%');
            out.push(char::from(UPPER_HEX[usize::from(c >> 4)]));
            out.push(char::from(UPPER_HEX[usize::from(c & 15)]));
        } else {
            out.push(char::from(c));
        }
    }
    out
}

/// Go `unescape` for the fragment and userinfo modes, whose only failure is
/// a malformed `%` escape. Invalid UTF-8 becomes U+FFFD.
fn unescape(s: &str, _mode: Mode) -> Result<String, go_url::UrlError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or(go_url::UrlError)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return Err(go_url::UrlError);
            }
            out.push((hex_value(hex[0]) << 4) | hex_value(hex[1]));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn hex_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// Go `validEncoded`.
fn valid_encoded(s: &str, mode: Mode) -> bool {
    s.bytes().all(|c| {
        matches!(
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
                | b'@'
                | b'['
                | b']'
                | b'%'
        ) || !should_escape(c, mode)
    })
}

/// Go `hexEscapeNonASCII`, applied by `http.Redirect` to `Location`.
#[must_use]
pub fn hex_escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c >= 0x80 {
            out.push('%');
            out.push(char::from(UPPER_HEX[usize::from(c >> 4)]));
            out.push(char::from(UPPER_HEX[usize::from(c & 15)]));
        } else {
            out.push(char::from(c));
        }
    }
    out
}

/// Go `htmlEscape` (`http.Redirect` body).
#[must_use]
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(raw: &str) -> String {
        GoUrl::parse(raw).expect("parses").to_string()
    }

    #[test]
    fn url_round_trips_like_go() {
        for (raw, want) in [
            ("https://app.example.com/cb", "https://app.example.com/cb"),
            ("HTTPS://App.Example.com/cb", "https://App.Example.com/cb"),
            ("https://u:p%40@h.example/x", "https://u:p%40@h.example/x"),
            ("https://u@h.example", "https://u@h.example"),
            ("https://h.example/a%2Fb", "https://h.example/a%2Fb"),
            ("https://h.example/a b", "https://h.example/a%20b"),
            ("https://h.example/é#ü", "https://h.example/%C3%A9#%C3%BC"),
            ("https://h.example/#a%20b", "https://h.example/#a%20b"),
            ("https://h.example/#a b", "https://h.example/#a%20b"),
            ("https://h.example/?", "https://h.example/?"),
            ("com.example.app:/cb", "com.example.app:/cb"),
            ("mailto:a@b", "mailto:a@b"),
            ("file:///etc/x", "file:///etc/x"),
            ("http://[::1]:8080/x", "http://[::1]:8080/x"),
            ("//h.example/x", "//h.example/x"),
            ("/relative?x=1", "/relative?x=1"),
            ("*", "*"),
        ] {
            assert_eq!(round_trip(raw), want, "{raw}");
        }
    }

    #[test]
    fn url_parse_failures_match_go() {
        for raw in [
            "http://[::1",
            "http://a b/",
            ":x",
            "http://h:port/",
            "a:b/c\u{7f}",
        ] {
            assert!(GoUrl::parse(raw).is_none(), "{raw}");
        }
    }

    #[test]
    fn query_parse_skips_bad_pairs() {
        let q = QueryValues::parse("a=1&&b=%zz&c;d=2&e&f=%20x+y&a=2");
        assert_eq!(q.get("a"), "1");
        assert_eq!(q.get("b"), "");
        assert_eq!(q.get("e"), "");
        assert_eq!(q.get("f"), " x y");
        assert_eq!(q.encode(), "a=1&a=2&e=&f=+x+y");
    }

    #[test]
    fn location_escaping() {
        assert_eq!(hex_escape_non_ascii("/é?x"), "/%C3%A9?x");
        assert_eq!(html_escape("a&b<\"'>"), "a&amp;b&lt;&#34;&#39;&gt;");
    }
}
