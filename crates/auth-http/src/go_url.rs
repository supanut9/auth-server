//! Byte-exact ports of the parts of Go's `net/url` and `path` packages that
//! the HTTP layer depends on (Go 1.26 semantics).
//!
//! The `url` crate normalises (default ports, IDNA, lowercase hosts) where Go
//! keeps the raw text, so origin checks and redirect targets use these ports.

/// Go `url` encoding modes used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

/// Go `shouldEscape` (generated `table` in Go 1.26).
fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone)
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
            Mode::QueryComponent => return true,
            Mode::Fragment => return false,
            Mode::Host | Mode::Zone => {}
        },
        _ => {}
    }
    !(mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*'))
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

fn escape(s: &[u8], mode: Mode) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s {
        if c == b' ' && mode == Mode::QueryComponent {
            out.push('+');
        } else if should_escape(c, mode) {
            out.push('%');
            out.push(char::from(UPPER_HEX[usize::from(c >> 4)]));
            out.push(char::from(UPPER_HEX[usize::from(c & 15)]));
        } else {
            out.push(char::from(c));
        }
    }
    out
}

/// Go `unescape`. The error carries no detail: callers only branch on it.
fn unescape(s: &[u8], mode: Mode) -> Result<Vec<u8>, UrlError> {
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                if i + 2 >= s.len()
                    || !s[i + 1].is_ascii_hexdigit()
                    || !s[i + 2].is_ascii_hexdigit()
                {
                    return Err(UrlError);
                }
                if mode == Mode::Host && unhex(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return Err(UrlError);
                }
                if mode == Mode::Zone {
                    let v = (unhex(s[i + 1]) << 4) | unhex(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && v != b' ' && should_escape(v, Mode::Host) {
                        return Err(UrlError);
                    }
                }
                i += 3;
            }
            c => {
                if matches!(mode, Mode::Host | Mode::Zone) && c < 0x80 && should_escape(c, mode) {
                    return Err(UrlError);
                }
                i += 1;
            }
        }
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                out.push((unhex(s[i + 1]) << 4) | unhex(s[i + 2]));
                i += 3;
            }
            b'+' if mode == Mode::QueryComponent => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// A Go `net/url` parse or unescape failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlError;

/// Go `url.QueryEscape`.
#[must_use]
pub fn query_escape(s: &str) -> String {
    escape(s.as_bytes(), Mode::QueryComponent)
}

/// Go `url.QueryUnescape`. Go strings may hold invalid UTF-8; here such bytes
/// become U+FFFD.
pub fn query_unescape(s: &str) -> Result<String, UrlError> {
    unescape(s.as_bytes(), Mode::QueryComponent)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Go `unescape(p, encodePath)`: how `net/http` derives `URL.Path` from the
/// request target.
pub fn unescape_path(s: &str) -> Result<String, UrlError> {
    unescape(s.as_bytes(), Mode::Path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Go `escape(path, encodePath)`, as used by `URL.EscapedPath` for a path
/// without a matching `RawPath`.
#[must_use]
pub fn escape_path(s: &str) -> String {
    escape(s.as_bytes(), Mode::Path)
}

/// The parts of a Go `*url.URL` the HTTP layer reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoUrl {
    /// Lowercased scheme, or empty.
    pub scheme: String,
    /// Unescaped host including any `:port`, or empty.
    pub host: String,
}

/// Go `url.Parse`, reduced to the scheme and host. Every check that can make
/// Go return an error is kept.
pub fn parse(raw: &str) -> Result<GoUrl, UrlError> {
    let (without_fragment, fragment) = match raw.split_once('#') {
        Some((before, after)) => (before, Some(after)),
        None => (raw, None),
    };
    let url = parse_without_fragment(without_fragment)?;
    if let Some(fragment) = fragment
        && !fragment.is_empty()
    {
        unescape(fragment.as_bytes(), Mode::Fragment)?;
    }
    Ok(url)
}

fn parse_without_fragment(raw: &str) -> Result<GoUrl, UrlError> {
    if raw.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err(UrlError);
    }
    let mut url = GoUrl::default();
    if raw == "*" {
        return Ok(url);
    }
    let (scheme, rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();

    let rest = if rest.ends_with('?') && rest.matches('?').count() == 1 {
        &rest[..rest.len() - 1]
    } else {
        rest.split_once('?').map_or(rest, |(before, _)| before)
    };

    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            // Opaque URL: no host.
            return Ok(url);
        }
        let segment = rest.split_once('/').map_or(rest, |(segment, _)| segment);
        if segment.contains(':') {
            return Err(UrlError);
        }
    }

    let mut path = rest;
    if (!url.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let authority_and_path = &rest[2..];
        let (authority, remainder) = match authority_and_path.find('/') {
            Some(i) => (&authority_and_path[..i], &authority_and_path[i..]),
            None => (authority_and_path, ""),
        };
        url.host = parse_authority(&url.scheme, authority)?;
        path = remainder;
    }
    unescape(path.as_bytes(), Mode::Path)?;
    Ok(url)
}

fn get_scheme(raw: &str) -> Result<(&str, &str), UrlError> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err(UrlError);
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

fn parse_authority(scheme: &str, authority: &str) -> Result<String, UrlError> {
    let at = authority.rfind('@');
    let host = parse_host(scheme, at.map_or(authority, |i| &authority[i + 1..]))?;
    if let Some(i) = at {
        let userinfo = &authority[..i];
        if !valid_userinfo(userinfo) {
            return Err(UrlError);
        }
        match userinfo.split_once(':') {
            None => {
                unescape(userinfo.as_bytes(), Mode::UserPassword)?;
            }
            Some((username, password)) => {
                unescape(username.as_bytes(), Mode::UserPassword)?;
                unescape(password.as_bytes(), Mode::UserPassword)?;
            }
        }
    }
    Ok(host)
}

fn parse_host(scheme: &str, host: &str) -> Result<String, UrlError> {
    match host.rfind('[') {
        Some(i) if i > 0 => return Err(UrlError),
        Some(_) => return parse_ip_literal(host),
        None => {}
    }
    if let Some(first) = host.find(':') {
        let last = host.rfind(':').unwrap_or(first);
        // Go 1.26 default (`urlstrictcolons=1`): http/https hosts may hold
        // one colon only; other schemes use the last colon.
        let i = if last != first && scheme != "http" && scheme != "https" {
            last
        } else {
            first
        };
        if !valid_optional_port(&host[i..]) {
            return Err(UrlError);
        }
    }
    let bytes = unescape(host.as_bytes(), Mode::Host)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_ip_literal(host: &str) -> Result<String, UrlError> {
    let close = host.rfind(']').ok_or(UrlError)?;
    let colon_port = &host[close + 1..];
    if !valid_optional_port(colon_port) {
        return Err(UrlError);
    }
    let unescaped_port = unescape(colon_port.as_bytes(), Mode::Host)?;
    let hostname = &host[1..close];
    let unescaped_host = match hostname.find("%25") {
        Some(zone) => {
            let mut bytes = unescape(&hostname.as_bytes()[..zone], Mode::Host)?;
            bytes.extend(unescape(&hostname.as_bytes()[zone..], Mode::Zone)?);
            bytes
        }
        None => unescape(hostname.as_bytes(), Mode::Host)?,
    };
    let unescaped_host = String::from_utf8(unescaped_host).map_err(|_| UrlError)?;
    // Go `netip.ParseAddr` must yield an IPv6 address (zone allowed).
    let address = match unescaped_host.split_once('%') {
        Some((_, "")) => return Err(UrlError),
        Some((address, _)) => address,
        None => unescaped_host.as_str(),
    };
    address
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| UrlError)?;
    Ok(format!(
        "[{unescaped_host}]{}",
        String::from_utf8_lossy(&unescaped_port)
    ))
}

fn valid_optional_port(port: &str) -> bool {
    match port.strip_prefix(':') {
        _ if port.is_empty() => true,
        Some(digits) => digits.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

fn valid_userinfo(s: &str) -> bool {
    s.chars().all(|c| {
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

/// Go `path.Clean`.
#[must_use]
pub fn path_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let bytes = path.as_bytes();
    let rooted = bytes[0] == b'/';
    let n = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if bytes[r] == b'/' || (bytes[r] == b'.' && (r + 1 == n || bytes[r + 1] == b'/')) {
            r += 1;
        } else if bytes[r] == b'.' && bytes[r + 1] == b'.' && (r + 2 == n || bytes[r + 2] == b'/') {
            r += 2;
            if out.len() > dotdot {
                // Go: `w--` then back up while `buf[w] != '/'`, dropping the
                // separator too.
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && bytes[r] != b'/' {
                out.push(bytes[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return ".".to_owned();
    }
    // Only ASCII separators are removed, so UTF-8 stays valid.
    String::from_utf8(out).unwrap_or_default()
}

/// Go `path.Split`: everything up to and including the last `/`, and the rest.
#[must_use]
pub fn path_split(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_escape_matches_go() {
        assert_eq!(
            query_escape("a b+c/d=e;f,g\"h\\i~j*k@ü"),
            "a+b%2Bc%2Fd%3De%3Bf%2Cg%22h%5Ci~j%2Ak%40%C3%BC"
        );
        assert_eq!(query_escape("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(query_escape(""), "");
    }

    #[test]
    fn query_unescape_matches_go() {
        assert_eq!(query_unescape("a+b%2Bc").unwrap(), "a b+c");
        assert_eq!(query_unescape("%c3%BC").unwrap(), "ü");
        assert!(query_unescape("%").is_err());
        assert!(query_unescape("%zz").is_err());
        assert!(query_unescape("abc%4").is_err());
    }

    #[test]
    fn escape_path_matches_go() {
        assert_eq!(escape_path("/a b/c?d#e"), "/a%20b/c%3Fd%23e");
        assert_eq!(escape_path("/$&+,:;=@!*()"), "/$&+,:;=@%21%2A%28%29");
    }

    #[test]
    fn unescape_path_keeps_plus() {
        assert_eq!(unescape_path("/a+b%2F").unwrap(), "/a+b/");
        assert!(unescape_path("/%zz").is_err());
    }

    #[test]
    fn parse_extracts_raw_host() {
        let url = parse("HTTPS://Auth.Example:443/logout?x=1#frag").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "Auth.Example:443");
        assert_eq!(
            parse("https://user:pw@h.example/x").unwrap().host,
            "h.example"
        );
        assert_eq!(parse("http://[::1]:8080/").unwrap().host, "[::1]:8080");
        assert_eq!(parse("/relative").unwrap(), GoUrl::default());
        assert_eq!(parse("//host/path").unwrap().host, "host");
        assert_eq!(parse("///triple").unwrap().host, "");
        assert_eq!(parse("mailto:x@y").unwrap().host, "");
        assert_eq!(parse("seg:ment/x").unwrap().scheme, "seg");
    }

    #[test]
    fn parse_rejects_like_go() {
        for raw in [
            ":nope",
            "https://h:abc/",
            "https://a:1:2/",
            "https://[1.2.3.4]/",
            "https://x[::1]/",
            "https://[::1/",
            "https://bad host/",
            "https://h/\u{7f}",
            "https://h/%zz",
            "1seg:ment/x",
            "a_b:c",
            "https://h/#%zz",
            "https://us er@h/",
        ] {
            assert_eq!(parse(raw), Err(UrlError), "{raw}");
        }
        assert_eq!(parse("postgres://a:1,b:2/db").unwrap().host, "a:1,b:2");
    }

    #[test]
    fn path_clean_matches_go() {
        for (input, want) in [
            ("", "."),
            ("/", "/"),
            ("//a//b/", "/a/b"),
            ("a/../..", ".."),
            ("/../a", "/a"),
            ("./a/./b/.", "a/b"),
            ("api//api//healthz", "api/api/healthz"),
            ("abc/def/../../..", ".."),
            ("/abc/def/..", "/abc"),
            ("a/b/../../../c", "../c"),
        ] {
            assert_eq!(path_clean(input), want, "{input}");
        }
    }

    #[test]
    fn path_split_matches_go() {
        assert_eq!(path_split("api//healthz"), ("api//", "healthz"));
        assert_eq!(path_split("healthz"), ("", "healthz"));
    }
}
