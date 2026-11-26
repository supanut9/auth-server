//! `Set-Cookie` values byte-identical to gin `c.SetCookie` (which
//! `QueryEscape`s the value) rendered by Go 1.26 `net/http` `Cookie.String`,
//! and `Cookie` header reading like gin `c.Cookie`.
//!
//! Attribute order: `Name=Value; Path; Domain; Max-Age; HttpOnly; Secure;
//! SameSite`. No `Expires` is ever sent.

use auth_adapters::config::Config;
use axum::http::{HeaderMap, HeaderValue, header};
use time::OffsetDateTime;

use crate::go_url;

/// Central SSO session cookie (`router.go` `ssoCookieName`).
pub const SSO_COOKIE_NAME: &str = "auth_sso_session";
/// Double-submit CSRF cookie (`helpers.go` `csrfCookieName`).
pub const CSRF_COOKIE_NAME: &str = "auth_csrf";
/// `helpers.go` `csrfTokenTTL` (30 minutes), also the CSRF cookie `Max-Age`.
pub const CSRF_TOKEN_TTL_SECONDS: i64 = 30 * 60;

/// Go `http.SameSite` values this service emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Lax,
    Strict,
    None,
}

impl SameSite {
    /// `router.go` `sameSiteMode`: `strict` and `none` (trimmed, any case),
    /// anything else is `Lax`.
    #[must_use]
    pub fn from_config_value(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "strict" => Self::Strict,
            "none" => Self::None,
            _ => Self::Lax,
        }
    }

    fn attribute(self) -> &'static str {
        match self {
            Self::Lax => "; SameSite=Lax",
            Self::Strict => "; SameSite=Strict",
            Self::None => "; SameSite=None",
        }
    }
}

/// One cookie as gin's `c.SetCookie(name, value, maxAge, path, domain,
/// secure, httpOnly)` receives it, with the `SameSite` from `c.SetSameSite`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCookie<'a> {
    pub name: &'a str,
    /// Raw value; it is `QueryEscape`d when rendered.
    pub value: &'a str,
    /// Go `MaxAge`: `> 0` renders `Max-Age=N`, `0` omits the attribute
    /// (session cookie), `< 0` renders `Max-Age=0`.
    pub max_age: i64,
    /// gin substitutes `/` for an empty path.
    pub path: &'a str,
    pub domain: &'a str,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
}

impl SetCookie<'_> {
    /// The `Set-Cookie` header value.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push_str(self.name);
        out.push('=');
        // `QueryEscape` output never holds a space or comma, so Go never
        // quotes it.
        out.push_str(&go_url::query_escape(self.value));
        let path = if self.path.is_empty() { "/" } else { self.path };
        out.push_str("; Path=");
        out.push_str(&sanitize_cookie_path(path));
        if !self.domain.is_empty() && valid_cookie_domain(self.domain) {
            out.push_str("; Domain=");
            out.push_str(self.domain.strip_prefix('.').unwrap_or(self.domain));
        }
        if self.max_age > 0 {
            out.push_str("; Max-Age=");
            out.push_str(&self.max_age.to_string());
        } else if self.max_age < 0 {
            out.push_str("; Max-Age=0");
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        if self.secure {
            out.push_str("; Secure");
        }
        out.push_str(self.same_site.attribute());
        out
    }

    /// [`Self::render`] as a header value. Every rendered byte is visible
    /// ASCII (the value is escaped, invalid domains are dropped, the path is
    /// sanitised), so this cannot fail for the constant cookie names used here.
    #[must_use]
    pub fn header_value(&self) -> HeaderValue {
        HeaderValue::from_str(&self.render()).unwrap_or_else(|_| HeaderValue::from_static(""))
    }
}

/// Go `sanitizeCookiePath`: drops bytes outside `0x20..0x7f` and `;`.
fn sanitize_cookie_path(path: &str) -> String {
    path.chars()
        .filter(|&c| (' '..'\u{7f}').contains(&c) && c != ';')
        .collect()
}

/// Go `validCookieDomain`: a cookie domain name, or an IPv4 literal.
fn valid_cookie_domain(domain: &str) -> bool {
    is_cookie_domain_name(domain)
        || (domain.parse::<std::net::IpAddr>().is_ok() && !domain.contains(':'))
}

/// Go `isCookieDomainName`.
fn is_cookie_domain_name(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 255 {
        return false;
    }
    let s = domain.strip_prefix('.').unwrap_or(domain).as_bytes();
    let mut last = b'.';
    let mut ok = false;
    let mut part_len = 0;
    for &c in s {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {
                ok = true;
                part_len += 1;
            }
            b'0'..=b'9' => part_len += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part_len += 1;
            }
            b'.' => {
                if last == b'.' || last == b'-' {
                    return false;
                }
                if part_len > 63 || part_len == 0 {
                    return false;
                }
                part_len = 0;
            }
            _ => return false,
        }
        last = c;
    }
    if last == b'-' || part_len > 63 {
        return false;
    }
    ok
}

/// The `SSO_COOKIE_*` settings shared by the SSO and CSRF cookies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    pub secure: bool,
    pub same_site: SameSite,
    pub domain: String,
}

impl CookiePolicy {
    /// From `SSO_COOKIE_SECURE`, `SSO_COOKIE_SAME_SITE` and
    /// `SSO_COOKIE_DOMAIN`.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config.sso_cookie_secure,
            &config.sso_cookie_same_site,
            &config.sso_cookie_domain,
        )
    }

    #[must_use]
    pub fn new(secure: bool, same_site: &str, domain: &str) -> Self {
        Self {
            secure,
            same_site: SameSite::from_config_value(same_site),
            domain: domain.to_owned(),
        }
    }

    fn cookie<'a>(
        &'a self,
        name: &'a str,
        value: &'a str,
        max_age: i64,
        http_only: bool,
    ) -> SetCookie<'a> {
        SetCookie {
            name,
            value,
            max_age,
            path: "/",
            domain: &self.domain,
            secure: self.secure,
            http_only,
            same_site: self.same_site,
        }
    }

    /// `setSSOCookie`: `max_age` from [`sso_max_age`]; `0` yields a session
    /// cookie, exactly as Go does.
    #[must_use]
    pub fn sso_cookie(&self, session_id: &str, max_age: i64) -> HeaderValue {
        self.cookie(SSO_COOKIE_NAME, session_id, max_age.max(0), true)
            .header_value()
    }

    /// `clearSSOCookie`: empty value, `Max-Age=0`.
    #[must_use]
    pub fn clear_sso_cookie(&self) -> HeaderValue {
        self.cookie(SSO_COOKIE_NAME, "", -1, true).header_value()
    }

    /// `csrfToken`: `auth_csrf`, `Max-Age=1800`, not `HttpOnly`.
    #[must_use]
    pub fn csrf_cookie(&self, token: &str) -> HeaderValue {
        self.cookie(CSRF_COOKIE_NAME, token, CSRF_TOKEN_TTL_SECONDS, false)
            .header_value()
    }
}

/// `setSSOCookie` `Max-Age`: `int(time.Until(expiresAt).Seconds())`, i.e.
/// whole seconds truncated toward zero, clamped to `>= 0`.
#[must_use]
pub fn sso_max_age(expires_at: OffsetDateTime, now: OffsetDateTime) -> i64 {
    let until = expires_at - now;
    // Go's float `Seconds()` then `int()` truncates toward zero, as does
    // `whole_seconds`.
    until.whole_seconds().max(0)
}

/// gin `c.Cookie(name)`: the first `name` cookie across all `Cookie` header
/// lines (Go `readCookies` rules), `QueryUnescape`d. `None` when absent;
/// `Some("")` when the value does not unescape (gin ignores that error).
#[must_use]
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    for line in headers.get_all(header::COOKIE) {
        let mut line = trim_ascii_space(line.as_bytes());
        while !line.is_empty() {
            let (part, rest) = match line.iter().position(|&b| b == b';') {
                Some(i) => (&line[..i], &line[i + 1..]),
                None => (line, &b""[..]),
            };
            line = rest;
            let part = trim_ascii_space(part);
            if part.is_empty() {
                continue;
            }
            let (cookie_name, raw_value) = match part.iter().position(|&b| b == b'=') {
                Some(i) => (&part[..i], &part[i + 1..]),
                None => (part, &b""[..]),
            };
            if trim_ascii_space(cookie_name) != name.as_bytes() {
                continue;
            }
            let Some(value) = parse_cookie_value(raw_value) else {
                continue;
            };
            return Some(go_url::query_unescape(value).unwrap_or_default());
        }
    }
    None
}

/// Go `textproto.TrimString`: trims ASCII space, tab, CR and LF.
fn trim_ascii_space(bytes: &[u8]) -> &[u8] {
    let is_space = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let start = bytes
        .iter()
        .position(|b| !is_space(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_space(b))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Go `parseCookieValue(raw, true)`: strips one pair of surrounding quotes and
/// rejects bytes outside `0x20..0x7f` and `"`, `;`, `\`.
fn parse_cookie_value(raw: &[u8]) -> Option<&str> {
    let raw = if raw.len() > 1 && raw[0] == b'"' && raw[raw.len() - 1] == b'"' {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if raw
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b';' | b'\\'))
    {
        std::str::from_utf8(raw).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use time::Duration;

    use super::*;

    fn headers(lines: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for line in lines {
            map.append(header::COOKIE, HeaderValue::from_str(line).unwrap());
        }
        map
    }

    #[test]
    fn same_site_mapping() {
        assert_eq!(SameSite::from_config_value(" STRICT "), SameSite::Strict);
        assert_eq!(SameSite::from_config_value("None"), SameSite::None);
        assert_eq!(SameSite::from_config_value("lax"), SameSite::Lax);
        assert_eq!(SameSite::from_config_value(""), SameSite::Lax);
        assert_eq!(SameSite::from_config_value("bogus"), SameSite::Lax);
    }

    #[test]
    fn cookie_domain_validation_matches_go() {
        for valid in [
            "example.com",
            ".example.com",
            "localhost",
            "127.0.0.1",
            "a-b.c1",
            "x",
        ] {
            assert!(valid_cookie_domain(valid), "{valid}");
        }
        for invalid in [
            "bad domain",
            "::1",
            "-a.com",
            "a-.com",
            "a..com",
            "123.456",
            "a_b.com",
            "..com",
            "exämple.com",
        ] {
            assert!(!valid_cookie_domain(invalid), "{invalid}");
        }
        assert!(!valid_cookie_domain(&format!("{}.com", "a".repeat(64))));
        assert!(valid_cookie_domain(&format!("{}.com", "a".repeat(63))));
    }

    #[test]
    fn sso_max_age_truncates_and_clamps() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(
            sso_max_age(now + Duration::milliseconds(86_400_999), now),
            86_400
        );
        assert_eq!(sso_max_age(now + Duration::milliseconds(999), now), 0);
        assert_eq!(sso_max_age(now - Duration::seconds(5), now), 0);
    }

    #[test]
    fn read_cookie_follows_gin() {
        let map = headers(&["a=1; auth_csrf=tok%2Bx+y", "auth_csrf=second"]);
        assert_eq!(
            read_cookie(&map, CSRF_COOKIE_NAME).as_deref(),
            Some("tok+x y")
        );
        assert_eq!(read_cookie(&map, SSO_COOKIE_NAME), None);
        assert_eq!(
            read_cookie(&headers(&[" auth_sso_session = \"abc\" "]), SSO_COOKIE_NAME),
            None
        );
        assert_eq!(
            read_cookie(&headers(&["auth_sso_session=\"abc\""]), SSO_COOKIE_NAME).as_deref(),
            Some("abc")
        );
        // Invalid byte: skipped, the next cookie with the name wins.
        assert_eq!(
            read_cookie(
                &headers(&["auth_csrf=a\\b; auth_csrf=ok"]),
                CSRF_COOKIE_NAME
            )
            .as_deref(),
            Some("ok")
        );
        // Bad escape: gin ignores the QueryUnescape error and returns "".
        assert_eq!(
            read_cookie(&headers(&["auth_csrf=%zz"]), CSRF_COOKIE_NAME).as_deref(),
            Some("")
        );
        assert_eq!(
            read_cookie(&headers(&["auth_csrf"]), CSRF_COOKIE_NAME).as_deref(),
            Some("")
        );
        assert_eq!(
            read_cookie(&headers(&["auth_csrf="]), CSRF_COOKIE_NAME).as_deref(),
            Some("")
        );
    }
}
