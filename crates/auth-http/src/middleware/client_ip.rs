//! gin v1.12 `c.ClientIP()` under `gin.New()` defaults: every proxy is
//! trusted (`0.0.0.0/0`, `::/0`), `ForwardedByClientIP` is on and the remote
//! IP headers are `X-Forwarded-For` then `X-Real-IP`.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::ConnectInfo,
    http::{Extensions, HeaderMap},
};

const REMOTE_IP_HEADERS: [&str; 2] = ["x-forwarded-for", "x-real-ip"];

/// The client IP gin would report.
///
/// With every proxy trusted, a header wins when *all* of its comma-separated
/// entries parse as IPs; the result is the first entry, trimmed, as written.
/// Otherwise the peer address from [`ConnectInfo`] is used (IPv4-mapped IPv6
/// shown as IPv4, like Go `net.IP.String`).
///
/// Deviation: Go returns `""` before looking at any header when the peer
/// address is unknown. Here the headers are still consulted, because the
/// Vercel runtime provides no `ConnectInfo`; with no usable header and no
/// peer the result is `""`, as in Go.
#[must_use]
pub fn client_ip(headers: &HeaderMap, extensions: &Extensions) -> String {
    for name in REMOTE_IP_HEADERS {
        let joined = headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join(",");
        if let Some(ip) = validate_header(&joined) {
            return ip.to_owned();
        }
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_canonical().to_string())
        .unwrap_or_default()
}

/// gin `Engine.validateHeader` with every IP trusted.
fn validate_header(header: &str) -> Option<&str> {
    if header.is_empty() {
        return None;
    }
    let items: Vec<&str> = header.split(',').collect();
    for (i, item) in items.iter().enumerate().rev() {
        let ip = item.trim();
        if ip.parse::<IpAddr>().is_err() {
            break;
        }
        if i == 0 {
            return Some(ip);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn ip(pairs: &[(&'static str, &str)], peer: Option<&str>) -> String {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_str(value).unwrap());
        }
        let mut extensions = Extensions::new();
        if let Some(peer) = peer {
            extensions.insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        client_ip(&headers, &extensions)
    }

    #[test]
    fn forwarded_for_first_hop_wins() {
        assert_eq!(
            ip(
                &[("x-forwarded-for", " 203.0.113.9 , 10.0.0.1")],
                Some("10.0.0.2:5000")
            ),
            "203.0.113.9"
        );
        // Multiple header lines are joined with commas.
        assert_eq!(
            ip(
                &[
                    ("x-forwarded-for", "2001:db8::1"),
                    ("x-forwarded-for", "10.0.0.1")
                ],
                None
            ),
            "2001:db8::1"
        );
    }

    #[test]
    fn invalid_forwarded_for_falls_back() {
        assert_eq!(
            ip(
                &[
                    ("x-forwarded-for", "unknown, 10.0.0.1"),
                    ("x-real-ip", "198.51.100.7")
                ],
                None
            ),
            "198.51.100.7"
        );
        assert_eq!(
            ip(
                &[("x-forwarded-for", "10.0.0.1, garbage")],
                Some("192.0.2.1:1")
            ),
            "192.0.2.1"
        );
        assert_eq!(
            ip(&[("x-forwarded-for", "")], Some("[::ffff:192.0.2.5]:1")),
            "192.0.2.5"
        );
        assert_eq!(ip(&[], Some("[2001:db8::2]:443")), "2001:db8::2");
        assert_eq!(ip(&[], None), "");
        // Go `net.ParseIP` rejects these too (checked against gin v1.12).
        for bad in ["01.2.3.4", "fe80::1%eth0", "1.2.3.4:80"] {
            assert_eq!(
                ip(&[("x-forwarded-for", bad)], Some("192.0.2.1:1")),
                "192.0.2.1",
                "{bad}"
            );
        }
    }
}
