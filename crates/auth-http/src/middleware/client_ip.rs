//! Client IP selection for direct connections and Vercel's edge proxy.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::ConnectInfo,
    http::{Extensions, HeaderMap},
};

/// Set by the Vercel entry point, where the edge controls the IP headers.
#[derive(Clone, Copy)]
pub struct VercelEdge;

/// Use Vercel's client IP headers at its edge and the socket peer on the
/// standalone server. Canonicalize IPv6 spellings and mapped IPv4 addresses
/// so they share a rate-limit key.
#[must_use]
pub fn client_ip(headers: &HeaderMap, extensions: &Extensions) -> String {
    if extensions.get::<VercelEdge>().is_some() {
        for name in ["x-vercel-forwarded-for", "x-forwarded-for", "x-real-ip"] {
            if let Some(ip) = headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .and_then(|hop| hop.trim().parse::<IpAddr>().ok())
            {
                return ip.to_canonical().to_string();
            }
        }
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_canonical().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn ip(pairs: &[(&'static str, &str)], peer: Option<&str>, edge: bool) -> String {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_str(value).unwrap());
        }
        let mut extensions = Extensions::new();
        if edge {
            extensions.insert(VercelEdge);
        }
        if let Some(peer) = peer {
            extensions.insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        client_ip(&headers, &extensions)
    }

    #[test]
    fn vercel_ip_wins_and_is_canonicalized() {
        assert_eq!(
            ip(
                &[
                    ("x-vercel-forwarded-for", "2001:0db8:0:0::1"),
                    ("x-forwarded-for", "203.0.113.9, 10.0.0.1"),
                    ("x-real-ip", "198.51.100.7"),
                ],
                Some("10.0.0.2:5000"),
                true,
            ),
            "2001:db8::1"
        );
    }

    #[test]
    fn vercel_fallbacks_use_the_first_forwarded_hop() {
        assert_eq!(
            ip(&[("x-forwarded-for", " 203.0.113.9 , invalid")], None, true),
            "203.0.113.9"
        );
        assert_eq!(
            ip(
                &[
                    ("x-vercel-forwarded-for", "invalid"),
                    ("x-forwarded-for", "invalid, 10.0.0.1"),
                    ("x-real-ip", "198.51.100.7"),
                ],
                None,
                true,
            ),
            "198.51.100.7"
        );
        assert_eq!(ip(&[], Some("[::ffff:192.0.2.5]:1"), true), "192.0.2.5");
        assert_eq!(ip(&[], None, true), "");
    }

    #[test]
    fn direct_connection_uses_the_peer() {
        assert_eq!(
            ip(
                &[("x-vercel-forwarded-for", "203.0.113.9")],
                Some("[::ffff:192.0.2.5]:1"),
                false,
            ),
            "192.0.2.5"
        );
    }
}
