//! `support.go` `SupportAuthMiddleware`: static bearer token for
//! `/v1/support/*`.

use std::sync::Arc;

use auth_adapters::config::Config;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::Response,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::json::json_response;

/// The expected support token (`SUPPORT_API_TOKEN`, trimmed).
#[derive(Debug, Clone)]
pub struct SupportAuth {
    expected: Arc<SecretString>,
}

/// Outcome of checking one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportAuthResult {
    Allowed,
    /// No token configured: 503 `support_unavailable`.
    Unavailable,
    /// Missing or wrong token: 401 `invalid_token`.
    InvalidToken,
}

impl SupportAuth {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self::new(config.support_api_token.expose_secret())
    }

    #[must_use]
    pub fn new(token: &str) -> Self {
        Self {
            expected: Arc::new(SecretString::from(token.trim().to_owned())),
        }
    }

    /// Go: `TrimSpace(TrimPrefix(Authorization, "Bearer"))` (case-sensitive
    /// prefix, first header value), then a constant-time comparison.
    #[must_use]
    pub fn check(&self, headers: &HeaderMap) -> SupportAuthResult {
        let expected = self.expected.expose_secret();
        if expected.is_empty() {
            return SupportAuthResult::Unavailable;
        }
        let raw = headers
            .get(header::AUTHORIZATION)
            .map_or(&b""[..], |value| value.as_bytes());
        let raw = raw.strip_prefix(b"Bearer").unwrap_or(raw);
        // Non-UTF-8 bytes can never equal the (UTF-8) configured token.
        let Ok(raw) = std::str::from_utf8(raw) else {
            return SupportAuthResult::InvalidToken;
        };
        let provided = raw.trim();
        if provided.is_empty() {
            return SupportAuthResult::InvalidToken;
        }
        if bool::from(provided.as_bytes().ct_eq(expected.as_bytes())) {
            SupportAuthResult::Allowed
        } else {
            SupportAuthResult::InvalidToken
        }
    }
}

/// For `MethodRouter::route_layer(axum::middleware::from_fn_with_state(
/// support_auth, support_auth_middleware))` on every support route.
pub async fn support_auth_middleware(
    State(auth): State<SupportAuth>,
    request: Request,
    next: Next,
) -> Response {
    match auth.check(request.headers()) {
        SupportAuthResult::Allowed => next.run(request).await,
        SupportAuthResult::Unavailable => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "support_unavailable"}),
        ),
        SupportAuthResult::InvalidToken => {
            json_response(StatusCode::UNAUTHORIZED, &json!({"error": "invalid_token"}))
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn check(token: &str, header: Option<&str>) -> SupportAuthResult {
        let mut headers = HeaderMap::new();
        if let Some(value) = header {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        SupportAuth::new(token).check(&headers)
    }

    #[test]
    fn mirrors_go_parsing() {
        use SupportAuthResult::{Allowed, InvalidToken, Unavailable};
        assert_eq!(check("", Some("Bearer x")), Unavailable);
        assert_eq!(check("  ", Some("Bearer x")), Unavailable);
        assert_eq!(check("secret", None), InvalidToken);
        assert_eq!(check("secret", Some("Bearer")), InvalidToken);
        assert_eq!(check("secret", Some("Bearer   ")), InvalidToken);
        assert_eq!(check("secret", Some("Bearer secret")), Allowed);
        assert_eq!(check(" secret ", Some("Bearer secret")), Allowed);
        assert_eq!(check("secret", Some("Bearersecret")), Allowed);
        assert_eq!(check("secret", Some("secret")), Allowed);
        assert_eq!(check("secret", Some("bearer secret")), InvalidToken);
        assert_eq!(check("secret", Some("Bearer secret2")), InvalidToken);
        assert_eq!(check("secret", Some("Basic secret")), InvalidToken);
    }
}
