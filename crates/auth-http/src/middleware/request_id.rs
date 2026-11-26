//! `observability.go` `RequestIDMiddleware`.

use std::convert::Infallible;

use axum::{
    extract::{FromRequestParts, Request},
    http::{HeaderName, HeaderValue, request::Parts},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

/// `X-Request-Id`.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// The request ID stored in request extensions (gin `c.Set("request_id")`).
///
/// As an extractor it never fails: without the middleware it yields an empty
/// ID, like Go `requestIDFromContext`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestId(pub String);

impl RequestId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestId {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned().unwrap_or_default())
    }
}

/// Go `normalizeRequestID`: trimmed, 1..=128 bytes of `[A-Za-z0-9._-]`.
#[must_use]
pub fn normalize_request_id(raw: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(raw).ok()?.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        .then(|| value.to_owned())
}

/// Accepts a valid incoming `X-Request-Id` (first value) or generates a
/// UUIDv4, stores it as [`RequestId`] and echoes it on the response.
pub async fn request_id(mut request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| normalize_request_id(value.as_bytes()))
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let header = HeaderValue::from_str(&id).ok();
    request.extensions_mut().insert(RequestId(id));
    let mut response = next.run(request).await;
    if let Some(header) = header {
        response.headers_mut().insert(REQUEST_ID_HEADER, header);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_matches_go() {
        assert_eq!(
            normalize_request_id(b"  contract.request-01_OK \t").as_deref(),
            Some("contract.request-01_OK")
        );
        assert_eq!(
            normalize_request_id(&[b'a'; 128]).map(|id| id.len()),
            Some(128)
        );
        assert_eq!(normalize_request_id(&[b'a'; 129]), None);
        assert_eq!(normalize_request_id(b""), None);
        assert_eq!(normalize_request_id(b"   "), None);
        assert_eq!(normalize_request_id(b"bad id"), None);
        assert_eq!(normalize_request_id(b"a/b"), None);
        assert_eq!(normalize_request_id("é".as_bytes()), None);
        assert_eq!(normalize_request_id(&[0xff]), None);
    }
}
