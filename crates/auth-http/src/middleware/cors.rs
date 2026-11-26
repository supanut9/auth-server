//! `router.go` `CORSMiddleware`.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::Response,
};

/// The single allowed browser origin: `AUTH_UI_BASE_URL` with trailing `/`
/// trimmed.
#[derive(Debug, Clone)]
pub struct Cors {
    allowed_origin: Option<Arc<[u8]>>,
}

impl Cors {
    /// Allows `auth_ui_base_url` (trailing slashes trimmed).
    #[must_use]
    pub fn new(auth_ui_base_url: &str) -> Self {
        Self {
            allowed_origin: Some(trim_trailing_slashes(auth_ui_base_url.as_bytes()).into()),
        }
    }

    /// Allows no origin; only `Vary` and the `OPTIONS` short-circuit remain.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            allowed_origin: None,
        }
    }

    /// The trimmed `Origin` header when it equals the allowed origin. A
    /// missing header compares as the empty string, as Go `GetHeader` does.
    fn matching_origin<'a>(&self, headers: &'a HeaderMap) -> Option<&'a [u8]> {
        let allowed = self.allowed_origin.as_deref()?;
        let origin = trim_trailing_slashes(
            headers
                .get(header::ORIGIN)
                .map_or(&b""[..], HeaderValue::as_bytes),
        );
        (origin == allowed).then_some(origin)
    }
}

fn trim_trailing_slashes(value: &[u8]) -> &[u8] {
    let end = value.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    &value[..end]
}

/// Sets `name` unless the handler already did. gin sets these before the
/// handler runs, so a handler's own `Set` wins; this keeps that outcome.
fn set_default(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue) {
    headers.entry(name).or_insert(value);
}

fn apply(headers: &mut HeaderMap, origin: Option<&HeaderValue>) {
    set_default(headers, header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        set_default(headers, header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        set_default(
            headers,
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        set_default(
            headers,
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        set_default(
            headers,
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
    }
}

/// Adds `Vary: Origin` everywhere and the credentialed CORS headers for the
/// allowed origin; answers every `OPTIONS` request with 204 and no body (no
/// `Max-Age`), on any path, before the handler.
pub async fn cors(State(cors): State<Cors>, request: Request, next: Next) -> Response {
    let origin = cors
        .matching_origin(request.headers())
        .and_then(|origin| HeaderValue::from_bytes(origin).ok());

    let mut response = if request.method() == Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        response
    } else {
        next.run(request).await
    };
    apply(response.headers_mut(), origin.as_ref());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(cors: &Cors, value: Option<&str>) -> Option<String> {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(header::ORIGIN, HeaderValue::from_str(value).unwrap());
        }
        cors.matching_origin(&headers)
            .map(|origin| String::from_utf8(origin.to_vec()).unwrap())
    }

    #[test]
    fn exact_origin_after_trimming_slashes() {
        let cors = Cors::new("https://auth-ui.example//");
        assert_eq!(
            origin(&cors, Some("https://auth-ui.example/")).as_deref(),
            Some("https://auth-ui.example")
        );
        assert_eq!(origin(&cors, Some("https://AUTH-UI.example")), None);
        assert_eq!(origin(&cors, Some("https://auth-ui.example:443")), None);
        assert_eq!(origin(&cors, None), None);
        assert_eq!(
            origin(&Cors::deny_all(), Some("https://auth-ui.example")),
            None
        );
        // Go compares "" == "" when the configured origin is only slashes.
        assert_eq!(origin(&Cors::new("/"), None).as_deref(), Some(""));
    }
}
