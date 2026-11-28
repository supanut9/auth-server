//! Global and per-route middleware (`internal/httpserver/server.go` and
//! `internal/adapter/in/http`).
//!
//! Global order, outermost first, as gin applies `router.Use(...)`:
//! request ID → access log → CORS → panic recovery → handler. CORS sits
//! outside recovery here (gin has it inside) so a panic's 500 still carries
//! the CORS headers gin had already written to the response before the
//! panic; the observable result is the same.

pub mod client_ip;
pub mod cors;
pub mod logger;
pub mod request_id;
pub mod support_auth;

use std::any::Any;

use auth_adapters::config::Config;
use axum::{
    Router,
    body::Body,
    http::{Response, StatusCode},
    middleware::{from_fn, from_fn_with_state},
};
use tower_http::catch_panic::CatchPanicLayer;

pub use self::{
    client_ip::client_ip,
    cors::Cors,
    logger::{AccessLog, LogErrors},
    request_id::RequestId,
    support_auth::{SupportAuth, support_auth_middleware},
};

/// The global middleware stack.
#[derive(Debug, Clone)]
pub struct GlobalLayers {
    pub cors: Cors,
    pub access_log: AccessLog,
}

impl GlobalLayers {
    /// CORS for `AUTH_UI_BASE_URL`, access log to stdout.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self {
            cors: Cors::new(&config.auth_ui_base_url),
            access_log: AccessLog::stdout(),
        }
    }

    /// Replaces the access-log sink (tests).
    #[must_use]
    pub fn with_access_log(mut self, access_log: AccessLog) -> Self {
        self.access_log = access_log;
        self
    }

    /// Applies the stack to every route and the fallback of `router`.
    pub(crate) fn wrap(&self, router: Router) -> Router {
        router
            .layer(CatchPanicLayer::custom(panic_response))
            .layer(from_fn_with_state(self.cors.clone(), cors::cors))
            .layer(from_fn_with_state(
                self.access_log.clone(),
                logger::access_log,
            ))
            .layer(from_fn(request_id::request_id))
    }
}

/// gin `Recovery`: `AbortWithStatus(500)`, so no body and no content type.
fn panic_response(_panic: Box<dyn Any + Send + 'static>) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}
