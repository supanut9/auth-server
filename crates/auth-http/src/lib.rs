//! HTTP routes shared by the local server and the Vercel function.
//!
//! Handlers register on a [`GinRouter`] (gin path syntax) and the result goes
//! through [`apply_global_layers`], which reproduces gin's middleware order
//! and routing quirks.

pub mod cookies;
pub mod go_url;
pub mod json;
pub mod middleware;
pub mod post_logout;
pub mod routing;

use std::sync::Arc;

use auth_adapters::config::Config;
use axum::{Router, extract::State, http::StatusCode, response::Response};
use serde_json::json;

use crate::middleware::{AccessLog, Cors};
pub use crate::{
    json::{GoJson, json_response},
    middleware::{GlobalLayers, RequestId},
    routing::{FullPath, GinRouter},
};

/// Applies the global middleware (request ID, JSON access log, CORS for
/// `AUTH_UI_BASE_URL`, panic recovery) and gin's routing quirks to `routes`.
pub fn apply_global_layers(routes: GinRouter, config: &Config) -> Router {
    routes.into_router(&GlobalLayers::from_config(config))
}

/// The router for `config`. Currently only the `GET /healthz` stub; handler
/// lanes add their routes here.
pub fn build_router(config: &Config) -> Router {
    apply_global_layers(health_routes(&config.app_name), config)
}

/// Config-free router kept for the current entrypoints until they load
/// [`Config`] and call [`build_router`]: same `GET /healthz` stub and global
/// layers, but no origin is CORS-allowed.
pub fn router() -> Router {
    health_routes("auth-server").into_router(&GlobalLayers {
        cors: Cors::deny_all(),
        access_log: AccessLog::stdout(),
    })
}

fn health_routes(app_name: &str) -> GinRouter {
    GinRouter::new()
        .get("/healthz", healthz)
        .with_state(Arc::<str>::from(app_name))
}

/// `GET /healthz` (no database check yet).
async fn healthz(State(app_name): State<Arc<str>>, request_id: RequestId) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "app_name": &*app_name,
            "request_id": request_id.as_str(),
            "status": "ok",
        }),
    )
}
