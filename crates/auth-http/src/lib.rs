//! HTTP routes shared by the local server and the Vercel function.

use axum::{Json, Router, http::HeaderName, response::IntoResponse, routing::get};
use serde_json::json;
use uuid::Uuid;

/// Builds the authorization server router.
pub fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

async fn healthz() -> impl IntoResponse {
    let request_id = Uuid::new_v4().to_string();
    let body = json!({
        "app_name": "auth-server",
        "request_id": request_id,
        "status": "ok",
    });

    (
        [(HeaderName::from_static("x-request-id"), request_id)],
        Json(body),
    )
}
