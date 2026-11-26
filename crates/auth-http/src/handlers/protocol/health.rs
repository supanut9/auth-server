//! `GET /healthz`, `GET /readyz` and the non-production `GET /dev/callback`.

use axum::{
    extract::State,
    http::{StatusCode, Uri},
    response::Response,
};
use serde_json::json;

use super::gohttp::url_query;
use crate::{json::json_response, middleware::RequestId, routing::not_found, state::AppState};

/// Go `healthz`.
pub async fn healthz(State(state): State<AppState>, request_id: RequestId) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "status": "ok",
            "app_name": state.config.app_name,
            "request_id": request_id.as_str(),
        }),
    )
}

/// Go `readyz`: the [`auth_core::ports::ReadinessProbe`] applies Go's 2 s
/// ping timeout itself.
pub async fn readyz(State(state): State<AppState>, request_id: RequestId) -> Response {
    if state.readiness.ping().await.is_err() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"status": "degraded", "error": "database_unavailable"}),
        );
    }
    json_response(
        StatusCode::OK,
        &json!({
            "status": "ok",
            "app_name": state.config.app_name,
            "database": "ready",
            "request_id": request_id.as_str(),
        }),
    )
}

/// Go `devCallback`: echoes `code`, `state` and `error`. Not mounted in
/// production; answers gin's 404 there when mounted anyway.
pub async fn dev_callback(State(state): State<AppState>, uri: Uri) -> Response {
    if state.config.is_production() {
        return not_found().await;
    }
    let query = url_query(&uri);
    json_response(
        StatusCode::OK,
        &json!({
            "code": query.get("code"),
            "state": query.get("state"),
            "error": query.get("error"),
        }),
    )
}
