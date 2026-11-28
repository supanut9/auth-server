//! Vercel's daily retention job.

use auth_core::crypto::{constant_time_eq, sha256_b64url};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use secrecy::ExposeSecret;
use serde_json::json;

use super::gohttp::error_json;
use crate::{json::json_response, state::AppState};

pub async fn cleanup(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let response = match &state.config.cron_secret {
        None => error_json(StatusCode::SERVICE_UNAVAILABLE, "cleanup_unavailable"),
        Some(secret) if authorized(&headers, secret.expose_secret()) => {
            match state.cleanup.delete_expired(state.clock.now()).await {
                Ok(deleted) => json_response(StatusCode::OK, &json!({"deleted": deleted})),
                Err(_) => error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            }
        }
        Some(_) => unauthorized(),
    };
    ([(header::CACHE_CONTROL, "no-store")], response)
}

fn authorized(headers: &HeaderMap, secret: &str) -> bool {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
    else {
        return false;
    };
    // Compare fixed-length digests even when the supplied token has another length.
    constant_time_eq(
        sha256_b64url(token).as_bytes(),
        sha256_b64url(secret).as_bytes(),
    )
}

fn unauthorized() -> Response {
    (
        [(header::WWW_AUTHENTICATE, "Bearer")],
        error_json(StatusCode::UNAUTHORIZED, "invalid_token"),
    )
        .into_response()
}
