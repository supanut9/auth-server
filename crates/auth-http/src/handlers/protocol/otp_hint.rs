//! `GET /v1/auth/otp/test-hint` (Go `handlers_otp_test_hint.go`, INT-244):
//! non-production only.

use std::sync::Arc;

use auth_core::{identity::equal_fold, ports::OtpChallengeRepository};
use axum::{
    extract::State,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::gohttp::{error_json, format_go_time, url_query};
use crate::{json::json_response, state::AppState};

/// The OTP challenge repository the test hint reads.
///
/// [`AppState`] carries no OTP challenge repository (only the identity
/// service holds one), so the entrypoint provides it as a request
/// extension: `router.layer(axum::Extension(OtpHintSource(repo)))`.
/// Without it every lookup fails, which the endpoint reports as `404`
/// (Go's "no active challenge").
#[derive(Clone)]
pub struct OtpHintSource(pub Arc<dyn OtpChallengeRepository>);

impl std::fmt::Debug for OtpHintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpHintSource").finish_non_exhaustive()
    }
}

fn not_found() -> Response {
    error_json(StatusCode::NOT_FOUND, "not_found")
}

/// Go `testOTPHint`: `404 not_found` in production, without an allowlist,
/// for a non-allowlisted email or without an active challenge; `400` for a
/// missing `email`; otherwise the challenge ID, email, expiry and the
/// first 8 characters of the code hash (never the code).
pub async fn test_otp_hint(
    State(state): State<AppState>,
    source: Option<axum::Extension<OtpHintSource>>,
    uri: Uri,
) -> Response {
    let config = &state.config;
    if config.is_production() || config.otp_test_hint_allowlist.is_empty() {
        return not_found();
    }
    let email = url_query(&uri)
        .get("email")
        .to_lowercase()
        .trim()
        .to_owned();
    if email.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "invalid_request", "error_description": "email query param required"}),
        );
    }
    let allowed = config
        .otp_test_hint_allowlist
        .iter()
        .any(|entry| equal_fold(entry.trim(), &email));
    if !allowed {
        return not_found();
    }
    let Some(axum::Extension(OtpHintSource(repo))) = source else {
        return not_found();
    };
    let Ok(challenge) = repo.find_latest_active_by_email(&email).await else {
        return not_found();
    };
    // Go slices `CodeHash[:8]` and `time.Time` marshals; either failing
    // panics into gin's recovery (500, empty body).
    let (Some(prefix), Ok(expires_at)) = (
        challenge.code_hash.get(..8),
        format_go_time(challenge.expires_at),
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    json_response(
        StatusCode::OK,
        &json!({
            "otp_challenge_id": challenge.id.as_str(),
            "email": challenge.email,
            "expires_at": expires_at,
            "code_hash_prefix": prefix,
        }),
    )
}
