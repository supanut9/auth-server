//! `POST /v1/auth/consent/{accept,reject}` (Go
//! `handlers_otp_consent_stateless.go`).

use auth_core::{domain::ClientId, flow::UpsertConsentRequest};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;

use super::{
    body::{bind, bind_authorize_with},
    redirects::{authorization_success_url, oauth_error_url},
    respond::{error_only, invalid_request, issue_code, oauth_json},
};
use crate::{
    handlers::common::{current_sso_session, verify_csrf},
    json::json_response,
    state::AppState,
};

fn csrf_error(description: &str) -> Response {
    oauth_json(StatusCode::FORBIDDEN, "csrf", description)
}

fn redirect_to(target: &str) -> Response {
    json_response(StatusCode::OK, &json!({"redirect_to": target}))
}

/// Go `acceptConsentStateless`: bind (`csrf_token` required) → CSRF
/// (`403`) → validate (`400`) → SSO session (`401 unauthenticated`) →
/// upsert the consent → issue a code → `200 {"redirect_to"}`.
pub async fn accept(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let (body, extra) = match bind_authorize_with(&body, &["csrf_token"]) {
        Ok(bound) => bound,
        Err(error) => return invalid_request(&error.to_string()),
    };
    if let Err(description) = verify_csrf(&headers, &extra[0]) {
        return csrf_error(description);
    }
    let validated = match state.validator.validate(&body.to_oauth_request()).await {
        Ok(validated) => validated,
        Err(error) => {
            return oauth_json(
                StatusCode::BAD_REQUEST,
                error.code().as_str(),
                error.description(),
            );
        }
    };
    let Ok(session) = current_sso_session(&state, &headers).await else {
        return error_only(StatusCode::UNAUTHORIZED, "unauthenticated");
    };

    if let Err(error) = state
        .flow
        .upsert_consent(UpsertConsentRequest {
            account_id: session.account_id.clone(),
            client_id: validated.client().client_id.clone(),
            scopes: validated.scopes().as_slice().to_vec(),
        })
        .await
    {
        return oauth_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &error.to_string(),
        );
    }
    let code = match issue_code(&state, &session, &validated).await {
        Ok(code) => code,
        Err(error) => {
            return oauth_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &error.to_string(),
            );
        }
    };
    let request = validated.request();
    match authorization_success_url(&request.redirect_uri, &code, &request.state) {
        Some(target) => redirect_to(&target),
        None => error_only(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

/// Go `rejectConsentStateless`: bind (`client_id`, `redirect_uri`,
/// `state`, `csrf_token` required) → CSRF → the client exists (`400
/// invalid_client`) → `redirect_uri` is one of its registered URIs (`400
/// invalid_request`) → `200 {"redirect_to"}` carrying `access_denied`.
/// No status, scope or SSO session check: declining needs none.
pub async fn reject(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    const FIELDS: [&str; 4] = ["client_id", "redirect_uri", "state", "csrf_token"];
    let values = match bind(&body, &FIELDS, &FIELDS) {
        Ok(values) => values,
        Err(error) => return invalid_request(&error.to_string()),
    };
    let [client_id, redirect_uri, client_state, csrf_token] = &values[..] else {
        return error_only(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if let Err(description) = verify_csrf(&headers, csrf_token) {
        return csrf_error(description);
    }
    let Ok(client) = state
        .clients
        .find_by_client_id(&ClientId::new(client_id.as_str()))
        .await
    else {
        return error_only(StatusCode::BAD_REQUEST, "invalid_client");
    };
    if !client.has_redirect_uri(redirect_uri) {
        return error_only(StatusCode::BAD_REQUEST, "invalid_request");
    }
    match oauth_error_url(
        redirect_uri,
        client_state,
        "access_denied",
        "user denied consent",
    ) {
        Some(target) => redirect_to(&target),
        None => error_only(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}
