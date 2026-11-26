//! `GET /v1/oauth2/authorize` (Go `handlers_stateless.go
//! authorizeStateless`).

use auth_core::oauth::AuthorizeRequest;
use axum::{
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use super::{
    redirects::{QueryValues, auth_ui_route, preserved_authorize_query},
    respond::{
        found, has_consent, issue_code, oauth_json, redirect_authorization_success,
        redirect_oauth_error,
    },
};
use crate::{handlers::common::current_sso_session, state::AppState};

/// Stateless authorize: no authorization-request row; the OAuth params
/// travel in URLs and are re-validated by every action endpoint.
///
/// - Validation error: fatal → `400` JSON; recoverable → 302 to the raw
///   `redirect_uri` with `error`.
/// - `prompt=login` skips the SSO session lookup.
/// - Session + consent covering the scopes → code issued with
///   `auth_time = authenticated_at`, 302 to the client.
/// - Session without consent → `consent_required` for `prompt=none`, else
///   302 to auth-ui `/consent`.
/// - No session → `login_required` for `prompt=none`, else 302 to auth-ui
///   `/login`.
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let query = QueryValues::parse(raw_query.as_deref().unwrap_or_default());
    let prompt = query.get("prompt");
    let request = AuthorizeRequest {
        response_type: query.get("response_type").to_owned(),
        client_id: query.get("client_id").to_owned(),
        redirect_uri: query.get("redirect_uri").to_owned(),
        scope: query.get("scope").to_owned(),
        state: query.get("state").to_owned(),
        nonce: query.get("nonce").to_owned(),
        code_challenge: query.get("code_challenge").to_owned(),
        code_challenge_method: query.get("code_challenge_method").to_owned(),
        prompt: prompt.to_owned(),
    };

    let validated = match state.validator.validate(&request).await {
        Ok(validated) => validated,
        Err(error) if error.is_recoverable() => {
            return redirect_oauth_error(
                &request.redirect_uri,
                &request.state,
                error.code().as_str(),
                error.description(),
            );
        }
        Err(error) => {
            return oauth_json(
                StatusCode::BAD_REQUEST,
                error.code().as_str(),
                error.description(),
            );
        }
    };
    let redirect_uri = &validated.request().redirect_uri;
    let client_state = &validated.request().state;

    let session = if prompt == "login" {
        None
    } else {
        current_sso_session(&state, &headers).await.ok()
    };

    let Some(session) = session else {
        if prompt == "none" {
            return redirect_oauth_error(
                redirect_uri,
                client_state,
                "login_required",
                "no active SSO session",
            );
        }
        let target = auth_ui_route(
            &state.config.auth_ui_base_url,
            "/login",
            &preserved_authorize_query(&query),
        );
        return found(&target);
    };

    if has_consent(&state, &session, &validated).await {
        return match issue_code(&state, &session, &validated).await {
            Ok(code) => redirect_authorization_success(redirect_uri, &code, client_state),
            Err(error) => redirect_oauth_error(
                redirect_uri,
                client_state,
                "server_error",
                &error.to_string(),
            ),
        };
    }
    if prompt == "none" {
        return redirect_oauth_error(
            redirect_uri,
            client_state,
            "consent_required",
            "consent required",
        );
    }
    found(&auth_ui_route(
        &state.config.auth_ui_base_url,
        "/consent",
        &preserved_authorize_query(&query),
    ))
}
