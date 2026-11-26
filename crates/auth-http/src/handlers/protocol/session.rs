//! `GET /v1/clients/:clientID/public-info`, `GET /v1/auth/me` and
//! `GET /v1/auth/csrf` (Go `helpers.go`).

use auth_core::{crypto::b64url_encode, domain::ClientId, ports::RepoError};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::gohttp::{error_json, format_go_time, path_segment, split_protocol_list};
use crate::{
    cookies::CSRF_TOKEN_TTL_SECONDS, handlers::common::current_sso_session, json::json_response,
    state::AppState,
};

/// Index of `:clientID` in `/v1/clients/:clientID/public-info`.
const CLIENT_ID_SEGMENT: usize = 3;

/// Go `clientPublicInfo`: the non-secret client fields. `allowed_scopes`
/// keeps the stored order (first occurrence), it is not sorted. The client
/// status is not checked.
pub async fn client_public_info(State(state): State<AppState>, uri: Uri) -> Response {
    let segment = path_segment(&uri, CLIENT_ID_SEGMENT);
    let client_id = segment.trim();
    if client_id.is_empty() {
        return error_json(StatusCode::BAD_REQUEST, "invalid_request");
    }
    match state
        .clients
        .find_by_client_id(&ClientId::new(client_id))
        .await
    {
        Ok(client) => json_response(
            StatusCode::OK,
            &json!({
                "client_id": client.client_id.as_str(),
                "display_name": client.display_name,
                "logo_uri": client.logo_uri,
                "allowed_scopes": split_protocol_list(&client.allowed_scopes),
            }),
        ),
        Err(RepoError::NotFound) => error_json(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

/// Go `currentUser`: `401 {"error":"unauthenticated"}` unless the SSO
/// cookie names an active session whose account loads.
pub async fn current_user(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let unauthenticated = || error_json(StatusCode::UNAUTHORIZED, "unauthenticated");
    let Ok(session) = current_sso_session(&state, &headers).await else {
        return unauthenticated();
    };
    let Ok(account) = state.accounts.find_by_id(&session.account_id).await else {
        return unauthenticated();
    };
    let (Ok(expires_at), Ok(authenticated_at)) = (
        format_go_time(session.expires_at),
        format_go_time(session.authenticated_at),
    ) else {
        // Go's time.Time MarshalJSON failure panics into gin's recovery.
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    json_response(
        StatusCode::OK,
        &json!({
            "account_id": account.id.as_str(),
            "display_name": account.display_name,
            "email": account.primary_verified_email,
            "login_method": session.login_method,
            "authenticated": true,
            "session": {
                "id": session.id.as_str(),
                "expires_at": expires_at,
                "authenticated_at": authenticated_at,
            },
        }),
    )
}

/// Go `csrfToken`: a fresh double-submit token (32 random bytes,
/// base64url, 43 characters) set as the non-`HttpOnly` `auth_csrf` cookie
/// and returned with its lifetime.
pub async fn csrf_token(State(state): State<AppState>) -> Response {
    let mut raw = [0_u8; 32];
    if state.random.fill_bytes(&mut raw).is_err() {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    let token = b64url_encode(raw);
    let mut response = json_response(
        StatusCode::OK,
        &json!({"csrf_token": token, "expires_in": CSRF_TOKEN_TTL_SECONDS}),
    );
    response
        .headers_mut()
        .append(header::SET_COOKIE, state.cookies.csrf_cookie(&token));
    response
}
