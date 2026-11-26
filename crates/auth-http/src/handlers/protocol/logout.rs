//! `GET /v1/auth/logout` and `GET /v1/auth/logout/global` (Go
//! `logoutLocal`, `logoutGlobal`).

use auth_core::domain::{ChainId, SessionId};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};

use super::gohttp::{error_json, found, url_query};
use crate::{
    cookies::{SSO_COOKIE_NAME, read_cookie},
    handlers::common::{SessionLookupError, current_sso_session},
    post_logout::post_logout_redirect_for,
    state::AppState,
};

/// Go `logoutLocal` (AUTH-018): `refresh_token_chain_id` is honoured only
/// for a chain owned by the caller's active SSO session. No cookie, an
/// unknown session or an inactive one ignore the parameter; a real
/// repository failure is `500 {"error":"server_error"}`. Then `302` to the
/// post-logout target. The SSO cookie is left alone.
pub async fn logout_local(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let query = url_query(&uri);
    let chain_id = query.get("refresh_token_chain_id");
    if !chain_id.is_empty() {
        let result = match current_sso_session(&state, &headers).await {
            Ok(session) => state
                .flow
                .logout_local(&session.id, &ChainId::new(chain_id))
                .await
                .map_err(drop),
            Err(
                SessionLookupError::NoCookie
                | SessionLookupError::Inactive
                | SessionLookupError::Repo(auth_core::ports::RepoError::NotFound),
            ) => Ok(()),
            Err(SessionLookupError::Repo(_)) => Err(()),
        };
        if result.is_err() {
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    }
    found(&post_logout_redirect_for(
        &state.config,
        query.get("post_logout_redirect_uri"),
    ))
}

/// Go `logoutGlobal` (AUTH-019): without an SSO cookie value, just the
/// redirect. Otherwise revoke the session and its refresh chains, clear the
/// cookie (`Max-Age=0`) and redirect.
pub async fn logout_global(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let query = url_query(&uri);
    let target = post_logout_redirect_for(&state.config, query.get("post_logout_redirect_uri"));
    let session_id = read_cookie(&headers, SSO_COOKIE_NAME).unwrap_or_default();
    if session_id.is_empty() {
        return found(&target);
    }
    if state
        .flow
        .logout_global(&SessionId::new(session_id))
        .await
        .is_err()
    {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    let mut response = found(&target);
    response
        .headers_mut()
        .append(header::SET_COOKIE, state.cookies.clear_sso_cookie());
    response
}
