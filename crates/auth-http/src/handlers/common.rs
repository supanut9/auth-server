//! Helpers shared by the protocol and flow handlers.

use auth_core::{
    crypto::constant_time_eq,
    domain::{SessionId, SsoSession, SsoSessionStatus},
};
use axum::http::HeaderMap;

use crate::{
    cookies::{CSRF_COOKIE_NAME, SSO_COOKIE_NAME, read_cookie},
    state::AppState,
};

/// Why [`current_sso_session`] found no usable session.
#[derive(Debug)]
pub enum SessionLookupError {
    /// No `auth_sso_session` cookie (Go `http.ErrNoCookie`).
    NoCookie,
    /// The repository failed, including `NotFound` (Go returned the GORM error).
    Repo(auth_core::ports::RepoError),
    /// Found but not active, expired or revoked (Go `"inactive sso session"`).
    Inactive,
}

/// Go `Handler.currentSSOSession`: the session named by the SSO cookie, only
/// if it is active, not past `expires_at` and not revoked.
pub async fn current_sso_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<SsoSession, SessionLookupError> {
    let id = read_cookie(headers, SSO_COOKIE_NAME).ok_or(SessionLookupError::NoCookie)?;
    let session = state
        .sso_sessions
        .find_by_id(&SessionId::new(id))
        .await
        .map_err(SessionLookupError::Repo)?;
    let expired = state.clock.now() > session.expires_at;
    if session.status != SsoSessionStatus::Active || expired || session.revoked_at.is_some() {
        return Err(SessionLookupError::Inactive);
    }
    Ok(session)
}

/// Go `verifyCSRF`: double-submit check of the body token against the
/// `auth_csrf` cookie. The error is the exact `error_description` Go sent
/// with `403 {"error":"csrf"}`.
pub fn verify_csrf(headers: &HeaderMap, body_token: &str) -> Result<(), &'static str> {
    if body_token.is_empty() {
        return Err("missing csrf token");
    }
    // Go `c.Cookie` errors only when the cookie is absent; an empty value
    // falls through to the comparison and reports a mismatch.
    let Some(cookie) = read_cookie(headers, CSRF_COOKIE_NAME) else {
        return Err("missing csrf cookie");
    };
    if !constant_time_eq(body_token.as_bytes(), cookie.as_bytes()) {
        return Err("csrf token mismatch");
    }
    Ok(())
}
