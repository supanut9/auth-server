//! `GET /v1/support/accounts/:accountID` and `POST
//! /v1/support/accounts/:accountID/sign-out` (Go `support.go`).
//!
//! Response structs keep Go's field order; lists are never `null`.

use auth_core::{
    domain::{AccountId, ChainId, ClientId, SessionId},
    ports::{RepoError, SupportAccountSummary},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;

use super::gohttp::{error_json, path_segment, serialize_optional_time, serialize_time};
use crate::{json::json_response, middleware::support_auth::SupportAuthResult, state::AppState};

/// Index of `:accountID` in `/v1/support/accounts/:accountID[/sign-out]`.
const ACCOUNT_ID_SEGMENT: usize = 4;

#[derive(Serialize)]
struct SupportAccount<'a> {
    id: &'a str,
    email: &'a str,
    display_name: &'a str,
    avatar_url: &'a str,
    status: &'a str,
    #[serde(serialize_with = "serialize_time")]
    created_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_time")]
    updated_at: OffsetDateTime,
}

#[derive(Serialize)]
struct SupportClientRef<'a> {
    client_id: &'a str,
    display_name: &'a str,
}

#[derive(Serialize)]
struct SupportSession<'a> {
    id: &'a str,
    status: &'a str,
    login_method: &'a str,
    #[serde(serialize_with = "serialize_time")]
    authenticated_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_time")]
    last_seen_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_time")]
    expires_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_optional_time")]
    revoked_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
struct SupportConsent<'a> {
    id: &'a str,
    client: SupportClientRef<'a>,
    granted_scopes: &'a str,
    #[serde(serialize_with = "serialize_time")]
    granted_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_time")]
    last_used_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_optional_time")]
    revoked_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
struct SupportRefreshChain<'a> {
    id: &'a str,
    client: SupportClientRef<'a>,
    sso_session_id: &'a str,
    scope: &'a str,
    status: &'a str,
    #[serde(serialize_with = "serialize_time")]
    absolute_expires_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_time")]
    inactive_expires_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_time")]
    last_used_at: OffsetDateTime,
    #[serde(serialize_with = "serialize_optional_time")]
    revoked_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
struct SupportAccountSummaryResponse<'a> {
    account: SupportAccount<'a>,
    sessions: Vec<SupportSession<'a>>,
    consents: Vec<SupportConsent<'a>>,
    refresh_token_chains: Vec<SupportRefreshChain<'a>>,
}

#[derive(Serialize)]
struct SupportSignOutResponse<'a> {
    account_id: &'a str,
    revoked_session_ids: Vec<&'a str>,
    revoked_chain_ids: Vec<&'a str>,
    revoked_refresh_chain_count: usize,
}

fn client_ref<'a>(
    summary: &'a SupportAccountSummary,
    client_id: &'a ClientId,
) -> SupportClientRef<'a> {
    SupportClientRef {
        client_id: client_id.as_str(),
        // A client missing from the registry renders an empty name (Go's
        // zero-value map lookup).
        display_name: summary
            .client_display_names
            .get(client_id)
            .map_or("", String::as_str),
    }
}

fn summary_response(summary: &SupportAccountSummary) -> SupportAccountSummaryResponse<'_> {
    let account = &summary.account;
    SupportAccountSummaryResponse {
        account: SupportAccount {
            id: account.id.as_str(),
            email: &account.primary_verified_email,
            display_name: &account.display_name,
            avatar_url: &account.avatar_url,
            status: account.status.as_str(),
            created_at: account.created_at,
            updated_at: account.updated_at,
        },
        sessions: summary
            .sessions
            .iter()
            .map(|session| SupportSession {
                id: session.id.as_str(),
                status: session.status.as_str(),
                login_method: &session.login_method,
                authenticated_at: session.authenticated_at,
                last_seen_at: session.last_seen_at,
                expires_at: session.expires_at,
                revoked_at: session.revoked_at,
            })
            .collect(),
        consents: summary
            .consents
            .iter()
            .map(|consent| SupportConsent {
                id: consent.id.as_str(),
                client: client_ref(summary, &consent.client_id),
                granted_scopes: &consent.granted_scopes,
                granted_at: consent.granted_at,
                last_used_at: consent.last_used_at,
                revoked_at: consent.revoked_at,
            })
            .collect(),
        refresh_token_chains: summary
            .refresh_token_chains
            .iter()
            .map(|chain| SupportRefreshChain {
                id: chain.id.as_str(),
                client: client_ref(summary, &chain.client_id),
                sso_session_id: chain.sso_session_id.as_str(),
                scope: &chain.scope,
                status: chain.status.as_str(),
                absolute_expires_at: chain.absolute_expires_at,
                inactive_expires_at: chain.inactive_expires_at,
                last_used_at: chain.last_used_at,
                revoked_at: chain.revoked_at,
            })
            .collect(),
    }
}

/// Why a support request stopped before its action.
enum SupportFailure {
    /// Go `SupportAuthMiddleware`: `503 support_unavailable` without a
    /// configured token.
    Unavailable,
    /// `401 invalid_token`: missing or wrong bearer.
    InvalidToken,
    /// `400 invalid_request`: blank `:accountID`.
    InvalidRequest,
    /// `404 not_found` (Go `renderLookupError`).
    NotFound,
    /// `500 server_error`.
    ServerError,
}

impl SupportFailure {
    fn into_response(self) -> Response {
        match self {
            Self::Unavailable => json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "support_unavailable"}),
            ),
            Self::InvalidToken => error_json(StatusCode::UNAUTHORIZED, "invalid_token"),
            Self::InvalidRequest => error_json(StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => error_json(StatusCode::NOT_FOUND, "not_found"),
            Self::ServerError => error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        }
    }
}

/// The support bearer check (run first, as gin's group middleware is), the
/// trimmed `:accountID` and the account summary.
async fn load_summary(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<(String, SupportAccountSummary), SupportFailure> {
    match state.support_auth.check(headers) {
        SupportAuthResult::Allowed => {}
        SupportAuthResult::Unavailable => return Err(SupportFailure::Unavailable),
        SupportAuthResult::InvalidToken => return Err(SupportFailure::InvalidToken),
    }
    let account_id = path_segment(uri, ACCOUNT_ID_SEGMENT).trim().to_owned();
    if account_id.is_empty() {
        return Err(SupportFailure::InvalidRequest);
    }
    match state
        .support
        .load_account_summary(&AccountId::new(account_id.as_str()))
        .await
    {
        Ok(summary) => Ok((account_id, summary)),
        Err(RepoError::NotFound) => Err(SupportFailure::NotFound),
        Err(_) => Err(SupportFailure::ServerError),
    }
}

/// Go `getSupportAccount`.
pub async fn get_support_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    match load_summary(&state, &headers, &uri).await {
        Ok((_, summary)) => json_response(StatusCode::OK, &summary_response(&summary)),
        Err(failure) => failure.into_response(),
    }
}

/// Go `signOutSupportAccount`: revokes every session and refresh chain the
/// summary lists (whatever their status) in one transaction and reports
/// their IDs. `account_id` echoes the trimmed path value.
pub async fn sign_out_support_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let (account_id, summary) = match load_summary(&state, &headers, &uri).await {
        Ok(loaded) => loaded,
        Err(failure) => return failure.into_response(),
    };
    let session_ids: Vec<_> = summary.sessions.iter().map(|s| s.id.clone()).collect();
    let chain_ids: Vec<_> = summary
        .refresh_token_chains
        .iter()
        .map(|chain| chain.id.clone())
        .collect();
    if state
        .support
        .sign_out(&session_ids, &chain_ids, state.clock.now())
        .await
        .is_err()
    {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }
    json_response(
        StatusCode::OK,
        &SupportSignOutResponse {
            account_id: &account_id,
            revoked_session_ids: session_ids.iter().map(SessionId::as_str).collect(),
            revoked_chain_ids: chain_ids.iter().map(ChainId::as_str).collect(),
            revoked_refresh_chain_count: chain_ids.len(),
        },
    )
}
