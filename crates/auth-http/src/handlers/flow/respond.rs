//! Response helpers shared by the flow handlers.

use std::time::Instant;

use auth_core::{
    domain::SsoSession,
    flow::{FlowError, IssueDirectCodeRequest},
    oauth::ValidatedAuthorizeRequest,
};
use axum::{
    body::Body,
    extract::FromRequestParts,
    http::{HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

use super::redirects::{
    authorization_success_url, hex_escape_non_ascii, html_escape, oauth_error_url,
};
use crate::{
    cookies::sso_max_age,
    json::{JSON_CONTENT_TYPE, json_response, to_go_json},
    middleware::{
        client_ip::client_ip,
        rate_limit::{otp_rate_limit_key, retry_after_seconds},
    },
    routing::FullPath,
    state::AppState,
};

/// `c.JSON(status, gin.H{"error": error, "error_description": description})`.
#[must_use]
pub fn oauth_json(status: StatusCode, error: &str, description: &str) -> Response {
    json_response(
        status,
        &json!({"error": error, "error_description": description}),
    )
}

/// `c.JSON(status, gin.H{"error": error})`.
#[must_use]
pub fn error_only(status: StatusCode, error: &str) -> Response {
    json_response(status, &json!({"error": error}))
}

/// `400 {"error":"invalid_request","error_description":...}` (bind and
/// identity failures).
#[must_use]
pub fn invalid_request(description: &str) -> Response {
    oauth_json(StatusCode::BAD_REQUEST, "invalid_request", description)
}

/// gin `c.Redirect(302, location)` on a `GET`: Go `http.Redirect` writes
/// `Location` with non-ASCII bytes hex-escaped, `text/html` and a short
/// HTML body. Every location built here is absolute, so the relative-path
/// resolution of `http.Redirect` never applies.
#[must_use]
pub fn found(location: &str) -> Response {
    let location = hex_escape_non_ascii(location);
    let body = format!("<a href=\"{}\">Found</a>.\n\n", html_escape(&location));
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

/// Go `redirectOAuthError`: 302 to the redirect URI with the error, or
/// `400 {"error","error_description"}` when the URI is unusable.
#[must_use]
pub fn redirect_oauth_error(
    redirect_uri: &str,
    state: &str,
    error: &str,
    description: &str,
) -> Response {
    match oauth_error_url(redirect_uri, state, error, description) {
        Some(target) => found(&target),
        None => oauth_json(StatusCode::BAD_REQUEST, error, description),
    }
}

/// Go `redirectAuthorizationSuccess`: 302 to the redirect URI with the
/// code, or `400 {"error":"invalid_request"}` when the URI is unusable.
#[must_use]
pub fn redirect_authorization_success(redirect_uri: &str, code: &str, state: &str) -> Response {
    match authorization_success_url(redirect_uri, code, state) {
        Some(target) => found(&target),
        None => error_only(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

/// Go `setSSOCookie`: appends the `auth_sso_session` cookie for `session`.
pub fn set_sso_cookie(state: &AppState, response: &mut Response, session: &SsoSession) {
    let max_age = sso_max_age(session.expires_at, state.clock.now());
    response.headers_mut().append(
        header::SET_COOKIE,
        state.cookies.sso_cookie(session.id.as_str(), max_age),
    );
}

/// Whether `session`'s account already consented to the validated scopes
/// for the validated client (Go `Flow.HasConsentForScopes`).
pub async fn has_consent(
    state: &AppState,
    session: &SsoSession,
    validated: &ValidatedAuthorizeRequest,
) -> bool {
    state
        .flow
        .has_consent_for_scopes(
            &session.account_id,
            &validated.client().client_id,
            validated.scopes().as_slice(),
        )
        .await
}

/// Go `Flow.IssueDirectCode` for `session` (its account, ID and
/// `authenticated_at`) and the validated request (including its `nonce`).
/// Shared by all four code-issuing paths: authorize, provider post-auth,
/// OTP verify and consent accept. Returns the code value.
pub async fn issue_code(
    state: &AppState,
    session: &SsoSession,
    validated: &ValidatedAuthorizeRequest,
) -> Result<String, FlowError> {
    let request = validated.request();
    let (code, _) = state
        .flow
        .issue_direct_code(IssueDirectCodeRequest {
            account_id: session.account_id.clone(),
            client_id: validated.client().client_id.clone(),
            sso_session_id: Some(session.id.clone()),
            redirect_uri: request.redirect_uri.clone(),
            scopes: validated.scopes().as_slice().to_vec(),
            pkce_code_challenge: request.code_challenge.clone(),
            pkce_code_challenge_method: request.code_challenge_method.clone(),
            nonce: request.nonce.clone(),
            auth_time: session.authenticated_at,
        })
        .await?;
    Ok(code)
}

/// A JSON object response whose `email` member is the pre-rendered
/// [`auth_core::identity::mask_email_json`] token, so the bytes match gin
/// even when masking cut a multi-byte character (`�`). `rest` must not
/// hold `email` and its keys must sort after it.
#[must_use]
pub fn json_with_masked_email(masked_email_json: &str, rest: &Map<String, Value>) -> Response {
    let Ok(rest) = to_go_json(rest) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut body = Vec::with_capacity(rest.len() + masked_email_json.len() + 10);
    body.extend_from_slice(b"{\"email\":");
    body.extend_from_slice(masked_email_json.as_bytes());
    if rest.len() > 2 {
        body.push(b',');
        body.extend_from_slice(&rest[1..]);
    } else {
        body.push(b'}');
    }
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    response
}

/// Go `OTPRateLimitMiddleware` as an extractor: listed first in the OTP
/// handlers' arguments, it runs before the body is read, as the gin
/// middleware ran before the handler. Uses the limiter shared through
/// [`AppState::otp_rate_limiter`] (20 hits per 60 s per route and client
/// IP); a rejected request gets
/// `429 {"error":"rate_limited",...}` with `Retry-After`.
#[derive(Debug, Clone, Copy)]
pub struct OtpRateLimit;

impl FromRequestParts<AppState> for OtpRateLimit {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let full_path = parts
            .extensions
            .get::<FullPath>()
            .map(|path| path.as_str().to_owned())
            .unwrap_or_default();
        let key = otp_rate_limit_key(&full_path, &client_ip(&parts.headers, &parts.extensions));
        match state.otp_rate_limiter.allow(&key, Instant::now()) {
            Ok(()) => Ok(Self),
            Err(retry_after) => {
                let mut response = json_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    &json!({
                        "error": "rate_limited",
                        "error_description": "too many requests; try again in a moment",
                    }),
                );
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from(retry_after_seconds(retry_after)),
                );
                Err(response)
            }
        }
    }
}
