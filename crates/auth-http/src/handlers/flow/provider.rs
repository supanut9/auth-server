//! Provider login (Go `handlers_provider_stateless.go`):
//! `POST /v1/auth/login/{google,github}` and
//! `GET /v1/auth/login/callback/{google,github}`.

use auth_adapters::provider::provider_authorization_url;
use auth_core::{
    domain::SsoSession,
    identity::{IdentityError, ProviderLoginRequest},
    oauth::{AuthorizeRequest, ValidatedAuthorizeRequest, envelope::Envelope},
};
use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::StatusCode,
    response::Response,
};
use serde_json::json;

use super::{
    body::bind_authorize_with,
    redirects::{QueryValues, auth_ui_error_route, auth_ui_route, oauth_values_from_request},
    respond::{
        error_only, found, has_consent, invalid_request, issue_code, oauth_json,
        redirect_authorization_success, redirect_oauth_error, set_sso_cookie,
    },
};
use crate::{json::json_response, state::AppState};

pub const GOOGLE: &str = "google";
pub const GITHUB: &str = "github";

/// Go `providerClientID`.
fn provider_client_id<'a>(state: &'a AppState, provider: &str) -> &'a str {
    match provider {
        GOOGLE => &state.config.google_client_id,
        GITHUB => &state.config.github_client_id,
        _ => "",
    }
}

/// Go `providerRedirectURI`.
fn provider_redirect_uri<'a>(state: &'a AppState, provider: &str) -> &'a str {
    match provider {
        GOOGLE => &state.config.google_redirect_url,
        GITHUB => &state.config.github_redirect_url,
        _ => "",
    }
}

pub async fn start_google(State(state): State<AppState>, body: Bytes) -> Response {
    start(&state, GOOGLE, &body).await
}

pub async fn start_github(State(state): State<AppState>, body: Bytes) -> Response {
    start(&state, GITHUB, &body).await
}

/// Go `startProviderLoginStateless`: bind → validate (any error is a 400
/// JSON) → provider configured (else 503) → sign the canonical request
/// into the envelope used as the provider `state` → `200
/// {"authorization_url"}`.
async fn start(state: &AppState, provider: &str, body: &[u8]) -> Response {
    let body = match bind_authorize_with(body, &[]) {
        Ok((body, _)) => body,
        Err(error) => return invalid_request(&error.to_string()),
    };
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
    if !state.providers.contains_key(provider) {
        return error_only(StatusCode::SERVICE_UNAVAILABLE, "provider_unavailable");
    }
    let request = validated.request();
    let envelope = Envelope {
        provider: provider.to_owned(),
        client_id: validated.client().client_id.as_str().to_owned(),
        redirect_uri: request.redirect_uri.clone(),
        scope: request.scope.clone(),
        state: request.state.clone(),
        nonce: request.nonce.clone(),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: request.code_challenge_method.clone(),
        prompt: request.prompt.clone(),
    };
    let Ok(token) = state.envelope.sign(&envelope) else {
        return error_only(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let url = provider_authorization_url(
        provider,
        provider_client_id(state, provider),
        provider_redirect_uri(state, provider),
        &token,
    );
    json_response(StatusCode::OK, &json!({"authorization_url": url}))
}

pub async fn callback_google(State(state): State<AppState>, query: RawQuery) -> Response {
    callback(&state, GOOGLE, query).await
}

pub async fn callback_github(State(state): State<AppState>, query: RawQuery) -> Response {
    callback(&state, GITHUB, query).await
}

/// Go `handleProviderCallbackStateless`, in Go's order: `state` and `code`
/// present → envelope verifies (burning its JTI) → envelope provider
/// matches the route → provider configured → envelope params re-validated
/// (any error redirects to the envelope's `redirect_uri`) → code exchange →
/// account resolution and a new SSO session → SSO cookie → post-auth
/// redirect for that fresh session.
async fn callback(state: &AppState, provider_name: &str, RawQuery(raw): RawQuery) -> Response {
    let query = QueryValues::parse(raw.as_deref().unwrap_or_default());
    let (state_token, code) = (query.get("state"), query.get("code"));
    if state_token.is_empty() || code.is_empty() {
        return error_only(StatusCode::BAD_REQUEST, "invalid_request");
    }

    let envelope = match state.envelope.verify(state_token).await {
        Ok(envelope) => envelope,
        Err(error) => {
            return oauth_json(StatusCode::BAD_REQUEST, "invalid_state", &error.to_string());
        }
    };
    if envelope.provider != provider_name {
        return oauth_json(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "state provider mismatch",
        );
    }
    let Some(provider) = state.providers.get(provider_name) else {
        return error_only(StatusCode::SERVICE_UNAVAILABLE, "provider_unavailable");
    };

    let request = AuthorizeRequest {
        response_type: "code".to_owned(),
        client_id: envelope.client_id.clone(),
        redirect_uri: envelope.redirect_uri.clone(),
        scope: envelope.scope.clone(),
        state: envelope.state.clone(),
        nonce: envelope.nonce.clone(),
        code_challenge: envelope.code_challenge.clone(),
        code_challenge_method: envelope.code_challenge_method.clone(),
        prompt: envelope.prompt.clone(),
    };
    let validated = match state.validator.validate(&request).await {
        Ok(validated) => validated,
        Err(error) => {
            return redirect_oauth_error(
                &envelope.redirect_uri,
                &envelope.state,
                error.code().as_str(),
                error.description(),
            );
        }
    };

    let profile = match provider
        .exchange_authorization_code(code, provider_redirect_uri(state, provider_name))
        .await
    {
        Ok(profile) => profile,
        Err(error) => {
            return oauth_json(
                StatusCode::BAD_GATEWAY,
                "provider_error",
                &error.to_string(),
            );
        }
    };

    let result = state
        .identity
        .handle_provider_login(ProviderLoginRequest {
            provider_name: provider_name.to_owned(),
            provider_account_id: profile.account_id,
            email: profile.email,
            email_verified: profile.email_verified,
            display_name: profile.display_name,
            avatar_url: profile.avatar_url,
        })
        .await;
    let result = match result {
        Ok(result) => result,
        Err(IdentityError::ProviderEmailVerificationRequired) => {
            // The user retries with email OTP from the auth-ui error screen.
            return found(&auth_ui_error_route(
                &state.config.auth_ui_base_url,
                validated.request(),
                "provider_email_unverified",
                "provider did not return a verified email; try email OTP",
            ));
        }
        Err(error) => {
            return oauth_json(StatusCode::BAD_REQUEST, "invalid_grant", &error.to_string());
        }
    };

    let mut response = redirect_post_authentication(state, &validated, &result.session).await;
    set_sso_cookie(state, &mut response, &result.session);
    response
}

/// Go `redirectPostAuthenticationStateless`: straight back to the client
/// with a code when `session`'s account already consented, otherwise to
/// auth-ui `/consent` with the canonical OAuth params.
///
/// `session` is the one the login just created, never the incoming SSO
/// cookie's (AUTH-017): a browser signed in as A that logs in as B must get
/// a code for B.
async fn redirect_post_authentication(
    state: &AppState,
    validated: &ValidatedAuthorizeRequest,
    session: &SsoSession,
) -> Response {
    let request = validated.request();
    if !session.account_id.is_empty() && has_consent(state, session, validated).await {
        return match issue_code(state, session, validated).await {
            Ok(code) => {
                redirect_authorization_success(&request.redirect_uri, &code, &request.state)
            }
            Err(error) => redirect_oauth_error(
                &request.redirect_uri,
                &request.state,
                "server_error",
                &error.to_string(),
            ),
        };
    }
    found(&auth_ui_route(
        &state.config.auth_ui_base_url,
        "/consent",
        &oauth_values_from_request(request),
    ))
}
