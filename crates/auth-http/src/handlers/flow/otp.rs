//! `POST /v1/auth/otp/{start,verify,resend}` (Go
//! `handlers_otp_consent_stateless.go`). Each handler takes
//! [`OtpRateLimit`] first, the port of the gin OTP rate-limit middleware.

use auth_core::{
    domain::OtpChallenge,
    identity::{OtpResendRequest, OtpStartRequest, OtpVerifyRequest, mask_email_json},
};
use axum::{body::Bytes, extract::State, http::StatusCode, response::Response};
use serde_json::{Map, Value, json};

use super::{
    body::{bind, bind_authorize_with},
    redirects::{auth_ui_route, authorization_success_url, oauth_values_from_request},
    respond::{
        OtpRateLimit, error_only, has_consent, invalid_request, issue_code, json_with_masked_email,
        oauth_json, set_sso_cookie,
    },
};
use crate::{json::json_response, middleware::logger::format_rfc3339_nano_utc, state::AppState};

/// `email` (masked), `expires_at` and `otp_challenge_id`, plus `extra`
/// members (keys sorting after `email`).
fn challenge_response(challenge: &OtpChallenge, extra: Map<String, Value>) -> Response {
    let mut rest = extra;
    rest.insert(
        "expires_at".to_owned(),
        Value::from(format_rfc3339_nano_utc(challenge.expires_at)),
    );
    rest.insert(
        "otp_challenge_id".to_owned(),
        Value::from(challenge.id.as_str()),
    );
    json_with_masked_email(&mask_email_json(&challenge.email), &rest)
}

/// Go `startOTPStateless`: bind (`email` required) → validate (`400`) →
/// create and mail the challenge (`400 invalid_request` + error text) →
/// `200 {"email","expires_at","otp_challenge_id","redirect_to"}` where
/// `redirect_to` is auth-ui `/otp` with the body's OAuth params as sent
/// (`response_type` not defaulted), the challenge ID and the normalized,
/// unmasked email.
pub async fn start(_: OtpRateLimit, State(state): State<AppState>, body: Bytes) -> Response {
    let (body, extra) = match bind_authorize_with(&body, &["email"]) {
        Ok(bound) => bound,
        Err(error) => return invalid_request(&error.to_string()),
    };
    let email = &extra[0];
    if let Err(error) = state.validator.validate(&body.to_oauth_request()).await {
        return oauth_json(
            StatusCode::BAD_REQUEST,
            error.code().as_str(),
            error.description(),
        );
    }
    let challenge = match state
        .identity
        .start_otp_challenge(OtpStartRequest {
            email: email.clone(),
            purpose: String::new(),
        })
        .await
    {
        Ok(challenge) => challenge,
        Err(error) => return invalid_request(&error.to_string()),
    };

    let mut query = oauth_values_from_request(body.raw());
    query.set("otp_challenge_id", challenge.id.as_str());
    query.set("email", &challenge.email);
    let mut extra = Map::new();
    extra.insert(
        "redirect_to".to_owned(),
        Value::from(auth_ui_route(
            &state.config.auth_ui_base_url,
            "/otp",
            &query,
        )),
    );
    challenge_response(&challenge, extra)
}

/// Go `verifyOTPStateless`: bind (`otp_challenge_id`, `email`, `code`
/// required) → validate (`400`, before any OTP check) → verify the code
/// (`400 invalid_grant` + error text) → SSO cookie → code for the new
/// session when consent covers the scopes (`redirect_to` the client),
/// otherwise `redirect_to` auth-ui `/consent` with the canonical params.
pub async fn verify(_: OtpRateLimit, State(state): State<AppState>, body: Bytes) -> Response {
    let (body, extra) = match bind_authorize_with(&body, &["otp_challenge_id", "email", "code"]) {
        Ok(bound) => bound,
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
    let [otp_challenge_id, email, code] = <[String; 3]>::try_from(extra).unwrap_or_default();
    let result = match state
        .identity
        .verify_otp_challenge(OtpVerifyRequest {
            otp_challenge_id,
            email,
            code,
        })
        .await
    {
        Ok(result) => result,
        Err(error) => {
            return oauth_json(StatusCode::BAD_REQUEST, "invalid_grant", &error.to_string());
        }
    };
    let (account, session) = (&result.account, &result.session);

    // Go sets the cookie before deciding the next hop, so it is also sent
    // with the error responses below.
    let mut response = if has_consent(&state, session, &validated).await {
        match issue_code(&state, session, &validated).await {
            Ok(code) => {
                let request = validated.request();
                match authorization_success_url(&request.redirect_uri, &code, &request.state) {
                    Some(target) => verified(account, &target),
                    None => error_only(StatusCode::BAD_REQUEST, "invalid_request"),
                }
            }
            Err(error) => oauth_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &error.to_string(),
            ),
        }
    } else {
        verified(
            account,
            &auth_ui_route(
                &state.config.auth_ui_base_url,
                "/consent",
                &oauth_values_from_request(validated.request()),
            ),
        )
    };
    set_sso_cookie(&state, &mut response, session);
    response
}

fn verified(account: &auth_core::domain::Account, redirect_to: &str) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "account": {
                "id": account.id.as_str(),
                "display_name": account.display_name,
                "email": account.primary_verified_email,
            },
            "redirect_to": redirect_to,
        }),
    )
}

/// Go `resendOTPStateless`: bind (`otp_challenge_id` required) → resend
/// (`400 invalid_request` + error text) → `200
/// {"email","expires_at","otp_challenge_id"}`.
pub async fn resend(_: OtpRateLimit, State(state): State<AppState>, body: Bytes) -> Response {
    let otp_challenge_id = match bind(&body, &["otp_challenge_id"], &["otp_challenge_id"]) {
        Ok(mut values) => values.remove(0),
        Err(error) => return invalid_request(&error.to_string()),
    };
    match state
        .identity
        .resend_otp_challenge(OtpResendRequest { otp_challenge_id })
        .await
    {
        Ok(challenge) => challenge_response(&challenge, Map::new()),
        Err(error) => invalid_request(&error.to_string()),
    }
}
