//! `GET /v1/oidc/userinfo` (Go `userInfo`).

use auth_core::domain::AccountId;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};

use super::gohttp::{error_json, split_protocol_list, string_claim};
use crate::{json::json_response, state::AppState};

/// `TrimSpace(TrimPrefix(Authorization, "Bearer"))` of the first
/// `Authorization` value (case-sensitive prefix).
fn bearer_token(headers: &HeaderMap) -> String {
    let raw = headers
        .get(header::AUTHORIZATION)
        .map_or(&b""[..], |value| value.as_bytes());
    let raw = raw.strip_prefix(b"Bearer").unwrap_or(raw);
    String::from_utf8_lossy(raw).trim().to_owned()
}

fn invalid_token(challenge: &'static str) -> Response {
    let mut response = error_json(StatusCode::UNAUTHORIZED, "invalid_token");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(challenge),
    );
    response
}

/// Requires a platform access token for a known account. `email` and
/// `email_verified` need the `email` scope. `name` and `picture` need
/// `profile`.
pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = bearer_token(&headers);
    if token.is_empty() {
        return invalid_token("Bearer");
    }
    let invalid = || invalid_token(r#"Bearer error="invalid_token""#);
    let Ok(claims) = state.jwt_verifier.verify(&token) else {
        return invalid();
    };
    if !state.token.is_access_token(&claims) {
        return invalid();
    }
    let subject = string_claim(&claims, "sub");
    if subject.is_empty() || subject == string_claim(&claims, "client_id") {
        return invalid();
    }
    let Ok(account) = state.accounts.find_by_id(&AccountId::new(subject)).await else {
        return invalid();
    };

    let scopes = split_protocol_list(&string_claim(&claims, "scope"));
    let has = |scope: &str| scopes.iter().any(|granted| granted == scope);
    let mut response = json!({ "sub": account.id.as_str() });
    if has("email") {
        response["email"] = Value::from(account.primary_verified_email);
        response["email_verified"] = Value::Bool(true);
    }
    if has("profile") {
        response["name"] = Value::from(account.display_name);
        response["picture"] = Value::from(account.avatar_url);
    }
    json_response(StatusCode::OK, &response)
}
