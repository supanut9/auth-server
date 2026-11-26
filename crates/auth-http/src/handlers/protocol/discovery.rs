//! `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json`.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use serde_json::json;

use super::gohttp::error_json;
use crate::{json::json_response, state::AppState};

/// Go `openIDConfiguration`: `issuer` is `JWT_ISSUER` with every trailing
/// `/` trimmed (the JWT `iss` claim is not trimmed).
pub async fn openid_configuration(State(state): State<AppState>) -> Response {
    let issuer = state.config.jwt_issuer.trim_end_matches('/');
    json_response(
        StatusCode::OK,
        &json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/v1/oauth2/authorize"),
            "token_endpoint": format!("{issuer}/v1/oauth2/token"),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "userinfo_endpoint": format!("{issuer}/v1/oidc/userinfo"),
            "revocation_endpoint": format!("{issuer}/v1/oauth2/revoke"),
            "introspection_endpoint": format!("{issuer}/v1/oauth2/introspect"),
            "scopes_supported": ["openid", "email", "profile", "offline_access", "trading.read", "trading.write"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "prompt_values_supported": ["login", "none"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [state.config.jwt_signing_alg],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        }),
    )
}

/// Go `jwks`: the provider's bytes verbatim with `Content-Type:
/// application/json` (gin `c.Data`, no charset).
pub async fn jwks(State(state): State<AppState>) -> Response {
    let Ok(document) = state.jwks.public_jwks() else {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let mut response = Response::new(Body::from(document));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}
