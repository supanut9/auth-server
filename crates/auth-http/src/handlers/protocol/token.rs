//! `POST /v1/oauth2/token`, `/revoke` and `/introspect` (Go `token`,
//! `revoke`, `introspect` and helpers in `router.go`).

use auth_core::{
    crypto::{hash_opaque, match_client_secret},
    domain::{ClientId, ClientType, OAuthClient, RefreshTokenChainStatus, Scopes, SessionId},
    flow::{ConsumeAuthorizationCodeRequest, FlowError},
    ports::JwtClaims,
    token::{
        ClientCredentialsTokenRequest, RefreshTokenRequest, UserTokenRequest,
        client_credentials_scope_permitted,
    },
};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use secrecy::ExposeSecret;
use serde_json::{Value, json};

use super::gohttp::{
    Values, basic_auth, empty_ok, error_json, post_form, split_protocol_list, string_claim,
};
use crate::{json::json_response, state::AppState};

/// The form body plus the client credentials: HTTP Basic first, each part
/// independently falling back to the `client_id` / `client_secret` form
/// fields when empty.
struct TokenRequest {
    form: Values,
    client_id: String,
    client_secret: String,
}

async fn read_token_request(request: Request) -> TokenRequest {
    let (parts, body) = request.into_parts();
    let form = post_form(&parts.headers, body).await;
    let (mut client_id, mut client_secret) = basic_credentials(&parts.headers);
    if client_id.is_empty() {
        client_id = form.get("client_id").to_owned();
    }
    if client_secret.is_empty() {
        client_secret = form.get("client_secret").to_owned();
    }
    TokenRequest {
        form,
        client_id,
        client_secret,
    }
}

fn basic_credentials(headers: &HeaderMap) -> (String, String) {
    basic_auth(headers).unwrap_or_default()
}

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// A failed client authentication; both render as `401`.
#[derive(Debug, Clone, Copy)]
enum ClientAuthError {
    InvalidClient,
    UnauthorizedClient,
}

impl ClientAuthError {
    fn into_response(self) -> Response {
        let code = match self {
            Self::InvalidClient => "invalid_client",
            Self::UnauthorizedClient => "unauthorized_client",
        };
        error_json(StatusCode::UNAUTHORIZED, code)
    }
}

/// Go `authenticateClient`: unknown client → `invalid_client`; a public
/// client where a confidential one is required → `unauthorized_client`; a
/// confidential client whose secret does not match → `invalid_client`.
/// Public clients are not secret-checked. The client status is not checked
/// (as in Go).
async fn authenticate_client(
    state: &AppState,
    client_id: &str,
    client_secret: &str,
    confidential_only: bool,
) -> Result<OAuthClient, ClientAuthError> {
    let Ok(client) = state
        .clients
        .find_by_client_id(&ClientId::new(client_id))
        .await
    else {
        return Err(ClientAuthError::InvalidClient);
    };
    let confidential = client.client_type == ClientType::Confidential;
    if confidential_only && !confidential {
        return Err(ClientAuthError::UnauthorizedClient);
    }
    if confidential
        && !match_client_secret(client.client_secret_hash.expose_secret(), client_secret)
    {
        return Err(ClientAuthError::InvalidClient);
    }
    Ok(client)
}

/// Go `token`: dispatch on `grant_type` before any client authentication.
pub async fn token(State(state): State<AppState>, request: Request) -> Response {
    let request = read_token_request(request).await;
    let response = match request.form.get("grant_type") {
        "authorization_code" => authorization_code_grant(&state, &request).await,
        "refresh_token" => refresh_token_grant(&state, &request).await,
        "client_credentials" => client_credentials_grant(&state, &request).await,
        _ => error_json(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    };
    no_store(response)
}

/// Exchange a valid authorization code for user tokens.
async fn authorization_code_grant(state: &AppState, request: &TokenRequest) -> Response {
    let client =
        match authenticate_client(state, &request.client_id, &request.client_secret, false).await {
            Ok(client) => client,
            Err(error) => return error.into_response(),
        };

    let code = match state
        .flow
        .consume_authorization_code(ConsumeAuthorizationCodeRequest {
            code: request.form.get("code").to_owned(),
            client_id: client.client_id.clone(),
            redirect_uri: request.form.get("redirect_uri").to_owned(),
            code_verifier: request.form.get("code_verifier").to_owned(),
        })
        .await
    {
        Ok(code) => code,
        Err(error @ FlowError::PkceValidationFailed) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "invalid_grant", "error_description": error.to_string()}),
            );
        }
        Err(_) => return error_json(StatusCode::BAD_REQUEST, "invalid_grant"),
    };

    let Ok(account) = state.accounts.find_by_id(&code.account_id).await else {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };

    let issued = state
        .token
        .issue_user_tokens(UserTokenRequest {
            account_id: account.id.clone(),
            client_id: client.client_id.clone(),
            scope: split_protocol_list(&code.granted_scopes),
            sso_session_id: code
                .sso_session_id
                .clone()
                .unwrap_or_else(SessionId::default),
            device_session_id: code.id.to_string(),
            auth_time: code.auth_time,
            nonce: code.nonce.clone(),
            email: account.primary_verified_email,
            email_verified: true,
            name: account.display_name,
            picture: account.avatar_url,
        })
        .await;
    let Ok(tokens) = issued else {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };

    json_response(
        StatusCode::OK,
        &json!({
            "access_token": tokens.access_token,
            "id_token": tokens.id_token.unwrap_or_default(),
            "refresh_token": tokens.refresh_token.unwrap_or_default(),
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "scope": tokens.scope,
        }),
    )
}

/// Go `handleRefreshToken`: any service error is `400 invalid_grant`.
async fn refresh_token_grant(state: &AppState, request: &TokenRequest) -> Response {
    let client =
        match authenticate_client(state, &request.client_id, &request.client_secret, false).await {
            Ok(client) => client,
            Err(error) => return error.into_response(),
        };
    let Ok(tokens) = state
        .token
        .refresh_user_tokens(RefreshTokenRequest {
            client_id: client.client_id,
            refresh_token: request.form.get("refresh_token").to_owned(),
        })
        .await
    else {
        return error_json(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    json_response(
        StatusCode::OK,
        &json!({
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token.unwrap_or_default(),
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "scope": tokens.scope,
        }),
    )
}

/// Go `handleClientCredentials`: confidential clients only; no
/// `openid`/`email`/`profile`, and a subset of the client's allowed scopes.
async fn client_credentials_grant(state: &AppState, request: &TokenRequest) -> Response {
    let client =
        match authenticate_client(state, &request.client_id, &request.client_secret, true).await {
            Ok(client) => client,
            Err(error) => return error.into_response(),
        };
    let raw_scope = request.form.get("scope");
    if !client_credentials_scope_permitted(
        &Scopes::parse(raw_scope),
        &Scopes::parse(&client.allowed_scopes),
    ) {
        return error_json(StatusCode::BAD_REQUEST, "invalid_scope");
    }
    let Ok(tokens) = state
        .token
        .issue_client_credentials_token(ClientCredentialsTokenRequest {
            client_id: client.client_id,
            scope: split_protocol_list(raw_scope),
        })
        .await
    else {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    json_response(
        StatusCode::OK,
        &json!({
            "access_token": tokens.access_token,
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "scope": tokens.scope,
        }),
    )
}

/// Go `revoke`: always `200` with an empty body once the client is
/// authenticated. The refresh token's chain (tokens, then the chain) is
/// revoked only when it belongs to the authenticated client; every lookup
/// or revoke error is ignored.
pub async fn revoke(State(state): State<AppState>, request: Request) -> Response {
    let request = read_token_request(request).await;
    let client = match authenticate_client(
        &state,
        &request.client_id,
        &request.client_secret,
        false,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => return error.into_response(),
    };
    let Some(token_hash) = hash_opaque(request.form.get("token")) else {
        return empty_ok();
    };
    if let Ok(refresh_token) = state.refresh_tokens.find_by_token_hash(&token_hash).await
        && let Ok(chain) = state
            .refresh_token_chains
            .find_by_id(&refresh_token.refresh_token_chain_id)
            .await
        && chain.client_id == client.client_id
    {
        let _ = state.refresh_tokens.revoke_by_chain_id(&chain.id).await;
        let _ = state.refresh_token_chains.revoke_by_id(&chain.id).await;
    }
    empty_ok()
}

/// Go `introspect`: confidential clients only. `token_type_hint=
/// refresh_token` selects the refresh-token lookup; any other hint (or
/// none) only tries the JWT path.
pub async fn introspect(State(state): State<AppState>, request: Request) -> Response {
    let request = read_token_request(request).await;
    if let Err(error) =
        authenticate_client(&state, &request.client_id, &request.client_secret, true).await
    {
        return no_store(error.into_response());
    }
    let token = request.form.get("token");
    let body = if request.form.get("token_type_hint") == "refresh_token" {
        introspect_refresh_token(&state, token).await
    } else {
        introspect_access_token(&state, token)
    };
    no_store(json_response(StatusCode::OK, &body))
}

fn inactive() -> Value {
    json!({"active": false})
}

/// Go `introspectAccessToken`. Any verifiable JWT (including an ID token)
/// is reported active until `exp`.
fn introspect_access_token(state: &AppState, token: &str) -> Value {
    let Ok(claims) = state.jwt_verifier.verify(token) else {
        return inactive();
    };
    let exp = number_claim(&claims, "exp").unwrap_or(0.0);
    // Go `int64(float64)`: `as` truncates toward zero like Go for every
    // realistic timestamp.
    let exp_seconds = exp as i64;
    if exp > 0.0 && state.clock.now().unix_timestamp() >= exp_seconds {
        return inactive();
    }
    let mut response = json!({
        "active": true,
        "scope": string_claim(&claims, "scope"),
        "client_id": string_claim(&claims, "client_id"),
        "sub": string_claim(&claims, "sub"),
        "token_type": "Bearer",
    });
    if exp > 0.0 {
        response["exp"] = Value::from(exp_seconds);
    }
    if let Some(iat) = number_claim(&claims, "iat") {
        response["iat"] = Value::from(iat as i64);
    }
    if let Some(aud) = claims.get("aud") {
        response["aud"] = aud.clone();
    }
    response
}

/// Go `claims[key].(float64)`: present only for a JSON number.
fn number_claim(claims: &JwtClaims, key: &str) -> Option<f64> {
    claims.get(key).and_then(Value::as_f64)
}

/// Go `introspectRefreshToken`.
async fn introspect_refresh_token(state: &AppState, token: &str) -> Value {
    let Some(token_hash) = hash_opaque(token) else {
        return inactive();
    };
    let now = state.clock.now();
    let record = match state.refresh_tokens.find_by_token_hash(&token_hash).await {
        Ok(record)
            if record.revoked_at.is_none()
                && record.used_at.is_none()
                && now <= record.expires_at =>
        {
            record
        }
        _ => return inactive(),
    };
    let chain = match state
        .refresh_token_chains
        .find_by_id(&record.refresh_token_chain_id)
        .await
    {
        Ok(chain)
            if chain.revoked_at.is_none() && chain.status == RefreshTokenChainStatus::Active =>
        {
            chain
        }
        _ => return inactive(),
    };
    json!({
        "active": true,
        "scope": chain.scope,
        "client_id": chain.client_id.as_str(),
        "sub": chain.account_id.as_str(),
        "exp": chain.absolute_expires_at.unix_timestamp(),
        "iat": record.issued_at.unix_timestamp(),
        "token_type": "refresh_token",
    })
}
