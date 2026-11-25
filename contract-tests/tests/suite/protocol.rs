use auth_contract_tests::{json_response, setting};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::support::*;

#[tokio::test]
async fn health_and_ready_request_ids() {
    let api = Api::new();
    let app_name = setting("CONTRACT_APP_NAME", "auth-server");
    for path in ["/healthz", "/readyz"] {
        for incoming in [
            None,
            Some("contract.request-01_OK"),
            Some("bad id"),
            Some(&"a".repeat(129)),
        ] {
            let mut request = api.get(path);
            if let Some(id) = incoming {
                request = request.header("X-Request-Id", id);
            }
            let response = send(request).await;
            let id = header_value(&response, "x-request-id").to_owned();
            if incoming == Some("contract.request-01_OK") {
                assert_eq!(id, incoming.unwrap());
            } else {
                assert_eq!(
                    Uuid::parse_str(&id)
                        .expect("generated request ID")
                        .get_version_num(),
                    4
                );
            }
            let mut expected = json!({"status": "ok", "app_name": app_name, "request_id": id});
            if path == "/readyz" {
                expected["database"] = json!("ready");
            }
            assert_eq!(json_response(response, StatusCode::OK).await, expected);
        }
    }
}

#[tokio::test]
async fn discovery_and_jwks() {
    let api = Api::new();
    let issuer = api.issuer.trim_end_matches('/');
    let discovery =
        response_json(api.get("/.well-known/openid-configuration"), StatusCode::OK).await;
    assert_eq!(
        discovery,
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}{AUTHORIZE}"),
            "token_endpoint": format!("{issuer}{TOKEN}"),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "userinfo_endpoint": format!("{issuer}{USERINFO}"),
            "revocation_endpoint": format!("{issuer}{REVOKE}"),
            "introspection_endpoint": format!("{issuer}{INTROSPECT}"),
            "scopes_supported": ["openid", "email", "profile", "offline_access", "trading.read", "trading.write"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "prompt_values_supported": ["login", "none"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        })
    );

    let keys = jwks(&api).await;
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_keys(key, &["alg", "e", "kid", "kty", "n", "use"]);
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "RS256");
    let n = URL_SAFE_NO_PAD
        .decode(string(key, "n"))
        .expect("JWK modulus");
    let e = URL_SAFE_NO_PAD
        .decode(string(key, "e"))
        .expect("JWK exponent");
    assert!(!n.is_empty() && n[0] != 0);
    assert!(!e.is_empty() && e[0] != 0);
    assert_eq!(
        key["kid"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(rsa_spki(&n, &e)))
    );
}

pub async fn jwks(api: &Api) -> Vec<Value> {
    let response = response_json(api.get("/.well-known/jwks.json"), StatusCode::OK).await;
    assert_keys(&response, &["keys"]);
    response["keys"]
        .as_array()
        .expect("JWKS keys array")
        .clone()
}

pub fn verify_jwt(api: &Api, keys: &[Value], raw: &str, audience: &str) -> Value {
    let header = decode_header(raw).expect("JWT header");
    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    let kid = header.kid.expect("JWT kid");
    let key = keys
        .iter()
        .find(|key| key["kid"] == kid)
        .expect("JWT kid in JWKS");
    let decoding_key = DecodingKey::from_rsa_components(string(key, "n"), string(key, "e"))
        .expect("RSA public key");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&api.issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = decode::<Value>(raw, &decoding_key, &validation)
        .expect("valid JWT signature and registered claims")
        .claims;
    assert_eq!(claims["iss"], api.issuer);
    assert_eq!(claims["aud"], audience);
    assert_eq!(integer(&claims, "exp") - integer(&claims, "iat"), 600);
    claims
}

fn rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier for rsaEncryption, followed by a BIT STRING holding RSAPublicKey.
    const RSA_ENCRYPTION: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let rsa_key = der(0x30, &[der_integer(n), der_integer(e)].concat());
    let bit_string = der(0x03, &[&[0], rsa_key.as_slice()].concat());
    der(0x30, &[RSA_ENCRYPTION, &bit_string].concat())
}

fn der_integer(unsigned: &[u8]) -> Vec<u8> {
    let mut signed = Vec::new();
    if unsigned[0] & 0x80 != 0 {
        signed.push(0);
    }
    signed.extend_from_slice(unsigned);
    der(0x02, &signed)
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    if body.len() < 128 {
        encoded.push(body.len() as u8);
    } else {
        let bytes = body.len().to_be_bytes();
        let length = &bytes[bytes.iter().position(|&byte| byte != 0).unwrap()..];
        encoded.push(0x80 | length.len() as u8);
        encoded.extend_from_slice(length);
    }
    encoded.extend_from_slice(body);
    encoded
}

#[tokio::test]
async fn authorize_fatal_errors() {
    let api = Api::new();
    let inactive = setting("CONTRACT_INACTIVE_CLIENT_ID", "knowledge-web");
    let malformed_client = setting("CONTRACT_MALFORMED_CLIENT_ID", "language-web");
    let malformed_uri = setting("CONTRACT_MALFORMED_REDIRECT_URI", "/contract-callback");
    let cases: &[(&[(&str, &str)], &str, &str)] = &[
        (
            &[("client_id", ""), ("redirect_uri", "")],
            "invalid_request",
            "client_id is required",
        ),
        (
            &[("client_id", "contract-unknown"), ("redirect_uri", "")],
            "invalid_client",
            "client_id is unknown",
        ),
        (
            &[("client_id", &inactive), ("redirect_uri", "")],
            "invalid_client",
            "client is not active",
        ),
        (
            &[("redirect_uri", "")],
            "invalid_request",
            "redirect_uri is required",
        ),
        (
            &[("redirect_uri", "https://wrong.example.test/callback")],
            "invalid_request",
            "redirect_uri does not match a registered URI",
        ),
        (
            &[
                ("client_id", &malformed_client),
                ("redirect_uri", &malformed_uri),
            ],
            "invalid_request",
            "redirect_uri must be an absolute URL",
        ),
    ];
    for (updates, error, description) in cases {
        let mut flow = Flow::new(&api.browser, FULL_SCOPE);
        flow.params.extend(
            updates
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into())),
        );
        let response = send(api.authorize(&flow.params)).await;
        assert!(
            !response.headers().contains_key("location"),
            "{description}"
        );
        assert_error(response, StatusCode::BAD_REQUEST, error, Some(description)).await;
    }
}

#[tokio::test]
async fn authorize_recoverable_errors() {
    let api = Api::new();
    let bad_encoding = "*".repeat(43);
    let too_long = "A".repeat(129);
    let cases = [
        (
            "response_type",
            "",
            "invalid_request",
            "response_type is required",
        ),
        (
            "response_type",
            "token",
            "unsupported_response_type",
            "response_type must be code",
        ),
        ("state", "", "invalid_request", "state is required"),
        ("scope", "", "invalid_scope", "scope is required"),
        (
            "scope",
            "invalid.scope",
            "invalid_scope",
            "requested scopes are not allowed for this client",
        ),
        (
            "nonce",
            "",
            "invalid_request",
            "nonce is required for openid",
        ),
        (
            "code_challenge",
            "",
            "invalid_request",
            "code_challenge is required for public clients",
        ),
        (
            "code_challenge_method",
            "unknown",
            "invalid_request",
            "unsupported code_challenge_method",
        ),
        (
            "code_challenge_method",
            "plain",
            "invalid_request",
            "public clients must use S256 for code_challenge_method",
        ),
        (
            "code_challenge_method",
            "",
            "invalid_request",
            "public clients must use S256 for code_challenge_method",
        ),
        (
            "code_challenge",
            "short",
            "invalid_request",
            "code_challenge length must be 43–128 characters",
        ),
        (
            "code_challenge",
            &too_long,
            "invalid_request",
            "code_challenge length must be 43–128 characters",
        ),
        (
            "code_challenge",
            &bad_encoding,
            "invalid_request",
            "code_challenge must be base64url-encoded without padding",
        ),
    ];
    for (key, value, error, description) in cases {
        let mut flow = Flow::new(&api.browser, FULL_SCOPE);
        flow.params.insert(key.into(), value.into());
        let response = send(api.authorize(&flow.params)).await;
        flow.assert_error_redirect(location(&response), error, description);
    }
}

#[tokio::test]
async fn authorize_without_session() {
    let api = Api::new();
    let flow = Flow::new(&api.browser, "profile openid email").prompt("none");
    let response = send(api.authorize(&flow.params)).await;
    flow.assert_error_redirect(
        location(&response),
        "login_required",
        "no active SSO session",
    );

    let flow = Flow::new(&api.browser, "profile openid email").prompt("login");
    let mut query = flow.params.clone();
    query.insert("extra".into(), "ignored".into());
    let response = send(api.authorize(&query)).await;
    assert_eq!(location(&response), api.ui_route("/login", &flow.params));
    assert!(!response.headers().contains_key("set-cookie"));

    let flow = Flow::new(&api.browser, FULL_SCOPE);
    let response = send(api.authorize(&flow.params)).await;
    assert_eq!(location(&response), api.ui_route("/login", &flow.params));
}

#[tokio::test]
async fn client_credentials_scope_and_auth_methods() {
    let api = Api::new();
    let keys = jwks(&api).await;
    for (auth, scope) in [
        (ClientAuth::Basic, "trading.write trading.read trading.read"),
        (ClientAuth::Post, "trading.read trading.write"),
        (ClientAuth::Post, ""),
    ] {
        let result = response_json(
            api.form(
                TOKEN,
                &api.worker,
                auth,
                &[("grant_type", "client_credentials"), ("scope", scope)],
            ),
            StatusCode::OK,
        )
        .await;
        assert_keys(
            &result,
            &["access_token", "token_type", "expires_in", "scope"],
        );
        let scope = if scope.is_empty() {
            ""
        } else {
            "trading.read trading.write"
        };
        assert_eq!(result["scope"], scope);
        assert_eq!(result["token_type"], "Bearer");
        assert_eq!(result["expires_in"], 600);
        let token = string(&result, "access_token");
        let claims = verify_jwt(&api, &keys, token, &api.audience);
        assert_keys(
            &claims,
            &[
                "iss",
                "sub",
                "aud",
                "exp",
                "iat",
                "scope",
                "client_id",
                "jti",
            ],
        );
        assert_eq!(claims["sub"], api.worker.id);
        assert_eq!(claims["client_id"], api.worker.id);
        assert_eq!(claims["scope"], scope);
        assert_uuid_v7(string(&claims, "jti"));
        assert_error(
            send(api.get(USERINFO).bearer_auth(token)).await,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            None,
        )
        .await;
    }

    for scope in [
        "openid",
        "email",
        "profile",
        "trading.read profile",
        "unknown.scope",
    ] {
        let response = send(api.form(
            TOKEN,
            &api.worker,
            ClientAuth::Basic,
            &[("grant_type", "client_credentials"), ("scope", scope)],
        ))
        .await;
        assert_error(response, StatusCode::BAD_REQUEST, "invalid_scope", None).await;
    }
    let response = send(api.form(
        TOKEN,
        &api.browser,
        ClientAuth::Post,
        &[
            ("grant_type", "client_credentials"),
            ("scope", "trading.read"),
        ],
    ))
    .await;
    assert_error(
        response,
        StatusCode::UNAUTHORIZED,
        "unauthorized_client",
        None,
    )
    .await;
    let response = send(
        api.post(TOKEN)
            .basic_auth(&api.worker.id, Some("wrong-contract-secret"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", "trading.read"),
            ]),
    )
    .await;
    assert_error(response, StatusCode::UNAUTHORIZED, "invalid_client", None).await;
}

#[tokio::test]
async fn router_status_and_redirect_quirks() {
    let api = Api::new();
    let response = send(api.get("/contract-unknown-path")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(header_value(&response, "content-type"), "text/plain");
    assert_eq!(response.text().await.unwrap(), "404 page not found");

    let client = auth_contract_tests::http_client();
    for path in ["/contract-unknown-path", TOKEN] {
        let response = send(
            client
                .request(Method::OPTIONS, format!("{}{path}", api.base))
                .header("Origin", &api.ui),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(header_value(&response, "vary"), "Origin");
        assert_eq!(
            header_value(&response, "access-control-allow-origin"),
            api.ui
        );
        assert_eq!(
            header_value(&response, "access-control-allow-credentials"),
            "true"
        );
        assert_eq!(
            header_value(&response, "access-control-allow-headers"),
            "Authorization, Content-Type"
        );
        assert_eq!(
            header_value(&response, "access-control-allow-methods"),
            "GET, POST, OPTIONS"
        );
        assert!(response.bytes().await.unwrap().is_empty());
    }
    let response = send(api.post("/healthz")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.text().await.unwrap(), "404 page not found");

    let response = send(api.get("/healthz/")).await;
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(header_value(&response, "location"), "/healthz");
    let response = send(api.post("/v1/oauth2/token/")).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(header_value(&response, "location"), TOKEN);
}
