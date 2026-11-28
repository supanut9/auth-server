//! `POST /v1/oauth2/token`, `/revoke`, `/introspect` and `GET
//! /v1/oidc/userinfo`, signing with the real `JwksManager` and the
//! test-only key.

mod protocol_support;

use auth_core::{
    domain::{AccountId, ClientId, ClientType, OAuthClient, RefreshTokenChainStatus, SessionId},
    oauth::pkce::s256_challenge,
    ports::JwtVerifier,
    token::UserTokenRequest,
};
use axum::http::StatusCode;
use protocol_support::*;
use secrecy::SecretString;
use serde_json::{Value, json};
use time::Duration;

const TOKEN: &str = "/v1/oauth2/token";
const REVOKE: &str = "/v1/oauth2/revoke";
const INTROSPECT: &str = "/v1/oauth2/introspect";
const USERINFO: &str = "/v1/oidc/userinfo";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wRgWgUBTYoz5abcd";
const INVALID_GRANT: &str = r#"{"error":"invalid_grant"}"#;
const INVALID_CLIENT: &str = r#"{"error":"invalid_client"}"#;
const UNAUTHORIZED_CLIENT: &str = r#"{"error":"unauthorized_client"}"#;
const INVALID_TOKEN: &str = r#"{"error":"invalid_token"}"#;
const INACTIVE: &str = r#"{"active":false}"#;

fn redirect_uri(client: &str) -> String {
    format!("https://{client}.example/callback")
}

async fn exchange(router: &axum::Router, code: &str, verifier: &str) -> Reply {
    let uri = redirect_uri(BROWSER);
    post_form(
        router,
        TOKEN,
        &[],
        &[
            ("grant_type", "authorization_code"),
            ("client_id", BROWSER),
            ("code", code),
            ("redirect_uri", &uri),
            ("code_verifier", verifier),
        ],
    )
    .await
}

fn worker_auth() -> String {
    basic(WORKER, WORKER_SECRET)
}

fn assert_no_store(reply: &Reply) {
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
}

fn keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

async fn introspect(router: &axum::Router, token: &str, hint: &str) -> Reply {
    let auth = worker_auth();
    post_form(
        router,
        INTROSPECT,
        &[("authorization", &auth)],
        &[("token", token), ("token_type_hint", hint)],
    )
    .await
}

#[tokio::test]
async fn authorization_code_end_to_end_with_real_keys() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let code = fixture
        .issue_code(
            &account,
            &session,
            BROWSER,
            &["profile", "openid", "email"],
            &s256_challenge(VERIFIER),
            "S256",
        )
        .await;

    let reply = exchange(&router, &code, VERIFIER).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(
        reply.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    let tokens = reply.json();
    assert_eq!(
        keys(&tokens),
        [
            "access_token",
            "expires_in",
            "id_token",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 600);
    assert_eq!(tokens["scope"], "email openid profile");

    let access = fixture
        .jwks
        .verify(tokens["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(access["iss"], ISSUER);
    assert_eq!(access["aud"], AUDIENCE);
    assert_eq!(access["sub"], account.as_str());
    assert_eq!(access["client_id"], BROWSER);
    assert_eq!(access["sid"], session.as_str());
    assert_eq!(access["scope"], "email openid profile");
    let id = fixture
        .jwks
        .verify(tokens["id_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(id["aud"], BROWSER);
    assert_eq!(id["sub"], account.as_str());
    assert_eq!(id["email"], "ada@example.com");
    assert_eq!(id["email_verified"], true);
    assert_eq!(id["name"], "ada");
    assert_eq!(id["picture"], "https://cdn.example/ada@example.com.png");
    assert_eq!(
        id["auth_time"],
        (NOW - Duration::minutes(5)).unix_timestamp()
    );
    assert!(id.get("nonce").is_none(), "no nonce on the code, no claim");
    let chain = fixture.chains.all().pop().unwrap();
    assert_eq!(chain.sso_session_id, session);
    assert_eq!(chain.client_id, BROWSER);

    // The code is single use.
    exchange(&router, &code, VERIFIER)
        .await
        .assert_json(StatusCode::BAD_REQUEST, INVALID_GRANT);

    // userinfo with the access token.
    let auth = bearer(tokens["access_token"].as_str().unwrap());
    get(&router, USERINFO, &[("authorization", &auth)]).await.assert_json(
        StatusCode::OK,
        &format!(
            r#"{{"email":"ada@example.com","email_verified":true,"name":"ada","picture":"https://cdn.example/ada@example.com.png","sub":"{account}"}}"#
        ),
    );

    // Introspection of both tokens (JWT path and refresh path).
    let reply = introspect(&router, tokens["access_token"].as_str().unwrap(), "").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "active": true, "aud": AUDIENCE, "client_id": BROWSER, "exp": access["exp"],
            "iat": access["iat"], "scope": "email openid profile", "sub": account.as_str(),
            "token_type": "Bearer",
        })
    );
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let reply = introspect(&router, refresh, "refresh_token").await;
    reply.assert_json(
        StatusCode::OK,
        &format!(
            r#"{{"active":true,"client_id":"browser-web","exp":{},"iat":{},"scope":"email openid profile","sub":"{account}","token_type":"refresh_token"}}"#,
            chain.absolute_expires_at.unix_timestamp(),
            NOW.unix_timestamp()
        ),
    );
    // A refresh token on the JWT path is not a JWT.
    introspect(&router, refresh, "access_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);

    // Refresh grant: rotation, then reuse outside the grace window.
    let reply = post_form(
        &router,
        TOKEN,
        &[],
        &[
            ("grant_type", "refresh_token"),
            ("client_id", BROWSER),
            ("refresh_token", refresh),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let rotated = reply.json();
    assert_eq!(
        keys(&rotated),
        [
            "access_token",
            "expires_in",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );
    assert_ne!(rotated["refresh_token"], refresh);
    assert_eq!(rotated["scope"], "email openid profile");
    introspect(&router, refresh, "refresh_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
    fixture.clock.advance(Duration::minutes(2));
    post_form(
        &router,
        TOKEN,
        &[],
        &[
            ("grant_type", "refresh_token"),
            ("client_id", BROWSER),
            ("refresh_token", refresh),
        ],
    )
    .await
    .assert_json(StatusCode::BAD_REQUEST, INVALID_GRANT);
}

/// AUTH-041 (OIDC Core 3.1.3.6): the token endpoint passes the consumed
/// code's nonce on; it lands in the ID token only, never the access token.
#[tokio::test]
async fn authorization_code_echoes_the_request_nonce_in_the_id_token() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let code = fixture
        .issue_code_with_nonce(
            &account,
            &session,
            BROWSER,
            &["openid"],
            &s256_challenge(VERIFIER),
            "S256",
            "n-0S6_WzA2Mj",
        )
        .await;

    let reply = exchange(&router, &code, VERIFIER).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let tokens = reply.json();
    let id = fixture
        .jwks
        .verify(tokens["id_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(id["nonce"], "n-0S6_WzA2Mj");
    let access = fixture
        .jwks
        .verify(tokens["access_token"].as_str().unwrap())
        .unwrap();
    assert!(
        access.get("nonce").is_none(),
        "nonce must stay out of the access token"
    );
}

#[tokio::test]
async fn pkce_failure_leaves_the_authorization_code_usable() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let code = fixture
        .issue_code(
            &account,
            &session,
            BROWSER,
            &["openid"],
            &s256_challenge(VERIFIER),
            "S256",
        )
        .await;
    exchange(&router, &code, "wrong-verifier")
        .await
        .assert_json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant","error_description":"pkce validation failed"}"#,
        );
    assert_eq!(
        exchange(&router, &code, VERIFIER).await.status,
        StatusCode::OK
    );
    exchange(&router, &code, VERIFIER)
        .await
        .assert_json(StatusCode::BAD_REQUEST, INVALID_GRANT);

    // plain method, and a code without a challenge that receives a verifier.
    let code = fixture
        .issue_code(&account, &session, BROWSER, &["openid"], VERIFIER, "plain")
        .await;
    assert_eq!(
        exchange(&router, &code, VERIFIER).await.status,
        StatusCode::OK
    );
    let code = fixture
        .issue_code(&account, &session, BROWSER, &["openid"], "", "")
        .await;
    exchange(&router, &code, VERIFIER).await.assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_grant","error_description":"pkce validation failed"}"#,
    );
}

#[tokio::test]
async fn authorization_code_failures() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let code = fixture
        .issue_code(&account, &session, BROWSER, &["openid"], "", "")
        .await;

    // Unknown code, empty code, wrong redirect URI, wrong client.
    for (code, redirect) in [
        ("unknown", redirect_uri(BROWSER)),
        ("", redirect_uri(BROWSER)),
        (code.as_str(), "https://other.example/callback".to_owned()),
    ] {
        post_form(
            &router,
            TOKEN,
            &[],
            &[
                ("grant_type", "authorization_code"),
                ("client_id", BROWSER),
                ("code", code),
                ("redirect_uri", &redirect),
            ],
        )
        .await
        .assert_json(StatusCode::BAD_REQUEST, INVALID_GRANT);
    }
    let auth = worker_auth();
    let browser_redirect = redirect_uri(BROWSER);
    post_form(
        &router,
        TOKEN,
        &[("authorization", &auth)],
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &browser_redirect),
        ],
    )
    .await
    .assert_json(StatusCode::BAD_REQUEST, INVALID_GRANT);

    // Unknown client: 401 before the code is touched.
    post_form(
        &router,
        TOKEN,
        &[],
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "nope"),
            ("code", &code),
        ],
    )
    .await
    .assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);

    // A code whose account vanished: 500 after consume.
    let ghost = AccountId::new("ghost-account");
    let code = fixture
        .issue_code(&ghost, &session, BROWSER, &["openid"], "", "")
        .await;
    exchange(&router, &code, "").await.assert_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":"server_error"}"#,
    );
}

#[tokio::test]
async fn grant_type_dispatch_and_form_parsing() {
    let router = Fixture::new().router();
    let unsupported = r#"{"error":"unsupported_grant_type"}"#;
    for grant in ["", "password", "AUTHORIZATION_CODE"] {
        let reply = post_form(
            &router,
            TOKEN,
            &[],
            &[("grant_type", grant), ("client_id", "nope")],
        )
        .await;
        assert_no_store(&reply);
        reply.assert_json(StatusCode::BAD_REQUEST, unsupported);
    }
    // Only an urlencoded body counts: JSON, multipart and query strings do
    // not.
    post(
        &router,
        TOKEN,
        &[("content-type", "application/json")],
        r#"{"grant_type":"client_credentials"}"#,
    )
    .await
    .assert_json(StatusCode::BAD_REQUEST, unsupported);
    post(
        &router,
        "/v1/oauth2/token?grant_type=client_credentials",
        &[("content-type", "application/x-www-form-urlencoded")],
        "",
    )
    .await
    .assert_json(StatusCode::BAD_REQUEST, unsupported);
    // Media type parameters and case are ignored; the first value wins.
    let auth = worker_auth();
    let reply = post(
        &router,
        TOKEN,
        &[
            (
                "content-type",
                "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
            ),
            ("authorization", &auth),
        ],
        "grant_type=client_credentials&grant_type=password&scope=trading.read",
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_no_store(&reply);
}

#[tokio::test]
async fn client_authentication_rules() {
    let fixture = Fixture::new();
    fixture.clients.rows.lock().unwrap().push(OAuthClient {
        client_id: ClientId::new("pct%3Aid"),
        client_type: ClientType::Confidential,
        client_secret_hash: SecretString::from("s%40cret".to_owned()),
        allowed_scopes: "trading.read".to_owned(),
        ..OAuthClient::default()
    });
    let router = fixture.router();
    let cc = |auth: &str| {
        let auth = auth.to_owned();
        let router = router.clone();
        move |fields: Vec<(&'static str, &'static str)>| {
            let auth = auth.clone();
            let router = router.clone();
            async move {
                let mut all = vec![("grant_type", "client_credentials")];
                all.extend(fields);
                let headers: Vec<(&str, &str)> = if auth.is_empty() {
                    vec![]
                } else {
                    vec![("authorization", auth.as_str())]
                };
                post_form(&router, TOKEN, &headers, &all).await
            }
        }
    };

    // Basic, post, and hashed vs plaintext stored secrets.
    assert_eq!(cc(&worker_auth())(vec![]).await.status, StatusCode::OK);
    assert_eq!(
        cc("")(vec![
            ("client_id", WORKER),
            ("client_secret", WORKER_SECRET)
        ])
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        cc(&basic(LEGACY, LEGACY_SECRET))(vec![]).await.status,
        StatusCode::OK
    );
    // Basic credentials are not URL-decoded.
    assert_eq!(
        cc(&basic("pct%3Aid", "s%40cret"))(vec![]).await.status,
        StatusCode::OK
    );
    cc(&basic(LEGACY, "legacy%20plaintext"))(vec![])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);
    // Each Basic part falls back to the form independently.
    assert_eq!(
        cc(&basic(WORKER, ""))(vec![("client_secret", WORKER_SECRET)])
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        cc(&basic("", WORKER_SECRET))(vec![("client_id", WORKER)])
            .await
            .status,
        StatusCode::OK
    );
    // Basic wins over the form when set.
    assert_eq!(
        cc(&worker_auth())(vec![("client_id", BROWSER), ("client_secret", "x")])
            .await
            .status,
        StatusCode::OK
    );
    // A malformed Basic header is ignored.
    assert_eq!(
        cc("Basic !!!")(vec![
            ("client_id", WORKER),
            ("client_secret", WORKER_SECRET)
        ])
        .await
        .status,
        StatusCode::OK
    );
    // Wrong, missing secret, unknown client, public client.
    cc(&basic(WORKER, "wrong"))(vec![])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);
    cc("")(vec![("client_id", WORKER)])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);
    cc("")(vec![("client_id", "nope")])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);
    cc("")(vec![("client_id", BROWSER)])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, UNAUTHORIZED_CLIENT);
}

#[tokio::test]
async fn client_credentials_scope_rules_match_golden() {
    let fixture = Fixture::new();
    let golden = golden("scopes.json");
    let cases = golden["client_credentials_scope_rules"]["cases"]
        .as_array()
        .unwrap();
    for (index, case) in cases.iter().enumerate() {
        let id = format!("cc-{index}");
        fixture.clients.rows.lock().unwrap().push(OAuthClient {
            client_id: ClientId::new(id.as_str()),
            client_type: ClientType::Confidential,
            client_secret_hash: SecretString::from("secret".to_owned()),
            allowed_scopes: case["client_allowed_scopes"].as_str().unwrap().to_owned(),
            ..OAuthClient::default()
        });
    }
    let router = fixture.router();
    for (index, case) in cases.iter().enumerate() {
        let auth = basic(&format!("cc-{index}"), "secret");
        let requested = case["request_scope"].as_str().unwrap();
        let reply = post_form(
            &router,
            TOKEN,
            &[("authorization", &auth)],
            &[("grant_type", "client_credentials"), ("scope", requested)],
        )
        .await;
        match case["outcome"].as_str().unwrap() {
            "issue" => {
                assert_eq!(reply.status, StatusCode::OK, "{}", case["name"]);
                let body = reply.json();
                assert_eq!(
                    keys(&body),
                    ["access_token", "expires_in", "scope", "token_type"]
                );
                let mut split: Vec<String> = case["split"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect();
                split.sort();
                split.dedup();
                assert_eq!(body["scope"], split.join(" "), "{}", case["name"]);
                let claims = fixture
                    .jwks
                    .verify(body["access_token"].as_str().unwrap())
                    .unwrap();
                assert_eq!(claims["sub"], format!("cc-{index}"));
                assert!(claims.get("sid").is_none());
                // userinfo refuses client tokens (sub == client_id).
                let bearer = bearer(body["access_token"].as_str().unwrap());
                get(&router, USERINFO, &[("authorization", &bearer)])
                    .await
                    .assert_json(StatusCode::UNAUTHORIZED, INVALID_TOKEN);
            }
            _ => reply.assert_json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_scope"}"#),
        }
    }
}

#[tokio::test]
async fn refresh_grant_failures_are_invalid_grant() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let chain = store_chain(&fixture, &account, &session, BROWSER);
    store_refresh_token(&fixture, &chain, "refresh-a");
    for (client, token) in [(BROWSER, "unknown"), (BROWSER, ""), (LEGACY, "refresh-a")] {
        let secret = if client == LEGACY { LEGACY_SECRET } else { "" };
        post_form(
            &router,
            TOKEN,
            &[],
            &[
                ("grant_type", "refresh_token"),
                ("client_id", client),
                ("client_secret", secret),
                ("refresh_token", token),
            ],
        )
        .await
        .assert_json(StatusCode::BAD_REQUEST, INVALID_GRANT);
    }
    // A public client is never secret-checked.
    let reply = post_form(
        &router,
        TOKEN,
        &[],
        &[
            ("grant_type", "refresh_token"),
            ("client_id", BROWSER),
            ("client_secret", "anything"),
            ("refresh_token", "refresh-a"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
}

#[tokio::test]
async fn revoke_rules() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let own = store_chain(&fixture, &account, &session, LEGACY);
    store_refresh_token(&fixture, &own, "own-token");
    let foreign = store_chain(&fixture, &account, &session, BROWSER);
    store_refresh_token(&fixture, &foreign, "foreign-token");
    let auth = basic(LEGACY, LEGACY_SECRET);
    let revoke = |token: &'static str| {
        let router = router.clone();
        let auth = auth.clone();
        async move {
            post_form(
                &router,
                REVOKE,
                &[("authorization", &auth)],
                &[("token", token)],
            )
            .await
        }
    };

    for token in ["", "unknown", "foreign-token"] {
        let reply = revoke(token).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, "");
        assert_eq!(reply.header("content-type"), None);
    }
    assert_eq!(
        fixture.chains.get(&foreign.id).status,
        RefreshTokenChainStatus::Active
    );
    assert!(fixture.tokens.all().iter().all(|t| t.revoked_at.is_none()));

    assert_eq!(revoke("own-token").await.status, StatusCode::OK);
    assert_eq!(
        fixture.chains.get(&own.id).status,
        RefreshTokenChainStatus::Revoked
    );
    for token in fixture.tokens.all() {
        assert_eq!(
            token.revoked_at.is_some(),
            token.refresh_token_chain_id == own.id
        );
    }

    // Repository failures are swallowed.
    fixture.tokens.fail.set(true);
    assert_eq!(revoke("own-token").await.status, StatusCode::OK);

    // Client authentication still applies.
    post_form(
        &router,
        REVOKE,
        &[],
        &[("client_id", "nope"), ("token", "x")],
    )
    .await
    .assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);
    post_form(
        &router,
        REVOKE,
        &[("authorization", &basic(LEGACY, "wrong"))],
        &[("token", "x")],
    )
    .await
    .assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);
    // Public clients may revoke (no secret).
    let reply = post_form(
        &router,
        REVOKE,
        &[],
        &[("client_id", BROWSER), ("token", "x")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
}

async fn user_tokens(
    fixture: &Fixture,
    account: &AccountId,
    session: &SessionId,
    scope: &[&str],
) -> (String, String) {
    let tokens = fixture
        .state
        .token
        .issue_user_tokens(UserTokenRequest {
            account_id: account.clone(),
            client_id: ClientId::new(BROWSER),
            scope: scope.iter().map(|s| (*s).to_owned()).collect(),
            sso_session_id: session.clone(),
            device_session_id: "device".to_owned(),
            auth_time: NOW,
            nonce: String::new(),
            email: "ada@example.com".to_owned(),
            email_verified: true,
            name: "Ada".to_owned(),
            picture: String::new(),
        })
        .await
        .unwrap();
    (tokens.access_token, tokens.id_token.unwrap())
}

#[tokio::test]
async fn introspection_rules() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let (access, id_token) = user_tokens(&fixture, &account, &session, &["openid"]).await;

    // Confidential clients only.
    post_form(
        &router,
        INTROSPECT,
        &[],
        &[("client_id", BROWSER), ("token", &access)],
    )
    .await
    .assert_json(StatusCode::UNAUTHORIZED, UNAUTHORIZED_CLIENT);
    let reply = post_form(
        &router,
        INTROSPECT,
        &[],
        &[("client_id", "nope"), ("token", &access)],
    )
    .await;
    assert_no_store(&reply);
    reply.assert_json(StatusCode::UNAUTHORIZED, INVALID_CLIENT);

    // ID tokens are accepted on the JWT path (kept Go behavior).
    let reply = introspect(&router, &id_token, "").await;
    assert_no_store(&reply);
    let body = reply.json();
    assert_eq!(body["active"], true);
    assert_eq!(body["client_id"], "");
    assert_eq!(body["scope"], "");
    assert_eq!(body["aud"], BROWSER);
    assert_eq!(body["token_type"], "Bearer");

    // Inactive: garbage, empty, expired.
    for token in ["garbage", ""] {
        introspect(&router, token, "")
            .await
            .assert_json(StatusCode::OK, INACTIVE);
    }
    fixture.clock.advance(Duration::minutes(11));
    introspect(&router, &access, "")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
    fixture.clock.set(NOW);

    // Refresh path.
    let chain = store_chain(&fixture, &account, &session, BROWSER);
    let token = store_refresh_token(&fixture, &chain, "refresh-a");
    assert_eq!(
        introspect(&router, "refresh-a", "refresh_token")
            .await
            .json()["active"],
        true
    );
    for token in ["", "unknown"] {
        introspect(&router, token, "refresh_token")
            .await
            .assert_json(StatusCode::OK, INACTIVE);
    }
    let set_token = |f: &dyn Fn(&mut auth_core::domain::RefreshToken)| {
        let mut rows = fixture.tokens.rows.lock().unwrap();
        let row = rows.iter_mut().find(|t| t.id == token.id).unwrap();
        f(row);
    };
    set_token(&|t| t.used_at = Some(NOW));
    introspect(&router, "refresh-a", "refresh_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
    set_token(&|t| {
        t.used_at = None;
        t.revoked_at = Some(NOW);
    });
    introspect(&router, "refresh-a", "refresh_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
    set_token(&|t| {
        t.revoked_at = None;
        t.expires_at = NOW - Duration::seconds(1);
    });
    introspect(&router, "refresh-a", "refresh_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
    set_token(&|t| t.expires_at = NOW);
    assert_eq!(
        introspect(&router, "refresh-a", "refresh_token")
            .await
            .json()["active"],
        true
    );
    fixture
        .chains
        .rows
        .lock()
        .unwrap()
        .iter_mut()
        .find(|c| c.id == chain.id)
        .unwrap()
        .revoked_at = Some(NOW);
    introspect(&router, "refresh-a", "refresh_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
    fixture
        .chains
        .rows
        .lock()
        .unwrap()
        .iter_mut()
        .find(|c| c.id == chain.id)
        .unwrap()
        .revoked_at = None;
    fixture
        .chains
        .rows
        .lock()
        .unwrap()
        .iter_mut()
        .find(|c| c.id == chain.id)
        .unwrap()
        .status = RefreshTokenChainStatus::Revoked;
    introspect(&router, "refresh-a", "refresh_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
    fixture.tokens.fail.set(true);
    fixture
        .chains
        .rows
        .lock()
        .unwrap()
        .iter_mut()
        .find(|c| c.id == chain.id)
        .unwrap()
        .status = RefreshTokenChainStatus::Active;
    introspect(&router, "refresh-a", "refresh_token")
        .await
        .assert_json(StatusCode::OK, INACTIVE);
}

#[tokio::test]
async fn userinfo_rules() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let call = |auth: Option<String>| {
        let router = router.clone();
        async move {
            match auth {
                Some(auth) => get(&router, USERINFO, &[("authorization", &auth)]).await,
                None => get(&router, USERINFO, &[]).await,
            }
        }
    };
    for (auth, challenge) in [
        (None, "Bearer"),
        (Some("Bearer"), "Bearer"),
        (Some("Bearer   "), "Bearer"),
        (Some("Bearer garbage"), r#"Bearer error="invalid_token""#),
    ] {
        let reply = call(auth.map(str::to_owned)).await;
        assert_eq!(reply.header("www-authenticate"), Some(challenge));
        reply.assert_json(StatusCode::UNAUTHORIZED, INVALID_TOKEN);
    }

    let (openid, _) = user_tokens(&fixture, &account, &session, &["openid"]).await;
    let (email, _) = user_tokens(&fixture, &account, &session, &["openid", "email"]).await;
    let (profile, _) = user_tokens(&fixture, &account, &session, &["openid", "profile"]).await;
    call(Some(format!("Bearer {openid}")))
        .await
        .assert_json(StatusCode::OK, &format!(r#"{{"sub":"{account}"}}"#));
    // TrimPrefix("Bearer") + TrimSpace: no space and extra spaces both work.
    call(Some(format!("Bearer{email}  "))).await.assert_json(
        StatusCode::OK,
        &format!(r#"{{"email":"ada@example.com","email_verified":true,"sub":"{account}"}}"#),
    );
    call(Some(format!("Bearer {profile}")))
        .await
        .assert_json(
            StatusCode::OK,
            &format!(
                r#"{{"name":"ada","picture":"https://cdn.example/ada@example.com.png","sub":"{account}"}}"#
            ),
        );
    // The prefix is case-sensitive.
    call(Some(format!("bearer {openid}")))
        .await
        .assert_json(StatusCode::UNAUTHORIZED, INVALID_TOKEN);
    // Expired token and missing account.
    fixture.clock.advance(Duration::minutes(11));
    call(Some(format!("Bearer {openid}")))
        .await
        .assert_json(StatusCode::UNAUTHORIZED, INVALID_TOKEN);
    fixture.clock.set(NOW);
    fixture.accounts.rows.lock().unwrap().clear();
    call(Some(format!("Bearer {openid}")))
        .await
        .assert_json(StatusCode::UNAUTHORIZED, INVALID_TOKEN);
}
