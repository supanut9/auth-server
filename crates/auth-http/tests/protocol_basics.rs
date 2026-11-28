//! Health, discovery, JWKS, dev callback, client public info, `/v1/auth/me`
//! and `/v1/auth/csrf`.

mod protocol_support;

use auth_core::domain::SsoSessionStatus;
use axum::http::StatusCode;
use protocol_support::*;
use time::Duration;

const PROD_SECRET: &str = "0123456789abcdef0123456789abcdef";

fn production(conditional: bool) -> Fixture {
    let mut fixture = Fixture::with_config(config_with(&[
        ("APP_ENV", "production"),
        ("OTP_TEST_HINT_ALLOWLIST", ""),
        ("FLOW_ENVELOPE_SECRET", PROD_SECRET),
        ("SSO_COOKIE_SECURE", "true"),
    ]));
    fixture.conditional_routes = conditional;
    fixture
}

#[tokio::test]
async fn healthz_and_readyz() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let reply = get(&router, "/healthz", &[("x-request-id", "req-1")]).await;
    reply.assert_json(
        StatusCode::OK,
        r#"{"app_name":"auth-server","request_id":"req-1","status":"ok"}"#,
    );
    assert_eq!(reply.header("x-request-id"), Some("req-1"));

    let reply = get(&router, "/readyz", &[("x-request-id", "req-2")]).await;
    reply.assert_json(
        StatusCode::OK,
        r#"{"app_name":"auth-server","database":"ready","request_id":"req-2","status":"ok"}"#,
    );

    fixture.readiness.fail.set(true);
    let reply = get(&router, "/readyz", &[]).await;
    reply.assert_json(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"database_unavailable","status":"degraded"}"#,
    );
    assert!(reply.header("x-request-id").is_some());
}

#[tokio::test]
async fn dev_callback_only_outside_production() {
    let router = Fixture::new().router();
    let reply = get(
        &router,
        "/dev/callback?code=a+b&state=%3Cs%3E&code=second",
        &[],
    )
    .await;
    reply.assert_json(
        StatusCode::OK,
        r#"{"code":"a b","error":"","state":"\u003cs\u003e"}"#,
    );

    for conditional in [false, true] {
        let router = production(conditional).router();
        let reply = get(&router, "/dev/callback?code=x", &[]).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.header("content-type"), Some("text/plain"));
        assert_eq!(reply.body, "404 page not found");
    }
}

#[tokio::test]
async fn discovery_matches_golden() {
    let golden = golden("discovery.json");
    for case in golden["openid_configuration"]["cases"].as_array().unwrap() {
        let fixture = Fixture::with_config(config_with(&[
            ("JWT_ISSUER", case["jwt_issuer"].as_str().unwrap()),
            ("JWT_SIGNING_ALG", case["jwt_signing_alg"].as_str().unwrap()),
        ]));
        let reply = get(&fixture.router(), "/.well-known/openid-configuration", &[]).await;
        let response = &case["response"];
        assert_eq!(
            reply.status.as_u16(),
            response["status"].as_u64().unwrap() as u16
        );
        assert_eq!(
            reply.header("content-type"),
            response["content_type"].as_str()
        );
        assert_eq!(reply.body, response["body"].as_str().unwrap());
    }
}

#[tokio::test]
async fn jwks_document_and_failure() {
    let mut fixture = Fixture::new();
    let reply = get(&fixture.router(), "/.well-known/jwks.json", &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let golden = golden("jwks.json");
    assert_eq!(
        reply.body,
        golden["jwks_document"]["document"].as_str().unwrap()
    );
    assert_eq!(reply.json()["keys"][0]["kid"], golden["kid"]["kid"]);

    fixture.state.jwks = std::sync::Arc::new(FailingJwks);
    let reply = get(&fixture.router(), "/.well-known/jwks.json", &[]).await;
    reply.assert_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":"server_error"}"#,
    );
}

#[tokio::test]
async fn client_public_info_shapes() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let reply = get(&router, &format!("/v1/clients/{BROWSER}/public-info"), &[]).await;
    // allowed_scopes: first-seen order, not sorted, deduplicated.
    reply.assert_json(
        StatusCode::OK,
        r#"{"allowed_scopes":["profile","openid","email","offline_access"],"client_id":"browser-web","display_name":"browser-web display","logo_uri":"https://cdn.example/browser-web.png"}"#,
    );

    // The path parameter is decoded and trimmed.
    let reply = get(&router, "/v1/clients/%20browser-web%20/public-info", &[]).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["client_id"], BROWSER);

    let reply = get(&router, "/v1/clients/%20/public-info", &[]).await;
    reply.assert_json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#);

    let reply = get(&router, "/v1/clients/unknown/public-info", &[]).await;
    reply.assert_json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#);

    fixture.clients.fail.set(true);
    let reply = get(&router, "/v1/clients/unknown/public-info", &[]).await;
    reply.assert_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":"server_error"}"#,
    );
}

#[tokio::test]
async fn current_user_from_sso_cookie() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let cookie = format!("auth_sso_session={session}");

    let reply = get(&router, "/v1/auth/me", &[("cookie", &cookie)]).await;
    reply.assert_json(
        StatusCode::OK,
        &format!(
            r#"{{"account_id":"{account}","authenticated":true,"display_name":"ada","email":"ada@example.com","login_method":"email_otp","session":{{"authenticated_at":"2026-11-26T09:55:00.5Z","expires_at":"2026-11-27T10:00:00.5Z","id":"{session}"}}}}"#
        ),
    );

    let unauthenticated = r#"{"error":"unauthenticated"}"#;
    // No cookie, unknown session, expired, revoked and inactive sessions.
    get(&router, "/v1/auth/me", &[])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, unauthenticated);
    get(
        &router,
        "/v1/auth/me",
        &[("cookie", "auth_sso_session=nope")],
    )
    .await
    .assert_json(StatusCode::UNAUTHORIZED, unauthenticated);
    fixture.clock.advance(Duration::days(2));
    get(&router, "/v1/auth/me", &[("cookie", &cookie)])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, unauthenticated);
    fixture.clock.set(NOW);
    fixture.sessions.rows.lock().unwrap()[0].status = SsoSessionStatus::Revoked;
    get(&router, "/v1/auth/me", &[("cookie", &cookie)])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, unauthenticated);
    fixture.sessions.rows.lock().unwrap()[0].status = SsoSessionStatus::Active;
    fixture.sessions.rows.lock().unwrap()[0].revoked_at = Some(NOW);
    get(&router, "/v1/auth/me", &[("cookie", &cookie)])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, unauthenticated);
    fixture.sessions.rows.lock().unwrap()[0].revoked_at = None;

    // Account lookup failure and repository failure are 401 too.
    fixture.accounts.fail.set(true);
    get(&router, "/v1/auth/me", &[("cookie", &cookie)])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, unauthenticated);
    fixture.accounts.fail.set(false);
    fixture.sessions.fail.set(true);
    get(&router, "/v1/auth/me", &[("cookie", &cookie)])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, unauthenticated);
}

#[tokio::test]
async fn csrf_cookie_matches_golden() {
    let golden = golden("cookies.json");
    for case in golden["csrf_cookie"]["cases"].as_array().unwrap() {
        let config = &case["config"];
        let secure = if config["sso_cookie_secure"].as_bool().unwrap() {
            "true"
        } else {
            "false"
        };
        let fixture = Fixture::with_config(config_with(&[
            ("SSO_COOKIE_SECURE", secure),
            (
                "SSO_COOKIE_SAME_SITE",
                config["sso_cookie_same_site"].as_str().unwrap(),
            ),
            (
                "SSO_COOKIE_DOMAIN",
                config["sso_cookie_domain"].as_str().unwrap(),
            ),
        ]));
        let raw = hex(case["random_raw_hex"].as_str().unwrap());
        fixture.random.queue.lock().unwrap().push_back(raw);
        let reply = get(&fixture.router(), "/v1/auth/csrf", &[]).await;
        let response = &case["response"];
        assert_eq!(
            reply.status.as_u16(),
            response["status"].as_u64().unwrap() as u16
        );
        assert_eq!(
            reply.header("content-type"),
            response["content_type"].as_str()
        );
        assert_eq!(reply.body, response["body"].as_str().unwrap());
        let expected: Vec<&str> = response["set_cookie"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(reply.set_cookies(), expected, "{}", case["name"]);
        assert_eq!(case["token"].as_str().unwrap().len(), 43);
    }

    let fixture = Fixture::new();
    fixture
        .random
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let reply = get(&fixture.router(), "/v1/auth/csrf", &[]).await;
    reply.assert_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":"server_error"}"#,
    );
    assert!(reply.set_cookies().is_empty());
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn cleanup_is_unavailable_without_a_secret() {
    let router = Fixture::new().router();
    get(&router, "/v1/internal/cleanup", &[]).await.assert_json(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"cleanup_unavailable"}"#,
    );
}

#[tokio::test]
async fn cleanup_requires_the_bearer_scheme_and_token() {
    let router = Fixture::with_config(config_with(&[("CRON_SECRET", "cron-test-token")])).router();
    for header in ["cron-test-token", "Bearercron-test-token", "Bearer wrong"] {
        let reply = get(
            &router,
            "/v1/internal/cleanup",
            &[("authorization", header)],
        )
        .await;
        reply.assert_json(StatusCode::UNAUTHORIZED, r#"{"error":"invalid_token"}"#);
        assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
        assert_eq!(reply.header("cache-control"), Some("no-store"));
    }
    get(
        &router,
        "/v1/internal/cleanup",
        &[("authorization", "Bearer cron-test-token")],
    )
    .await
    .assert_json(
        StatusCode::OK,
        r#"{"deleted":{"authorization_codes":0,"otp_challenges":0,"otp_rate_limit_hits":0,"signed_state_jtis":0}}"#,
    );
}
