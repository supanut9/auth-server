//! Local and global logout, the support API and the OTP test hint.

mod protocol_support;

use std::collections::BTreeMap;

use auth_core::{
    domain::{
        Account, AccountId, AccountStatus, ClientId, ConsentGrant, OtpChallenge,
        RefreshTokenChainStatus, SsoSession, SsoSessionStatus,
    },
    ports::{RepoError, SupportAccountSummary},
};
use axum::http::StatusCode;
use protocol_support::*;
use time::{Duration, macros::datetime};

const PROD_SECRET: &str = "0123456789abcdef0123456789abcdef";
const SERVER_ERROR: &str = r#"{"error":"server_error"}"#;

fn sso(session: &impl std::fmt::Display) -> String {
    format!("auth_sso_session={session}")
}

#[tokio::test]
async fn post_logout_targets_match_golden() {
    let golden = golden("redirects.json");
    let section = &golden["post_logout"];
    let allowlist: Vec<&str> = section["post_logout_redirect_allowlist"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let fixture = Fixture::with_config(config_with(&[
        (
            "AUTH_UI_BASE_URL",
            section["auth_ui_base_url"].as_str().unwrap(),
        ),
        ("POST_LOGOUT_REDIRECT_ALLOWLIST", &allowlist.join(",")),
    ]));
    let router = fixture.router();
    for case in section["cases"].as_array().unwrap() {
        let candidate = case["post_logout_redirect_uri"].as_str().unwrap();
        let location = case["location"].as_str().unwrap();
        for path in ["/v1/auth/logout", "/v1/auth/logout/global"] {
            let uri = format!(
                "{path}?post_logout_redirect_uri={}",
                auth_http::go_url::query_escape(candidate)
            );
            let reply = get(&router, &uri, &[]).await;
            reply.assert_found(location);
            assert_eq!(
                reply.body,
                format!("<a href=\"{}\">Found</a>.\n\n", html(location))
            );
            assert!(reply.set_cookies().is_empty());
        }
    }
}

fn html(s: &str) -> String {
    s.replace('&', "&amp;").replace('\'', "&#39;")
}

#[tokio::test]
async fn local_logout_revokes_only_the_callers_chain() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let (other_account, other_session) = fixture.login("eve@example.com");
    let own = store_chain(&fixture, &account, &session, BROWSER);
    store_refresh_token(&fixture, &own, "own");
    let foreign = store_chain(&fixture, &other_account, &other_session, BROWSER);
    store_refresh_token(&fixture, &foreign, "foreign");
    let default_target = format!("{UI}/logout");
    let logout = |chain: &str, cookie: Option<String>| {
        let router = router.clone();
        let uri = format!("/v1/auth/logout?refresh_token_chain_id={chain}");
        async move {
            match cookie {
                Some(cookie) => get(&router, &uri, &[("cookie", &cookie)]).await,
                None => get(&router, &uri, &[]).await,
            }
        }
    };
    let active = |id| fixture.chains.get(id).status == RefreshTokenChainStatus::Active;

    // No cookie, unknown session, foreign chain: ignored, still redirected.
    logout(foreign.id.as_str(), None)
        .await
        .assert_found(&default_target);
    logout(foreign.id.as_str(), Some(sso(&"unknown")))
        .await
        .assert_found(&default_target);
    logout(foreign.id.as_str(), Some(sso(&session)))
        .await
        .assert_found(&default_target);
    logout("unknown-chain", Some(sso(&session)))
        .await
        .assert_found(&default_target);
    assert!(active(&own.id) && active(&foreign.id));

    // Inactive session: ignored.
    fixture.clock.advance(Duration::days(2));
    logout(own.id.as_str(), Some(sso(&session)))
        .await
        .assert_found(&default_target);
    assert!(active(&own.id));
    fixture.clock.set(NOW);

    // Own chain: tokens and chain revoked, cookie untouched.
    let reply = logout(own.id.as_str(), Some(sso(&session))).await;
    reply.assert_found(&default_target);
    assert!(reply.set_cookies().is_empty());
    assert!(!active(&own.id) && active(&foreign.id));
    for token in fixture.tokens.all() {
        assert_eq!(
            token.revoked_at.is_some(),
            token.refresh_token_chain_id == own.id
        );
    }

    // Repository failures: 500 (session lookup, then chain revoke).
    fixture.sessions.fail.set(true);
    logout(own.id.as_str(), Some(sso(&session)))
        .await
        .assert_json(StatusCode::INTERNAL_SERVER_ERROR, SERVER_ERROR);
    // Without a chain ID nothing is looked up.
    get(&router, "/v1/auth/logout", &[("cookie", &sso(&session))])
        .await
        .assert_found(&default_target);
    fixture.sessions.fail.set(false);
    fixture.chains.fail.set(true);
    logout(own.id.as_str(), Some(sso(&session)))
        .await
        .assert_json(StatusCode::INTERNAL_SERVER_ERROR, SERVER_ERROR);
}

#[tokio::test]
async fn global_logout_revokes_session_chains_and_clears_cookie() {
    let fixture = Fixture::with_config(config_with(&[
        ("SSO_COOKIE_SECURE", "true"),
        ("SSO_COOKIE_SAME_SITE", "none"),
        ("SSO_COOKIE_DOMAIN", ".example.com"),
    ]));
    let router = fixture.router();
    let (account, session) = fixture.login("ada@example.com");
    let (other_account, other_session) = fixture.login("eve@example.com");
    let own = store_chain(&fixture, &account, &session, BROWSER);
    store_refresh_token(&fixture, &own, "own");
    let foreign = store_chain(&fixture, &other_account, &other_session, BROWSER);

    // Empty cookie value: just the redirect.
    let reply = get(
        &router,
        "/v1/auth/logout/global",
        &[("cookie", "auth_sso_session=")],
    )
    .await;
    reply.assert_found(&format!("{UI}/logout"));
    assert!(reply.set_cookies().is_empty());

    let target = "https://community.example/bye?x=1&y=%C3%A9#frag";
    let uri = format!(
        "/v1/auth/logout/global?post_logout_redirect_uri={}",
        auth_http::go_url::query_escape(target)
    );
    let reply = get(&router, &uri, &[("cookie", &sso(&session))]).await;
    reply.assert_found(target);
    // The golden clear cookie (cookies.json `clear_secure_none_domain`).
    assert_eq!(
        reply.set_cookies(),
        [
            "auth_sso_session=; Path=/; Domain=example.com; Max-Age=0; HttpOnly; Secure; SameSite=None"
        ]
    );
    assert_eq!(
        fixture.sessions.get(session.as_str()).status,
        SsoSessionStatus::Revoked
    );
    assert_eq!(
        fixture.chains.get(&own.id).status,
        RefreshTokenChainStatus::Revoked
    );
    assert_eq!(
        fixture.chains.get(&foreign.id).status,
        RefreshTokenChainStatus::Active
    );
    assert!(fixture.tokens.all()[0].revoked_at.is_some());

    // Non-ASCII targets are percent-escaped in Location (Go
    // hexEscapeNonASCII).
    let target = "https://community.example/é";
    let uri = format!(
        "/v1/auth/logout/global?post_logout_redirect_uri={}",
        auth_http::go_url::query_escape(target)
    );
    let reply = get(&router, &uri, &[]).await;
    reply.assert_found("https://community.example/%C3%A9");
    assert_eq!(reply.body, format!("<a href=\"{target}\">Found</a>.\n\n"));

    // Unknown session IDs still clear the cookie; repository errors are 500.
    let reply = get(
        &router,
        "/v1/auth/logout/global",
        &[("cookie", "auth_sso_session=stale")],
    )
    .await;
    reply.assert_found(&format!("{UI}/logout"));
    assert_eq!(reply.set_cookies().len(), 1);
    fixture.sessions.fail.set(true);
    let reply = get(
        &router,
        "/v1/auth/logout/global",
        &[("cookie", &sso(&other_session))],
    )
    .await;
    reply.assert_json(StatusCode::INTERNAL_SERVER_ERROR, SERVER_ERROR);
    assert!(reply.set_cookies().is_empty());
}

fn summary(account: &AccountId) -> SupportAccountSummary {
    let session = |id: &str, revoked: bool| SsoSession {
        id: id.into(),
        account_id: account.clone(),
        status: if revoked {
            SsoSessionStatus::Revoked
        } else {
            SsoSessionStatus::Active
        },
        login_method: "google".to_owned(),
        authenticated_at: datetime!(2026-11-20 08:00:00.123456789 UTC),
        last_seen_at: datetime!(2026-11-21 08:00 UTC),
        expires_at: datetime!(2026-12-20 08:00 UTC),
        revoked_at: revoked.then_some(datetime!(2026-11-22 08:00:00.1 UTC)),
        ..SsoSession::default()
    };
    let chain = |id: &str, client: &str| auth_core::domain::RefreshTokenChain {
        id: id.into(),
        account_id: account.clone(),
        client_id: ClientId::new(client),
        sso_session_id: "s1".into(),
        scope: "openid".to_owned(),
        status: RefreshTokenChainStatus::Active,
        absolute_expires_at: datetime!(2026-12-20 08:00 UTC),
        inactive_expires_at: datetime!(2026-11-27 08:00 UTC),
        last_used_at: datetime!(2026-11-21 08:00 UTC),
        ..Default::default()
    };
    SupportAccountSummary {
        account: Account {
            id: account.clone(),
            primary_verified_email: "ada@example.com".to_owned(),
            display_name: "Ada <Admin>".to_owned(),
            avatar_url: String::new(),
            status: AccountStatus::Active,
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            updated_at: datetime!(2026-01-02 03:04:05.5 UTC),
        },
        sessions: vec![session("s1", false), session("s0", true)],
        consents: vec![ConsentGrant {
            id: "g1".into(),
            account_id: account.clone(),
            client_id: ClientId::new(BROWSER),
            granted_scopes: "email openid".to_owned(),
            granted_at: datetime!(2026-11-20 08:00 UTC),
            last_used_at: datetime!(2026-11-21 08:00 UTC),
            revoked_at: None,
        }],
        refresh_token_chains: vec![chain("c1", BROWSER), chain("c2", "gone-client")],
        client_display_names: BTreeMap::from([(ClientId::new(BROWSER), "Browser".to_owned())]),
    }
}

#[tokio::test]
async fn support_auth_and_lookup_errors() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let invalid = r#"{"error":"invalid_token"}"#;
    for auth in [
        None,
        Some("Bearer wrong"),
        Some("bearer support-secret"),
        Some("Bearer "),
    ] {
        let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("authorization", *a)).collect();
        get(&router, "/v1/support/accounts/a1", &headers)
            .await
            .assert_json(StatusCode::UNAUTHORIZED, invalid);
        post(&router, "/v1/support/accounts/a1/sign-out", &headers, "")
            .await
            .assert_json(StatusCode::UNAUTHORIZED, invalid);
    }
    // Auth runs before the path parameter check.
    get(&router, "/v1/support/accounts/%20", &[])
        .await
        .assert_json(StatusCode::UNAUTHORIZED, invalid);

    let auth = [("authorization", "Bearer support-secret")];
    get(&router, "/v1/support/accounts/%20", &auth)
        .await
        .assert_json(StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#);
    get(&router, "/v1/support/accounts/missing", &auth)
        .await
        .assert_json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#);
    *fixture.support.summary_error.lock().unwrap() = Some(RepoError::other("down"));
    post(&router, "/v1/support/accounts/missing/sign-out", &auth, "")
        .await
        .assert_json(StatusCode::INTERNAL_SERVER_ERROR, SERVER_ERROR);

    // No configured token (config validation normally prevents it): 503.
    let mut fixture = Fixture::new();
    fixture.state.support_auth = std::sync::Arc::new(auth_http::middleware::SupportAuth::new(" "));
    get(&fixture.router(), "/v1/support/accounts/a1", &auth)
        .await
        .assert_json(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"support_unavailable"}"#,
        );
}

#[tokio::test]
async fn support_summary_and_sign_out_shapes() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let account = AccountId::new("a1");
    *fixture.support.summary.lock().unwrap() = Some(summary(&account));
    let auth = [("authorization", "Bearer support-secret")];

    let reply = get(&router, "/v1/support/accounts/%20a1%20", &auth).await;
    reply.assert_json(
        StatusCode::OK,
        concat!(
            r#"{"account":{"id":"a1","email":"ada@example.com","display_name":"Ada \u003cAdmin\u003e","avatar_url":"","status":"active","created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05.5Z"},"#,
            r#""sessions":[{"id":"s1","status":"active","login_method":"google","authenticated_at":"2026-11-20T08:00:00.123456789Z","last_seen_at":"2026-11-21T08:00:00Z","expires_at":"2026-12-20T08:00:00Z","revoked_at":null},"#,
            r#"{"id":"s0","status":"revoked","login_method":"google","authenticated_at":"2026-11-20T08:00:00.123456789Z","last_seen_at":"2026-11-21T08:00:00Z","expires_at":"2026-12-20T08:00:00Z","revoked_at":"2026-11-22T08:00:00.1Z"}],"#,
            r#""consents":[{"id":"g1","client":{"client_id":"browser-web","display_name":"Browser"},"granted_scopes":"email openid","granted_at":"2026-11-20T08:00:00Z","last_used_at":"2026-11-21T08:00:00Z","revoked_at":null}],"#,
            r#""refresh_token_chains":[{"id":"c1","client":{"client_id":"browser-web","display_name":"Browser"},"sso_session_id":"s1","scope":"openid","status":"active","absolute_expires_at":"2026-12-20T08:00:00Z","inactive_expires_at":"2026-11-27T08:00:00Z","last_used_at":"2026-11-21T08:00:00Z","revoked_at":null},"#,
            r#"{"id":"c2","client":{"client_id":"gone-client","display_name":""},"sso_session_id":"s1","scope":"openid","status":"active","absolute_expires_at":"2026-12-20T08:00:00Z","inactive_expires_at":"2026-11-27T08:00:00Z","last_used_at":"2026-11-21T08:00:00Z","revoked_at":null}]}"#,
        ),
    );
    assert_eq!(fixture.support.requested.lock().unwrap()[0], account);

    let reply = post(&router, "/v1/support/accounts/a1/sign-out", &auth, "").await;
    reply.assert_json(
        StatusCode::OK,
        r#"{"account_id":"a1","revoked_session_ids":["s1","s0"],"revoked_chain_ids":["c1","c2"],"revoked_refresh_chain_count":2}"#,
    );
    let sign_outs = fixture.support.sign_outs.lock().unwrap().clone();
    assert_eq!(sign_outs.len(), 1);
    assert_eq!(sign_outs[0].2, NOW);

    // Empty lists are [] (never null), and a failed transaction is 500.
    let mut empty = summary(&account);
    empty.sessions.clear();
    empty.consents.clear();
    empty.refresh_token_chains.clear();
    *fixture.support.summary.lock().unwrap() = Some(empty);
    let body = get(&router, "/v1/support/accounts/a1", &auth).await.json();
    assert_eq!(body["sessions"], serde_json::json!([]));
    assert_eq!(body["consents"], serde_json::json!([]));
    assert_eq!(body["refresh_token_chains"], serde_json::json!([]));
    post(&router, "/v1/support/accounts/a1/sign-out", &auth, "")
        .await
        .assert_json(
            StatusCode::OK,
            r#"{"account_id":"a1","revoked_session_ids":[],"revoked_chain_ids":[],"revoked_refresh_chain_count":0}"#,
        );
    fixture.support.sign_out_fail.set(true);
    post(&router, "/v1/support/accounts/a1/sign-out", &auth, "")
        .await
        .assert_json(StatusCode::INTERNAL_SERVER_ERROR, SERVER_ERROR);
}

fn challenge(id: &str, email: &str, created_minutes_ago: i64) -> OtpChallenge {
    OtpChallenge {
        id: id.into(),
        email: email.to_owned(),
        purpose: "login".to_owned(),
        code_hash: format!("{id}-hash-abcdefgh"),
        expires_at: NOW + Duration::minutes(10),
        created_at: NOW - Duration::minutes(created_minutes_ago),
        last_sent_at: NOW,
        ..OtpChallenge::default()
    }
}

#[tokio::test]
async fn otp_test_hint_rules() {
    let not_found = r#"{"error":"not_found"}"#;
    let fixture = Fixture::new();
    let router = fixture.router();
    let hint = |query: &str| {
        let router = router.clone();
        let uri = format!("/v1/auth/otp/test-hint{query}");
        async move { get(&router, &uri, &[]).await }
    };

    hint("").await.assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"email query param required"}"#,
    );
    hint("?email=%20%20").await.assert_json(
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request","error_description":"email query param required"}"#,
    );
    hint("?email=stranger@example.com")
        .await
        .assert_json(StatusCode::NOT_FOUND, not_found);
    // Allowlisted but no active challenge.
    hint("?email=ci@example.com")
        .await
        .assert_json(StatusCode::NOT_FOUND, not_found);

    {
        let mut rows = fixture.otps.rows.lock().unwrap();
        rows.push(challenge("old", HINT_EMAIL, 5));
        rows.push(challenge("new", HINT_EMAIL, 1));
        let mut verified = challenge("verified", HINT_EMAIL, 0);
        verified.verified_at = Some(NOW);
        rows.push(verified);
    }
    // Email is lowercased and trimmed; the allowlist entry is trimmed and
    // compared case-insensitively.
    hint("?email=%20CI@Example.COM%20").await.assert_json(
        StatusCode::OK,
        r#"{"code_hash_prefix":"new-hash","email":"ci@example.com","expires_at":"2026-11-26T10:10:00.5Z","otp_challenge_id":"new"}"#,
    );
    fixture.clock.advance(Duration::minutes(11));
    hint("?email=ci@example.com")
        .await
        .assert_json(StatusCode::NOT_FOUND, not_found);
    fixture.clock.set(NOW);

    // A code hash shorter than 8 bytes: Go panics, gin answers 500.
    fixture.otps.rows.lock().unwrap().push(OtpChallenge {
        code_hash: "short".to_owned(),
        created_at: NOW,
        ..challenge("tiny", "other@example.com", 0)
    });
    let reply = hint("?email=other@example.com").await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.body, "");

    // Without the hint source extension: 404 like a missing challenge.
    let mut bare = Fixture::new();
    bare.with_hint_source = false;
    bare.otps
        .rows
        .lock()
        .unwrap()
        .push(challenge("x", HINT_EMAIL, 0));
    get(
        &bare.router(),
        "/v1/auth/otp/test-hint?email=ci@example.com",
        &[],
    )
    .await
    .assert_json(StatusCode::NOT_FOUND, not_found);

    // Empty allowlist: 404 before reading the email.
    let empty = Fixture::with_config(config_with(&[("OTP_TEST_HINT_ALLOWLIST", "")]));
    get(&empty.router(), "/v1/auth/otp/test-hint", &[])
        .await
        .assert_json(StatusCode::NOT_FOUND, not_found);

    // Production: gin's 404 page whether mounted or not.
    for conditional in [false, true] {
        let mut production = Fixture::with_config(config_with(&[
            ("APP_ENV", "production"),
            ("OTP_TEST_HINT_ALLOWLIST", ""),
            ("FLOW_ENVELOPE_SECRET", PROD_SECRET),
            ("SSO_COOKIE_SECURE", "true"),
        ]));
        production.conditional_routes = conditional;
        let reply = get(
            &production.router(),
            "/v1/auth/otp/test-hint?email=ci@example.com",
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        if conditional {
            assert_eq!(reply.body, "404 page not found");
        } else {
            assert_eq!(reply.body, not_found);
        }
    }
}
