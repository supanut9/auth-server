//! `FlowService` behavior: port of `internal/application/flow/service_test.go`
//! plus per-method coverage of check order, consent union and logout scoping.

mod flow_fakes;

use auth_core::crypto::{b64url_encode, sha256_b64url};
use auth_core::domain::{
    AccountId, AuthorizationCode, AuthorizationCodeId, ChainId, ClientId, ConsentGrant,
    ConsentGrantId, RefreshToken, RefreshTokenChain, RefreshTokenChainStatus, RefreshTokenId,
    SessionId, SsoSession, SsoSessionStatus, ZERO_TIME,
};
use auth_core::flow::{
    ConsumeAuthorizationCodeRequest, FlowError, IssueDirectCodeRequest, UpsertConsentRequest,
};
use auth_core::ports::RepoError;
use flow_fakes::{Harness, NOW, REVOKED_AT, config, strings};
use time::Duration;
use time::macros::{datetime, offset};

const ACCOUNT: &str = "account-1";
const CLIENT: &str = "client-1";
const REDIRECT: &str = "https://app.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn issue_request() -> IssueDirectCodeRequest {
    IssueDirectCodeRequest {
        account_id: AccountId::from(ACCOUNT),
        client_id: ClientId::from(CLIENT),
        sso_session_id: Some(SessionId::from("sso-1")),
        redirect_uri: REDIRECT.to_owned(),
        scopes: strings(&[" profile", "openid", "", "openid", "email "]),
        pkce_code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        pkce_code_challenge_method: "S256".to_owned(),
        nonce: String::new(),
        auth_time: datetime!(2026-04-01 18:59:30 +7),
    }
}

fn consume_request(code: &str) -> ConsumeAuthorizationCodeRequest {
    ConsumeAuthorizationCodeRequest {
        code: code.to_owned(),
        client_id: ClientId::from(CLIENT),
        redirect_uri: REDIRECT.to_owned(),
        code_verifier: String::new(),
    }
}

/// Stores a code whose value is `value`, issued at `NOW`.
fn stored_code(h: &Harness, id: &str, value: &str) -> AuthorizationCode {
    let code = AuthorizationCode {
        id: AuthorizationCodeId::from(id),
        code_hash: sha256_b64url(value),
        account_id: AccountId::from(ACCOUNT),
        client_id: ClientId::from(CLIENT),
        redirect_uri: REDIRECT.to_owned(),
        granted_scopes: "openid profile".to_owned(),
        auth_time: NOW,
        expires_at: NOW + Duration::minutes(5),
        created_at: NOW,
        ..AuthorizationCode::default()
    };
    h.codes.insert(code.clone());
    code
}

fn grant(scopes: &str) -> ConsentGrant {
    ConsentGrant {
        id: ConsentGrantId::from("consent-existing"),
        account_id: AccountId::from(ACCOUNT),
        client_id: ClientId::from(CLIENT),
        granted_scopes: scopes.to_owned(),
        granted_at: datetime!(2026-01-01 00:00 UTC),
        last_used_at: datetime!(2026-02-01 00:00 UTC),
        revoked_at: None,
    }
}

fn chain(id: &str, session: &str) -> RefreshTokenChain {
    RefreshTokenChain {
        id: ChainId::from(id),
        account_id: AccountId::from(ACCOUNT),
        sso_session_id: SessionId::from(session),
        status: RefreshTokenChainStatus::Active,
        ..RefreshTokenChain::default()
    }
}

fn token(id: &str, chain: &str) -> RefreshToken {
    RefreshToken {
        id: RefreshTokenId::from(id),
        refresh_token_chain_id: ChainId::from(chain),
        ..RefreshToken::default()
    }
}

fn session(id: &str) -> SsoSession {
    SsoSession {
        id: SessionId::from(id),
        account_id: AccountId::from(ACCOUNT),
        status: SsoSessionStatus::Active,
        ..SsoSession::default()
    }
}

fn is_repo_other(error: &FlowError, text: &str) -> bool {
    matches!(error, FlowError::Repo(RepoError::Other(_))) && error.to_string() == text
}

// ---------------------------------------------------------------- issue

#[tokio::test]
async fn issue_direct_code_persists_hash_and_normalized_fields() {
    let h = Harness::new();
    let raw: Vec<u8> = (100..132).collect();
    h.random.push(raw.clone());

    let (value, code) = h
        .service
        .issue_direct_code(issue_request())
        .await
        .expect("issue");

    assert_eq!(value, b64url_encode(&raw));
    assert_eq!(value.len(), 43);
    assert_eq!(h.random.draws(), 1);
    let want = AuthorizationCode {
        id: AuthorizationCodeId::from("code-1"),
        code_hash: sha256_b64url(&value),
        authorization_request_id: None,
        account_id: AccountId::from(ACCOUNT),
        client_id: ClientId::from(CLIENT),
        sso_session_id: Some(SessionId::from("sso-1")),
        redirect_uri: REDIRECT.to_owned(),
        granted_scopes: "email openid profile".to_owned(),
        pkce_code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        pkce_code_challenge_method: "S256".to_owned(),
        nonce: String::new(),
        auth_time: datetime!(2026-04-01 11:59:30 UTC),
        expires_at: NOW + Duration::minutes(5),
        consumed_at: None,
        created_at: NOW,
    };
    assert_eq!(code, want);
    assert_eq!(code.auth_time.offset(), offset!(UTC));
    assert_eq!(h.codes.get("code-1"), want);
    assert_eq!(h.log.calls(), [format!("codes.create({})", want.code_hash)]);
}

#[tokio::test]
async fn issue_direct_code_converts_clock_to_utc_and_allows_empty_scopes() {
    let h = Harness::new();
    h.clock.set(datetime!(2026-04-01 19:00 +7));
    let mut req = issue_request();
    req.scopes = Vec::new();
    req.sso_session_id = None;

    let (_, code) = h.service.issue_direct_code(req).await.expect("issue");

    assert_eq!(code.granted_scopes, "");
    assert_eq!(code.sso_session_id, None);
    assert_eq!(code.created_at, NOW);
    assert_eq!(code.created_at.offset(), offset!(UTC));
    assert_eq!(code.expires_at, NOW + config().authorization_code_ttl);
}

#[tokio::test]
async fn issue_direct_code_rejects_missing_identity_before_drawing_random() {
    let h = Harness::new();
    let mutations: [fn(&mut IssueDirectCodeRequest); 3] = [
        |req| req.account_id = AccountId::default(),
        |req| req.client_id = ClientId::default(),
        |req| req.redirect_uri.clear(),
    ];
    for mutate in mutations {
        let mut req = issue_request();
        mutate(&mut req);
        let error = h.service.issue_direct_code(req).await.expect_err("invalid");
        assert!(matches!(error, FlowError::AuthorizationRequestInvalidStage));
        assert_eq!(error.to_string(), "authorization request invalid stage");
    }
    assert_eq!(h.random.draws(), 0);
    assert!(h.log.calls().is_empty());
}

#[tokio::test]
async fn issue_direct_code_propagates_random_and_repository_failures() {
    let h = Harness::new();
    h.random.fail();
    let error = h
        .service
        .issue_direct_code(issue_request())
        .await
        .expect_err("random");
    assert!(matches!(error, FlowError::Random(_)));
    assert_eq!(error.to_string(), "random source exhausted");
    assert!(h.log.calls().is_empty());

    let h = Harness::new();
    h.log.fail("codes.create");
    let error = h
        .service
        .issue_direct_code(issue_request())
        .await
        .expect_err("create");
    assert!(is_repo_other(&error, "codes.create failed"));
}

/// Go `TestIssueDirectCodeKeepsNonceForTheTokenExchange` (AUTH-041): the
/// authorization request's nonce is stored on the code and comes back from
/// the consume step, which hands it to the token service.
#[tokio::test]
async fn issue_direct_code_keeps_nonce_for_the_token_exchange() {
    let h = Harness::new();
    let (value, code) = h
        .service
        .issue_direct_code(IssueDirectCodeRequest {
            nonce: "n-0S6_WzA2Mj".to_owned(),
            ..issue_request()
        })
        .await
        .expect("issue code");
    assert_eq!(code.nonce, "n-0S6_WzA2Mj");
    assert_eq!(h.codes.get("code-1").nonce, "n-0S6_WzA2Mj");

    let consumed = h
        .service
        .consume_authorization_code(ConsumeAuthorizationCodeRequest {
            code_verifier: VERIFIER.to_owned(),
            ..consume_request(&value)
        })
        .await
        .expect("consume code");
    assert_eq!(
        consumed.nonce, "n-0S6_WzA2Mj",
        "expected the code to carry the nonce"
    );
}

// ---------------------------------------------------------------- consume

#[tokio::test]
async fn consume_marks_code_consumed_at_now() {
    let h = Harness::new();
    let stored = stored_code(&h, "code-a", "the-code");
    h.clock.set(NOW + Duration::minutes(1));

    let consumed = h
        .service
        .consume_authorization_code(consume_request("the-code"))
        .await
        .expect("consume");

    let mut want = stored.clone();
    want.consumed_at = Some(NOW + Duration::minutes(1));
    assert_eq!(consumed.code(), &want);
    assert_eq!(consumed.account_id, AccountId::from(ACCOUNT));
    assert_eq!(h.codes.get("code-a"), want);
    assert_eq!(consumed.into_inner(), want);
    assert_eq!(
        h.log.calls(),
        [
            format!("codes.find_by_code_hash({})", stored.code_hash),
            "codes.update(code-a)".to_owned(),
        ]
    );
}

#[tokio::test]
async fn consume_issued_code_round_trip_and_single_use() {
    let h = Harness::new();
    let (value, _) = h
        .service
        .issue_direct_code(issue_request())
        .await
        .expect("issue");

    let request = ConsumeAuthorizationCodeRequest {
        code_verifier: VERIFIER.to_owned(),
        ..consume_request(&value)
    };
    let consumed = h
        .service
        .consume_authorization_code(request.clone())
        .await
        .expect("first consume");
    assert_eq!(consumed.consumed_at, Some(NOW));
    assert_eq!(consumed.granted_scopes, "email openid profile");

    let error = h
        .service
        .consume_authorization_code(request)
        .await
        .expect_err("second consume");
    assert!(matches!(error, FlowError::AuthorizationCodeAlreadyConsumed));
    assert_eq!(error.to_string(), "authorization code already consumed");
}

#[tokio::test]
async fn consume_empty_code_fails_before_lookup() {
    let h = Harness::new();
    let error = h
        .service
        .consume_authorization_code(consume_request(""))
        .await
        .expect_err("empty");
    assert!(matches!(error, FlowError::AuthorizationCodeExpired));
    assert_eq!(error.to_string(), "authorization code expired");
    assert!(h.log.calls().is_empty());
}

#[tokio::test]
async fn consume_unknown_code_returns_repository_not_found() {
    let h = Harness::new();
    let error = h
        .service
        .consume_authorization_code(consume_request("nope"))
        .await
        .expect_err("unknown");
    assert!(matches!(error, FlowError::Repo(RepoError::NotFound)));

    h.log.fail("codes.find_by_code_hash");
    let error = h
        .service
        .consume_authorization_code(consume_request("nope"))
        .await
        .expect_err("db");
    assert!(is_repo_other(&error, "codes.find_by_code_hash failed"));
}

type Fix = fn(&mut AuthorizationCode);

/// Check client, redirect URI, consumed, expired, then PKCE. Each fix reveals the
/// next error, and no failure writes the code.
#[tokio::test]
async fn consume_checks_in_order() {
    let h = Harness::new();
    let mut code = stored_code(&h, "code-a", "the-code");
    code.client_id = ClientId::from("other-client");
    code.redirect_uri = "https://evil.example.com/cb".to_owned();
    code.consumed_at = Some(NOW - Duration::minutes(1));
    code.expires_at = NOW - Duration::seconds(1);
    code.pkce_code_challenge = auth_core::oauth::pkce::s256_challenge(VERIFIER);
    code.pkce_code_challenge_method = "S256".to_owned();
    h.codes.insert(code.clone());

    let steps: [(Fix, &str); 4] = [
        (
            |c| c.client_id = ClientId::from(CLIENT),
            "authorization code client mismatch",
        ),
        (
            |c| c.redirect_uri = REDIRECT.to_owned(),
            "authorization code redirect uri mismatch",
        ),
        (
            |c| c.consumed_at = None,
            "authorization code already consumed",
        ),
        (
            |c| c.expires_at = NOW + Duration::minutes(5),
            "authorization code expired",
        ),
    ];
    for (fix, want) in steps {
        let error = h
            .service
            .consume_authorization_code(consume_request("the-code"))
            .await
            .expect_err(want);
        assert_eq!(error.to_string(), want);
        assert_eq!(h.codes.get("code-a"), code, "no write on failure");
        fix(&mut code);
        h.codes.insert(code.clone());
    }
    let error = h
        .service
        .consume_authorization_code(consume_request("the-code"))
        .await
        .expect_err("missing verifier");
    assert!(matches!(error, FlowError::PkceValidationFailed));
    assert_eq!(h.codes.get("code-a"), code, "no write on PKCE failure");
    h.service
        .consume_authorization_code(ConsumeAuthorizationCodeRequest {
            code_verifier: VERIFIER.to_owned(),
            ..consume_request("the-code")
        })
        .await
        .expect("all checks pass");
    assert_eq!(
        h.log.calls().last().map(String::as_str),
        Some("codes.update(code-a)")
    );
    assert_eq!(
        h.log
            .calls()
            .iter()
            .filter(|c| c.starts_with("codes.update"))
            .count(),
        1
    );
}

#[tokio::test]
async fn consume_error_variants() {
    let h = Harness::new();
    stored_code(&h, "code-a", "the-code");

    let mut req = consume_request("the-code");
    req.client_id = ClientId::from("client-2");
    let error = h
        .service
        .consume_authorization_code(req)
        .await
        .expect_err("client");
    assert!(matches!(error, FlowError::AuthorizationCodeClientMismatch));

    let mut req = consume_request("the-code");
    req.redirect_uri = format!("{REDIRECT}/");
    let error = h
        .service
        .consume_authorization_code(req)
        .await
        .expect_err("redirect");
    assert!(matches!(
        error,
        FlowError::AuthorizationCodeRedirectMismatch
    ));
}

#[tokio::test]
async fn consume_redirect_uri_must_match_exactly() {
    for presented in [
        "https://app.example.com/callback/",
        "https://APP.example.com/callback",
        "https://app.example.com/callback?x=1",
        "https://app.example.com:443/callback",
        "",
    ] {
        let h = Harness::new();
        stored_code(&h, "code-a", "the-code");
        let mut req = consume_request("the-code");
        req.redirect_uri = presented.to_owned();
        let error = h
            .service
            .consume_authorization_code(req)
            .await
            .expect_err(presented);
        assert!(
            matches!(error, FlowError::AuthorizationCodeRedirectMismatch),
            "{presented:?}"
        );
    }
}

/// Go `now.After(expiresAt)`: the expiry instant itself is still valid.
#[tokio::test]
async fn consume_expiry_is_strictly_after() {
    let h = Harness::new();
    let code = stored_code(&h, "code-a", "at-expiry");
    h.clock.set(code.expires_at);
    h.service
        .consume_authorization_code(consume_request("at-expiry"))
        .await
        .expect("at expiry");

    let h = Harness::new();
    let code = stored_code(&h, "code-b", "past-expiry");
    h.clock.set(code.expires_at + Duration::nanoseconds(1));
    let error = h
        .service
        .consume_authorization_code(consume_request("past-expiry"))
        .await
        .expect_err("past expiry");
    assert!(matches!(error, FlowError::AuthorizationCodeExpired));
}

#[tokio::test]
async fn consume_propagates_update_failure() {
    let h = Harness::new();
    stored_code(&h, "code-a", "the-code");
    h.log.fail("codes.update");
    let error = h
        .service
        .consume_authorization_code(consume_request("the-code"))
        .await
        .expect_err("update");
    assert!(is_repo_other(&error, "codes.update failed"));
}

// ---------------------------------------------------------------- consent

#[tokio::test]
async fn has_consent_requires_unrevoked_superset() {
    let h = Harness::new();
    let account = AccountId::from(ACCOUNT);
    let client = ClientId::from(CLIENT);

    assert!(
        !h.service
            .has_consent_for_scopes(&account, &client, &["openid"])
            .await,
        "no grant"
    );

    h.consents.insert(grant("openid profile email"));
    let cases: &[(&[&str], bool)] = &[
        (&["openid"], true),
        (&["email", "openid", "profile"], true),
        (&[" profile ", "openid", "openid"], true),
        (&[], true),
        (&[""], true),
        (&["openid", "offline_access"], false),
        (&["OpenID"], false),
    ];
    for (scopes, want) in cases {
        assert_eq!(
            h.service
                .has_consent_for_scopes(&account, &client, scopes)
                .await,
            *want,
            "{scopes:?}"
        );
    }

    let other = ClientId::from("client-2");
    assert!(
        !h.service
            .has_consent_for_scopes(&account, &other, &["openid"])
            .await
    );

    let mut revoked = grant("openid profile email");
    revoked.revoked_at = Some(NOW);
    h.consents.insert(revoked);
    assert!(
        !h.service
            .has_consent_for_scopes(&account, &client, &["openid"])
            .await,
        "revoked"
    );
    assert!(
        !h.service
            .has_consent_for_scopes(&account, &client, &[] as &[&str])
            .await,
        "revoked beats empty request"
    );
}

#[tokio::test]
async fn has_consent_is_read_only_and_false_on_error() {
    let h = Harness::new();
    let stored = grant("openid profile");
    h.consents.insert(stored.clone());
    let account = AccountId::from(ACCOUNT);
    let client = ClientId::from(CLIENT);

    assert!(
        h.service
            .has_consent_for_scopes(&account, &client, &["openid"])
            .await
    );
    assert_eq!(h.consents.get(ACCOUNT, CLIENT), Some(stored), "unchanged");
    assert!(h.consents.upserts().is_empty());

    h.log.fail("consents.find_by_account_and_client");
    assert!(
        !h.service
            .has_consent_for_scopes(&account, &client, &["openid"])
            .await
    );
}

#[tokio::test]
async fn has_consent_splits_stored_scopes_on_whitespace_only() {
    let h = Harness::new();
    h.consents.insert(grant("openid,profile\temail"));
    let account = AccountId::from(ACCOUNT);
    let client = ClientId::from(CLIENT);
    assert!(
        h.service
            .has_consent_for_scopes(&account, &client, &["openid,profile", "email"])
            .await
    );
    assert!(
        !h.service
            .has_consent_for_scopes(&account, &client, &["openid"])
            .await
    );
}

#[tokio::test]
async fn upsert_consent_creates_new_grant() {
    let h = Harness::new();
    let saved = h
        .service
        .upsert_consent(UpsertConsentRequest {
            account_id: AccountId::from(ACCOUNT),
            client_id: ClientId::from(CLIENT),
            scopes: strings(&["profile", " openid", "profile", ""]),
        })
        .await
        .expect("upsert");

    let sent = ConsentGrant {
        id: ConsentGrantId::default(),
        account_id: AccountId::from(ACCOUNT),
        client_id: ClientId::from(CLIENT),
        granted_scopes: "openid profile".to_owned(),
        granted_at: ZERO_TIME,
        last_used_at: NOW,
        revoked_at: None,
    };
    assert_eq!(h.consents.upserts(), [sent]);
    assert_eq!(saved.id, ConsentGrantId::from("consent-1"));
    assert_eq!(saved.granted_scopes, "openid profile");
    assert_eq!(
        h.log.calls(),
        [
            "consents.find_by_account_and_client(account-1|client-1)",
            "consents.upsert(account-1|client-1)",
        ]
    );
}

#[tokio::test]
async fn upsert_consent_unions_and_keeps_identity() {
    let h = Harness::new();
    let existing = grant("openid profile");
    h.consents.insert(existing.clone());
    h.clock.set(datetime!(2026-04-01 19:00 +7));

    let saved = h
        .service
        .upsert_consent(UpsertConsentRequest {
            account_id: AccountId::from(ACCOUNT),
            client_id: ClientId::from(CLIENT),
            scopes: strings(&["email", "openid"]),
        })
        .await
        .expect("upsert");

    let want = ConsentGrant {
        granted_scopes: "email openid profile".to_owned(),
        last_used_at: NOW,
        ..existing
    };
    assert_eq!(saved, want);
    assert_eq!(saved.last_used_at.offset(), offset!(UTC));
    assert_eq!(h.consents.upserts(), [want]);
}

/// Re-consenting after a revoke clears `revoked_at` and, like Go, keeps the
/// previously granted scopes in the union.
#[tokio::test]
async fn upsert_consent_unrevokes_and_keeps_old_scopes() {
    let h = Harness::new();
    let mut existing = grant("openid trading.read");
    existing.revoked_at = Some(datetime!(2026-03-01 00:00 UTC));
    h.consents.insert(existing.clone());

    let saved = h
        .service
        .upsert_consent(UpsertConsentRequest {
            account_id: AccountId::from(ACCOUNT),
            client_id: ClientId::from(CLIENT),
            scopes: strings(&["email"]),
        })
        .await
        .expect("upsert");

    assert_eq!(saved.revoked_at, None);
    assert_eq!(saved.granted_scopes, "email openid trading.read");
    assert_eq!(saved.id, existing.id);
    assert_eq!(saved.granted_at, existing.granted_at);
    let account = AccountId::from(ACCOUNT);
    let client = ClientId::from(CLIENT);
    assert!(
        h.service
            .has_consent_for_scopes(&account, &client, &["trading.read", "email"])
            .await
    );
}

/// Go treats any lookup error as "no existing grant".
#[tokio::test]
async fn upsert_consent_ignores_lookup_errors() {
    let h = Harness::new();
    h.consents.insert(grant("openid profile"));
    h.log.fail("consents.find_by_account_and_client");

    h.service
        .upsert_consent(UpsertConsentRequest {
            account_id: AccountId::from(ACCOUNT),
            client_id: ClientId::from(CLIENT),
            scopes: strings(&["email"]),
        })
        .await
        .expect("upsert");

    let sent = &h.consents.upserts()[0];
    assert_eq!(sent.id, ConsentGrantId::default());
    assert_eq!(sent.granted_scopes, "email");
    assert_eq!(sent.granted_at, ZERO_TIME);
}

#[tokio::test]
async fn upsert_consent_propagates_save_failure() {
    let h = Harness::new();
    h.log.fail("consents.upsert");
    let error = h
        .service
        .upsert_consent(UpsertConsentRequest {
            account_id: AccountId::from(ACCOUNT),
            client_id: ClientId::from(CLIENT),
            scopes: strings(&["openid"]),
        })
        .await
        .expect_err("upsert");
    assert!(is_repo_other(&error, "consents.upsert failed"));
}

// ---------------------------------------------------------------- sso session

#[tokio::test]
async fn start_sso_session_creates_active_session() {
    let h = Harness::new();
    h.clock.set(datetime!(2026-04-01 19:00 +7));
    let account = AccountId::from(ACCOUNT);

    let created = h
        .service
        .start_sso_session(&account, "email_otp")
        .await
        .expect("start");

    let want = SsoSession {
        id: created.id.clone(),
        account_id: account,
        status: SsoSessionStatus::Active,
        login_method: "email_otp".to_owned(),
        authenticated_at: NOW,
        last_seen_at: NOW,
        expires_at: NOW + Duration::hours(24),
        revoked_at: None,
        created_at: NOW,
        updated_at: NOW,
    };
    assert_eq!(created, want);
    assert!(!created.id.is_empty(), "repository assigns the id");
    assert_eq!(created.status.as_str(), "active");
    assert_eq!(h.sessions.get(created.id.as_str()), want);
}

#[tokio::test]
async fn start_sso_session_propagates_create_failure() {
    let h = Harness::new();
    h.log.fail("sessions.create");
    let error = h
        .service
        .start_sso_session(&AccountId::from(ACCOUNT), "google")
        .await
        .expect_err("create");
    assert!(is_repo_other(&error, "sessions.create failed"));
}

// ---------------------------------------------------------------- logout local

fn logout_fixture() -> Harness {
    let h = Harness::new();
    h.sessions.insert(session("sso-1"));
    h.sessions.insert(session("sso-2"));
    h.chains.insert(chain("chain-1", "sso-1"));
    h.chains.insert(chain("chain-2", "sso-1"));
    h.chains.insert(chain("chain-3", "sso-2"));
    h.tokens.insert(token("token-1", "chain-1"));
    h.tokens.insert(token("token-2", "chain-1"));
    h.tokens.insert(token("token-3", "chain-2"));
    h.tokens.insert(token("token-4", "chain-3"));
    h
}

fn assert_untouched(h: &Harness) {
    for id in ["chain-1", "chain-2", "chain-3"] {
        let chain = h.chains.get(id);
        assert_eq!(chain.status, RefreshTokenChainStatus::Active, "{id}");
        assert_eq!(chain.revoked_at, None, "{id}");
    }
    for id in ["token-1", "token-2", "token-3", "token-4"] {
        assert_eq!(h.tokens.get(id).revoked_at, None, "{id}");
    }
    for id in ["sso-1", "sso-2"] {
        assert_eq!(h.sessions.get(id).status, SsoSessionStatus::Active, "{id}");
    }
}

#[tokio::test]
async fn logout_local_revokes_own_chain_tokens_first() {
    let h = logout_fixture();
    h.service
        .logout_local(&SessionId::from("sso-1"), &ChainId::from("chain-1"))
        .await
        .expect("logout");

    assert_eq!(
        h.log.calls(),
        [
            "chains.find_by_id(chain-1)",
            "tokens.revoke_by_chain_id(chain-1)",
            "chains.revoke_by_id(chain-1)",
        ]
    );
    let revoked = h.chains.get("chain-1");
    assert_eq!(revoked.status, RefreshTokenChainStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(REVOKED_AT));
    for id in ["token-1", "token-2"] {
        assert_eq!(h.tokens.get(id).revoked_at, Some(REVOKED_AT), "{id}");
    }
    // Same session's other chain, other session, and the session itself stay.
    for id in ["chain-2", "chain-3"] {
        assert_eq!(h.chains.get(id).status, RefreshTokenChainStatus::Active);
    }
    for id in ["token-3", "token-4"] {
        assert_eq!(h.tokens.get(id).revoked_at, None, "{id}");
    }
    assert_eq!(h.sessions.get("sso-1").status, SsoSessionStatus::Active);
}

/// Sprint-0 ownership rule: a chain of another session is left alone.
#[tokio::test]
async fn logout_local_ignores_foreign_chain() {
    let h = logout_fixture();
    h.service
        .logout_local(&SessionId::from("sso-2"), &ChainId::from("chain-1"))
        .await
        .expect("logout");
    assert_eq!(h.log.calls(), ["chains.find_by_id(chain-1)"]);
    assert_untouched(&h);

    // A session ID that is a prefix of the owner is still foreign.
    h.chains.insert(chain("chain-9", "sso-10"));
    h.service
        .logout_local(&SessionId::from("sso-1"), &ChainId::from("chain-9"))
        .await
        .expect("logout");
    assert_eq!(
        h.chains.get("chain-9").status,
        RefreshTokenChainStatus::Active
    );
}

#[tokio::test]
async fn logout_local_unknown_chain_or_empty_ids_are_noops() {
    let h = logout_fixture();
    h.service
        .logout_local(&SessionId::from("sso-1"), &ChainId::from("missing"))
        .await
        .expect("unknown chain");
    assert_eq!(h.log.calls(), ["chains.find_by_id(missing)"]);
    h.log.clear();

    h.service
        .logout_local(&SessionId::default(), &ChainId::from("chain-1"))
        .await
        .expect("no session");
    h.service
        .logout_local(&SessionId::from("sso-1"), &ChainId::default())
        .await
        .expect("no chain");
    assert!(h.log.calls().is_empty());
    assert_untouched(&h);
}

/// A chain whose session is unset never matches a caller's session.
#[tokio::test]
async fn logout_local_chain_without_session_is_foreign() {
    let h = logout_fixture();
    h.chains.insert(chain("chain-x", ""));
    h.service
        .logout_local(&SessionId::from("sso-1"), &ChainId::from("chain-x"))
        .await
        .expect("logout");
    assert_eq!(
        h.chains.get("chain-x").status,
        RefreshTokenChainStatus::Active
    );
}

#[tokio::test]
async fn logout_local_propagates_failures_in_order() {
    let h = logout_fixture();
    h.log.fail("chains.find_by_id");
    let error = h
        .service
        .logout_local(&SessionId::from("sso-1"), &ChainId::from("chain-1"))
        .await
        .expect_err("find");
    assert!(is_repo_other(&error, "chains.find_by_id failed"));

    let h = logout_fixture();
    h.log.fail("tokens.revoke_by_chain_id");
    let error = h
        .service
        .logout_local(&SessionId::from("sso-1"), &ChainId::from("chain-1"))
        .await
        .expect_err("tokens");
    assert!(is_repo_other(&error, "tokens.revoke_by_chain_id failed"));
    assert_eq!(
        h.chains.get("chain-1").status,
        RefreshTokenChainStatus::Active,
        "chain not revoked when token revoke fails"
    );

    let h = logout_fixture();
    h.log.fail("chains.revoke_by_id");
    let error = h
        .service
        .logout_local(&SessionId::from("sso-1"), &ChainId::from("chain-1"))
        .await
        .expect_err("chain");
    assert!(is_repo_other(&error, "chains.revoke_by_id failed"));
}

// ---------------------------------------------------------------- logout global

/// Port of Go `TestLogoutGlobalRevokesSessionAndChains`.
#[tokio::test]
async fn logout_global_revokes_session_and_chains() {
    let h = logout_fixture();

    h.service
        .logout_global(&SessionId::from("sso-1"))
        .await
        .expect("logout global");

    let revoked = h.sessions.get("sso-1");
    assert_eq!(revoked.status, SsoSessionStatus::Revoked);
    assert!(revoked.revoked_at.is_some());
    let sibling = h.sessions.get("sso-2");
    assert_eq!(sibling.status, SsoSessionStatus::Active);
    assert_eq!(sibling.revoked_at, None);
    for id in ["chain-1", "chain-2"] {
        let chain = h.chains.get(id);
        assert_eq!(chain.status, RefreshTokenChainStatus::Revoked, "{id}");
        assert!(chain.revoked_at.is_some(), "{id}");
    }
    let other = h.chains.get("chain-3");
    assert_eq!(other.status, RefreshTokenChainStatus::Active);
    assert_eq!(other.revoked_at, None);
    for id in ["token-1", "token-2", "token-3"] {
        assert!(h.tokens.get(id).revoked_at.is_some(), "{id}");
    }
    assert_eq!(h.tokens.get("token-4").revoked_at, None);
}

#[tokio::test]
async fn logout_global_order_session_then_each_chain_tokens_first() {
    let h = logout_fixture();
    let mut done = chain("chain-0", "sso-1");
    done.status = RefreshTokenChainStatus::Revoked;
    done.revoked_at = Some(NOW);
    h.chains.insert(done);

    h.service
        .logout_global(&SessionId::from("sso-1"))
        .await
        .expect("logout global");

    assert_eq!(
        h.log.calls(),
        [
            "sessions.revoke_by_id(sso-1)",
            "chains.list_active_ids_by_sso_session_id(sso-1)",
            "tokens.revoke_by_chain_id(chain-1)",
            "chains.revoke_by_id(chain-1)",
            "tokens.revoke_by_chain_id(chain-2)",
            "chains.revoke_by_id(chain-2)",
        ]
    );
}

#[tokio::test]
async fn logout_global_empty_id_is_noop() {
    let h = logout_fixture();
    h.service
        .logout_global(&SessionId::default())
        .await
        .expect("noop");
    assert!(h.log.calls().is_empty());
    assert_untouched(&h);
}

#[tokio::test]
async fn logout_global_session_without_chains() {
    let h = logout_fixture();
    h.sessions.insert(session("sso-3"));
    h.service
        .logout_global(&SessionId::from("sso-3"))
        .await
        .expect("logout");
    assert_eq!(h.sessions.get("sso-3").status, SsoSessionStatus::Revoked);
    for id in ["chain-1", "chain-2", "chain-3"] {
        assert_eq!(h.chains.get(id).status, RefreshTokenChainStatus::Active);
    }
}

#[tokio::test]
async fn logout_global_stops_at_first_failure() {
    let h = logout_fixture();
    h.log.fail("sessions.revoke_by_id");
    let error = h
        .service
        .logout_global(&SessionId::from("sso-1"))
        .await
        .expect_err("session");
    assert!(is_repo_other(&error, "sessions.revoke_by_id failed"));
    assert_eq!(h.log.calls(), ["sessions.revoke_by_id(sso-1)"]);

    let h = logout_fixture();
    h.log.fail("chains.list_active_ids_by_sso_session_id");
    let error = h
        .service
        .logout_global(&SessionId::from("sso-1"))
        .await
        .expect_err("list");
    assert!(is_repo_other(
        &error,
        "chains.list_active_ids_by_sso_session_id failed"
    ));
    assert_eq!(h.sessions.get("sso-1").status, SsoSessionStatus::Revoked);

    let h = logout_fixture();
    h.log.fail("tokens.revoke_by_chain_id");
    let error = h
        .service
        .logout_global(&SessionId::from("sso-1"))
        .await
        .expect_err("tokens");
    assert!(is_repo_other(&error, "tokens.revoke_by_chain_id failed"));
    assert_eq!(
        h.log.calls().last().map(String::as_str),
        Some("tokens.revoke_by_chain_id(chain-1)")
    );
    assert_eq!(
        h.chains.get("chain-1").status,
        RefreshTokenChainStatus::Active
    );
}

#[test]
fn consume_request_debug_redacts_code() {
    let rendered = format!("{:?}", consume_request("super-secret-code"));
    assert!(!rendered.contains("super-secret-code"));
    assert!(rendered.contains("[redacted]"));
}
