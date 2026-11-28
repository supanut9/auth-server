//! Port of `internal/application/token/service_test.go`, plus refresh-grant
//! check-order and rotation tests.

mod token_support;

use std::sync::atomic::Ordering;

use auth_core::crypto::sha256_b64url;
use auth_core::domain::{
    AccessTokenStatus, AccountId, ChainId, ClientId, RefreshTokenChainStatus, Scopes, SessionId,
    SsoSession, SsoSessionStatus,
};
use auth_core::ports::RepoError;
use auth_core::token::{
    ClientCredentialsTokenRequest, IssuedTokens, RefreshTokenRequest, TokenError, UserTokenRequest,
    client_credentials_scope_permitted, hash_refresh_token,
};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use token_support::{Harness, MemorySessions, NOW, SESSION_ID, TestIds, config};

const GRACE: Duration = Duration::seconds(60);

fn user_request() -> UserTokenRequest {
    UserTokenRequest {
        account_id: AccountId::new("account-123"),
        client_id: ClientId::new("trading-web"),
        scope: vec!["openid".into(), "profile".into(), "trading.read".into()],
        sso_session_id: SessionId::new(SESSION_ID),
        device_session_id: "device-123".into(),
        auth_time: datetime!(2026-04-01 11:55 UTC),
        nonce: String::new(),
        email: "user@example.com".into(),
        email_verified: true,
        name: "Trader".into(),
        picture: "https://example.com/avatar.png".into(),
    }
}

fn refresh_request(client: &str, token: &str) -> RefreshTokenRequest {
    RefreshTokenRequest {
        client_id: ClientId::new(client),
        refresh_token: token.to_owned(),
    }
}

async fn issue(h: &Harness) -> IssuedTokens {
    h.service
        .issue_user_tokens(user_request())
        .await
        .expect("issue user tokens")
}

async fn refresh(h: &Harness, client: &str, token: &str) -> Result<IssuedTokens, TokenError> {
    h.service
        .refresh_user_tokens(refresh_request(client, token))
        .await
}

fn refresh_value(issued: &IssuedTokens) -> &str {
    issued.refresh_token.as_deref().expect("refresh token")
}

fn chain_id(h: &Harness) -> ChainId {
    h.chains.only().id
}

/// Marks the issued refresh token as used `ago` before now.
fn mark_used(h: &Harness, issued: &IssuedTokens, ago: Duration) {
    h.refresh
        .edit_by_hash(&sha256_b64url(refresh_value(issued)), |token| {
            token.used_at = Some(NOW - ago);
        });
}

fn assert_err(result: Result<IssuedTokens, TokenError>, want: &str) {
    match result {
        Ok(_) => panic!("expected error {want:?}, got tokens"),
        Err(error) => assert_eq!(error.to_string(), want),
    }
}

fn assert_not_found(result: Result<IssuedTokens, TokenError>) {
    match result {
        Err(TokenError::Repo(RepoError::NotFound)) => {}
        other => panic!("expected repo NotFound, got {other:?}"),
    }
}

const REUSE: &str = "refresh token reuse detected";
const REVOKED: &str = "refresh token revoked";
const EXPIRED: &str = "refresh token expired";
const MISMATCH: &str = "refresh token client mismatch";
const CHAIN_INACTIVE: &str = "refresh token chain inactive";
const SESSION_INACTIVE: &str = "refresh token session inactive";

// ---- Go service_test.go ----

#[tokio::test]
async fn issue_user_tokens_and_rotate_refresh() {
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    assert!(!issued.access_token.is_empty());
    assert!(issued.id_token.is_some());
    assert!(issued.refresh_token.is_some());
    assert_eq!(h.access.all().len(), 1);

    let refreshed = refresh(&h, "trading-web", refresh_value(&issued))
        .await
        .expect("refresh");
    assert!(!refreshed.access_token.is_empty());
    assert!(refreshed.refresh_token.is_some());

    // No grace: a second presentation is theft.
    assert_err(
        refresh(&h, "trading-web", refresh_value(&issued)).await,
        REUSE,
    );
    let chain = h.chains.only();
    assert_eq!(chain.status, RefreshTokenChainStatus::Revoked);
    assert!(chain.revoked_at.is_some());
    assert!(h.refresh.all().iter().all(|t| t.revoked_at.is_some()));
    // The sibling minted by the first rotation is dead too.
    assert_err(
        refresh(&h, "trading-web", refresh_value(&refreshed)).await,
        REVOKED,
    );
}

#[tokio::test]
async fn refresh_requires_active_sso_session() {
    let at = |expires_at: OffsetDateTime| MemorySessions::active(SESSION_ID, expires_at);
    let cases: Vec<(&str, Option<SsoSession>, Option<&str>)> = vec![
        ("active", Some(at(NOW + Duration::hours(1))), None),
        (
            "revoked status",
            Some(SsoSession {
                status: SsoSessionStatus::Revoked,
                ..at(NOW + Duration::hours(1))
            }),
            Some(SESSION_INACTIVE),
        ),
        (
            "unknown status",
            Some(SsoSession {
                status: SsoSessionStatus::parse(""),
                ..at(NOW + Duration::hours(1))
            }),
            Some(SESSION_INACTIVE),
        ),
        (
            "revocation timestamp",
            Some(SsoSession {
                revoked_at: Some(NOW),
                ..at(NOW + Duration::hours(1))
            }),
            Some(SESSION_INACTIVE),
        ),
        (
            "expired",
            Some(at(NOW - Duration::minutes(1))),
            Some(SESSION_INACTIVE),
        ),
        ("at expiry", Some(at(NOW)), Some(SESSION_INACTIVE)),
        ("missing", None, Some("record not found")),
    ];
    for (name, session, want) in cases {
        let h = Harness::standard(Duration::ZERO);
        let issued = h
            .service
            .issue_user_tokens(UserTokenRequest {
                scope: Vec::new(),
                device_session_id: String::new(),
                email: String::new(),
                name: String::new(),
                picture: String::new(),
                email_verified: false,
                auth_time: NOW,
                ..user_request()
            })
            .await
            .expect("issue");
        match session {
            Some(session) => h.sessions.put(session),
            None => h.sessions.remove(SESSION_ID),
        }
        let result = refresh(&h, "trading-web", refresh_value(&issued)).await;
        match want {
            None => {
                let refreshed = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(!refreshed.access_token.is_empty(), "{name}");
                assert!(refreshed.refresh_token.is_some(), "{name}");
            }
            Some(want) => {
                match &result {
                    Err(error) => assert_eq!(error.to_string(), want, "{name}"),
                    Ok(_) => panic!("{name}: expected {want}"),
                }
                if name == "missing" {
                    assert_not_found(result);
                }
                assert_eq!(h.access.all().len(), 1, "{name}: no new audit row");
                assert_eq!(h.refresh.all().len(), 1, "{name}: no new refresh token");
                assert!(
                    h.refresh.all()[0].used_at.is_none(),
                    "{name}: token not consumed"
                );
                assert_eq!(h.signer.recorded().len(), 2, "{name}: nothing signed");
            }
        }
    }
}

#[tokio::test]
async fn refresh_reuse_within_grace_succeeds() {
    let h = Harness::standard(GRACE);
    let issued = issue(&h).await;

    let first = refresh(&h, "trading-web", refresh_value(&issued))
        .await
        .expect("first refresh");
    let original = h.refresh.by_hash(&sha256_b64url(refresh_value(&issued)));
    assert_eq!(original.used_at, Some(NOW));
    let first_replacement = original.replaced_by_token_id.clone().expect("replaced_by");

    // Concurrent retry within the grace window: a distinct sibling.
    h.clock.advance(Duration::seconds(30));
    let second = refresh(&h, "trading-web", refresh_value(&issued))
        .await
        .expect("grace-window refresh");
    assert!(!second.access_token.is_empty());
    assert_ne!(second.refresh_token, first.refresh_token);

    // The presented token still records only its first rotation.
    let original = h.refresh.by_hash(&sha256_b64url(refresh_value(&issued)));
    assert_eq!(original.used_at, Some(NOW));
    assert_eq!(original.replaced_by_token_id, Some(first_replacement));

    // Both siblings stay valid and the chain is active.
    assert_eq!(h.chains.only().status, RefreshTokenChainStatus::Active);
    refresh(&h, "trading-web", refresh_value(&second))
        .await
        .expect("grace sibling refreshes");
    refresh(&h, "trading-web", refresh_value(&first))
        .await
        .expect("first sibling refreshes");
}

#[tokio::test]
async fn issue_client_credentials_token() {
    let h = Harness::standard(Duration::ZERO);
    let issued = h
        .service
        .issue_client_credentials_token(ClientCredentialsTokenRequest {
            client_id: ClientId::new("market-data-worker"),
            scope: vec!["trading.read".into()],
        })
        .await
        .expect("client credentials");
    assert!(!issued.access_token.is_empty());
    assert!(issued.id_token.is_none());
    assert!(issued.refresh_token.is_none());
    assert!(issued.id_token_expires_at.is_none());
    assert!(issued.refresh_token_expires_at.is_none());
    assert_eq!(issued.token_type, "Bearer");
    assert_eq!(issued.expires_in, 600);
    assert_eq!(issued.scope, "trading.read");

    assert_eq!(
        h.signer.claims_json(0),
        r#"{"aud":"platform-api","client_id":"market-data-worker","exp":1775045400,"iat":1775044800,"iss":"http://localhost:8050","jti":"id-1","scope":"trading.read","sub":"market-data-worker"}"#
    );
    let records = h.access.all();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.jti, "id-1");
    assert_eq!(record.sid, "");
    assert_eq!(record.account_id, None);
    assert_eq!(record.sso_session_id, None);
    assert_eq!(record.client_id.as_str(), "market-data-worker");
    assert_eq!(record.audience, "platform-api");
    assert_eq!(record.scope, "trading.read");
    assert_eq!(record.issued_at, NOW);
    assert_eq!(record.expires_at, NOW + Duration::minutes(10));
    assert_eq!(record.status, AccessTokenStatus::Active);
    assert!(h.chains.chains.lock().unwrap().is_empty());
    assert!(h.refresh.all().is_empty());
}

// ---- issuance details ----

#[tokio::test]
async fn issue_user_tokens_claims_and_rows() {
    let h = Harness::standard(Duration::ZERO);
    let issued = h
        .service
        .issue_user_tokens(UserTokenRequest {
            scope: vec![
                " profile".into(),
                "openid".into(),
                "openid".into(),
                String::new(),
                "trading.read".into(),
            ],
            ..user_request()
        })
        .await
        .expect("issue");

    let recorded = h.signer.recorded();
    assert_eq!(recorded.len(), 2, "access then id token");
    assert_eq!(
        h.signer.claims_json(0),
        r#"{"aud":"platform-api","client_id":"trading-web","exp":1775045400,"iat":1775044800,"iss":"http://localhost:8050","jti":"id-1","scope":"openid profile trading.read","sid":"sso-123","sub":"account-123"}"#
    );
    assert_eq!(
        h.signer.claims_json(1),
        r#"{"aud":"trading-web","auth_time":1775044500,"azp":"trading-web","email":"user@example.com","email_verified":true,"exp":1775045400,"iat":1775044800,"iss":"http://localhost:8050","name":"Trader","picture":"https://example.com/avatar.png","sid":"sso-123","sub":"account-123"}"#
    );
    for absent in ["nonce", "at_hash"] {
        assert!(!recorded[1].contains_key(absent), "id token has {absent}");
    }

    assert_eq!(issued.token_type, "Bearer");
    assert_eq!(issued.expires_in, 600);
    assert_eq!(issued.scope, "openid profile trading.read");
    assert_eq!(issued.access_token_expires_at, NOW + Duration::minutes(10));
    assert_eq!(
        issued.id_token_expires_at,
        Some(NOW + Duration::minutes(10))
    );
    assert_eq!(
        issued.refresh_token_expires_at,
        Some(NOW + Duration::days(30))
    );
    let value = refresh_value(&issued);
    assert_eq!(value.len(), 43);

    let chain = h.chains.only();
    assert_eq!(chain.id.as_str(), "id-2", "chain id is the second ID");
    assert_eq!(chain.account_id.as_str(), "account-123");
    assert_eq!(chain.client_id.as_str(), "trading-web");
    assert_eq!(chain.sso_session_id.as_str(), SESSION_ID);
    assert_eq!(chain.scope, "openid profile trading.read");
    assert_eq!(chain.device_session_id, "device-123");
    assert_eq!(chain.status, RefreshTokenChainStatus::Active);
    assert_eq!(chain.absolute_expires_at, NOW + Duration::days(30));
    assert_eq!(chain.inactive_expires_at, NOW + Duration::days(7));
    assert_eq!(chain.last_used_at, NOW);
    assert_eq!(chain.created_at, NOW);
    assert_eq!(chain.updated_at, NOW);
    assert_eq!(chain.revoked_at, None);

    let tokens = h.refresh.all();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].refresh_token_chain_id, chain.id);
    assert_eq!(tokens[0].token_hash, sha256_b64url(value));
    assert_eq!(tokens[0].token_hash, hash_refresh_token(value).unwrap());
    assert_eq!(tokens[0].issued_at, NOW);
    assert_eq!(tokens[0].expires_at, NOW + Duration::days(30));
    assert_eq!(tokens[0].used_at, None);

    let records = h.access.all();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.jti, "id-1");
    assert_eq!(record.sid, SESSION_ID);
    assert_eq!(record.account_id.as_ref().unwrap().as_str(), "account-123");
    assert_eq!(record.sso_session_id.as_ref().unwrap().as_str(), SESSION_ID);
    assert_eq!(record.audience, "platform-api");
    assert_eq!(record.scope, "openid profile trading.read");
    assert_eq!(record.expires_at, NOW + Duration::minutes(10));
    assert_eq!(record.status, AccessTokenStatus::Active);
    assert_eq!(record.created_at, NOW);
}

/// Go `TestIDTokenEchoesNonce` (AUTH-041, OIDC Core 3.1.3.6): a nonce sent on
/// the authorization request comes back in the ID token. Without one the claim
/// is omitted, not `""`; it never reaches the access token.
#[tokio::test]
async fn id_token_echoes_nonce() {
    for (name, nonce) in [("with nonce", "n-0S6_WzA2Mj"), ("without nonce", "")] {
        let h = Harness::standard(Duration::ZERO);
        h.service
            .issue_user_tokens(UserTokenRequest {
                scope: vec!["openid".into()],
                nonce: nonce.to_owned(),
                ..user_request()
            })
            .await
            .unwrap_or_else(|e| panic!("{name}: issue user tokens: {e}"));

        let recorded = h.signer.recorded();
        assert_eq!(recorded.len(), 2, "{name}: access then id token");
        assert!(
            !recorded[0].contains_key("nonce"),
            "{name}: nonce must stay out of the access token"
        );
        if nonce.is_empty() {
            assert!(
                !recorded[1].contains_key("nonce"),
                "{name}: expected no nonce claim, got {:?}",
                recorded[1].get("nonce")
            );
            continue;
        }
        assert_eq!(recorded[1]["nonce"], nonce, "{name}");
        // Sorted like Go's map marshalling: "nonce" lands between "name" and "picture".
        assert_eq!(
            h.signer.claims_json(1),
            r#"{"aud":"trading-web","auth_time":1775044500,"azp":"trading-web","email":"user@example.com","email_verified":true,"exp":1775045400,"iat":1775044800,"iss":"http://localhost:8050","name":"Trader","nonce":"n-0S6_WzA2Mj","picture":"https://example.com/avatar.png","sid":"sso-123","sub":"account-123"}"#,
            "{name}"
        );
    }
}

#[tokio::test]
async fn id_and_refresh_token_issued_without_openid_or_offline_access() {
    let h = Harness::standard(Duration::ZERO);
    let issued = h
        .service
        .issue_user_tokens(UserTokenRequest {
            scope: vec!["trading.read".into()],
            email_verified: false,
            ..user_request()
        })
        .await
        .expect("issue");
    assert!(issued.id_token.is_some());
    assert!(issued.refresh_token.is_some());
    // email_verified is copied from the request (the handler passes true).
    assert_eq!(h.signer.recorded()[1]["email_verified"], false);
}

#[tokio::test]
async fn expires_in_truncates_like_go() {
    let mut cfg = config(Duration::ZERO);
    cfg.access_token_ttl = Duration::milliseconds(90_900);
    let h = Harness::new(cfg, TestIds::default());
    let issued = h
        .service
        .issue_client_credentials_token(ClientCredentialsTokenRequest {
            client_id: ClientId::new("worker"),
            scope: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(issued.expires_in, 90);
    assert_eq!(issued.scope, "");
    assert_eq!(h.signer.recorded()[0]["exp"], NOW.unix_timestamp() + 90);
}

#[tokio::test]
async fn id_token_issuer_trims_trailing_slashes() {
    let mut cfg = config(Duration::ZERO);
    cfg.issuer = "https://auth.example.com///".into();
    let h = Harness::new(cfg, TestIds::default());
    h.service.issue_user_tokens(user_request()).await.unwrap();
    let claims = h.signer.recorded();
    assert_eq!(claims[0]["iss"], "https://auth.example.com///");
    assert_eq!(claims[1]["iss"], "https://auth.example.com");
}

#[tokio::test]
async fn signer_and_random_failures_propagate() {
    let h = Harness::standard(Duration::ZERO);
    h.signer.fail.store(true, Ordering::SeqCst);
    let error = h
        .service
        .issue_user_tokens(user_request())
        .await
        .unwrap_err();
    assert!(matches!(error, TokenError::Signing(_)), "{error:?}");
    assert_eq!(error.to_string(), "signer unavailable");
    assert!(h.chains.chains.lock().unwrap().is_empty());

    h.signer.fail.store(false, Ordering::SeqCst);
    h.random.fail.store(true, Ordering::SeqCst);
    let error = h
        .service
        .issue_user_tokens(user_request())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "generate opaque token: entropy unavailable"
    );
    assert!(h.chains.chains.lock().unwrap().is_empty());
    assert!(h.access.all().is_empty());
}

// ---- refresh success behavior ----

#[tokio::test]
async fn refresh_rotates_and_slides_inactivity() {
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    let chain_before = h.chains.only();

    let later = NOW + Duration::minutes(5);
    h.clock.set(later);
    let refreshed = refresh(&h, "trading-web", refresh_value(&issued))
        .await
        .expect("refresh");

    assert!(refreshed.id_token.is_none());
    assert!(refreshed.id_token_expires_at.is_none());
    assert_eq!(refreshed.token_type, "Bearer");
    assert_eq!(refreshed.expires_in, 600);
    assert_eq!(refreshed.scope, "openid profile trading.read");
    assert_eq!(
        refreshed.access_token_expires_at,
        later + Duration::minutes(10)
    );
    assert_eq!(
        refreshed.refresh_token_expires_at,
        Some(chain_before.absolute_expires_at)
    );
    assert_eq!(h.signer.recorded().len(), 3);
    assert_eq!(
        h.signer.claims_json(2),
        format!(
            r#"{{"aud":"platform-api","client_id":"trading-web","exp":{},"iat":{},"iss":"http://localhost:8050","jti":"id-3","scope":"openid profile trading.read","sid":"sso-123","sub":"account-123"}}"#,
            later.unix_timestamp() + 600,
            later.unix_timestamp()
        )
    );

    let tokens = h.refresh.all();
    assert_eq!(tokens.len(), 2);
    let (old, new) = (&tokens[0], &tokens[1]);
    assert_eq!(old.used_at, Some(later));
    assert_eq!(old.replaced_by_token_id.as_ref(), Some(&new.id));
    assert_eq!(new.token_hash, sha256_b64url(refresh_value(&refreshed)));
    assert_eq!(new.issued_at, later);
    assert_eq!(new.expires_at, chain_before.absolute_expires_at);
    assert_eq!(new.refresh_token_chain_id, chain_before.id);

    let chain = h.chains.only();
    assert_eq!(chain.last_used_at, later);
    assert_eq!(chain.inactive_expires_at, later + Duration::days(7));
    assert_eq!(chain.absolute_expires_at, chain_before.absolute_expires_at);

    let records = h.access.all();
    assert_eq!(records.len(), 2);
    let audit = &records[1];
    assert_eq!(audit.jti, "id-3");
    assert_eq!(audit.scope, "", "Go audits refresh with an empty scope");
    assert_eq!(audit.sid, SESSION_ID);
    assert_eq!(audit.account_id.as_ref().unwrap().as_str(), "account-123");
    assert_eq!(audit.issued_at, later);
}

#[tokio::test]
async fn refresh_scope_comes_from_chain_split_on_whitespace() {
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    let id = chain_id(&h);
    h.chains.edit(&id, |c| c.scope = "b,a  a\tc".into());
    let refreshed = refresh(&h, "trading-web", refresh_value(&issued))
        .await
        .unwrap();
    assert_eq!(refreshed.scope, "a b,a c");
    assert_eq!(
        refreshed.scope,
        Scopes::parse_whitespace("b,a  a\tc").to_string()
    );
}

// ---- refresh check order ----

#[tokio::test]
async fn empty_and_unknown_refresh_tokens() {
    let h = Harness::standard(Duration::ZERO);
    assert_err(
        refresh(&h, "trading-web", "").await,
        "hash opaque token: empty token",
    );
    assert_not_found(refresh(&h, "trading-web", "unknown").await);
}

#[tokio::test]
async fn revoked_checked_before_reuse() {
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    mark_used(&h, &issued, Duration::hours(1));
    h.refresh
        .edit_by_hash(&sha256_b64url(refresh_value(&issued)), |t| {
            t.revoked_at = Some(NOW);
        });
    assert_err(
        refresh(&h, "trading-web", refresh_value(&issued)).await,
        REVOKED,
    );
    assert_eq!(h.chains.only().status, RefreshTokenChainStatus::Active);
}

#[tokio::test]
async fn reuse_detected_before_client_mismatch_and_revokes_chain() {
    let h = Harness::standard(GRACE);
    let issued = issue(&h).await;
    // A live sibling on the same chain.
    let sibling = refresh(&h, "trading-web", refresh_value(&issued))
        .await
        .unwrap();
    h.clock.advance(Duration::seconds(61));

    assert_err(
        refresh(&h, "other-client", refresh_value(&issued)).await,
        REUSE,
    );
    let chain = h.chains.only();
    assert_eq!(chain.status, RefreshTokenChainStatus::Revoked);
    assert!(chain.revoked_at.is_some());
    assert!(h.refresh.all().iter().all(|t| t.revoked_at.is_some()));
    assert_err(
        refresh(&h, "trading-web", refresh_value(&sibling)).await,
        REVOKED,
    );
}

#[tokio::test]
async fn reuse_grace_boundary() {
    // Exactly at the grace limit: still a sibling (`>` not `>=`).
    let h = Harness::standard(GRACE);
    let issued = issue(&h).await;
    mark_used(&h, &issued, GRACE);
    refresh(&h, "trading-web", refresh_value(&issued))
        .await
        .expect("at grace limit");

    // One second past it: theft.
    let h = Harness::standard(GRACE);
    let issued = issue(&h).await;
    mark_used(&h, &issued, GRACE + Duration::seconds(1));
    assert_err(
        refresh(&h, "trading-web", refresh_value(&issued)).await,
        REUSE,
    );

    // A negative grace disables the window.
    let h = Harness::standard(Duration::seconds(-5));
    let issued = issue(&h).await;
    mark_used(&h, &issued, Duration::ZERO);
    assert_err(
        refresh(&h, "trading-web", refresh_value(&issued)).await,
        REUSE,
    );
}

#[tokio::test]
async fn reuse_within_grace_still_runs_later_checks() {
    let h = Harness::standard(GRACE);
    let issued = issue(&h).await;
    mark_used(&h, &issued, Duration::seconds(10));
    assert_err(
        refresh(&h, "other-client", refresh_value(&issued)).await,
        MISMATCH,
    );
    assert_eq!(h.chains.only().status, RefreshTokenChainStatus::Active);
}

#[tokio::test]
async fn token_expiry_checked_before_chain_load() {
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    let id = chain_id(&h);
    let hash = sha256_b64url(refresh_value(&issued));

    // now == expires_at is not expired (Go `now.After`).
    h.refresh.edit_by_hash(&hash, |t| t.expires_at = NOW);
    h.sessions.remove(SESSION_ID);
    assert_not_found(refresh(&h, "trading-web", refresh_value(&issued)).await);

    h.refresh
        .edit_by_hash(&hash, |t| t.expires_at = NOW - Duration::seconds(1));
    h.chains.remove(&id);
    assert_err(
        refresh(&h, "other-client", refresh_value(&issued)).await,
        EXPIRED,
    );
}

#[tokio::test]
async fn missing_chain_is_a_repository_error() {
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    h.chains.remove(&chain_id(&h));
    assert_not_found(refresh(&h, "trading-web", refresh_value(&issued)).await);
}

#[tokio::test]
async fn client_mismatch_before_chain_inactive() {
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    let id = chain_id(&h);
    h.chains.edit(&id, |c| {
        c.status = RefreshTokenChainStatus::Revoked;
        c.absolute_expires_at = NOW - Duration::days(1);
    });
    assert_err(
        refresh(&h, "other-client", refresh_value(&issued)).await,
        MISMATCH,
    );
    assert_err(
        refresh(&h, "trading-web", refresh_value(&issued)).await,
        CHAIN_INACTIVE,
    );
}

#[tokio::test]
async fn chain_inactive_variants() {
    for status in [
        RefreshTokenChainStatus::Revoked,
        RefreshTokenChainStatus::parse(""),
        RefreshTokenChainStatus::parse("suspended"),
    ] {
        let h = Harness::standard(Duration::ZERO);
        let issued = issue(&h).await;
        h.chains.edit(&chain_id(&h), |c| c.status = status.clone());
        assert_err(
            refresh(&h, "trading-web", refresh_value(&issued)).await,
            CHAIN_INACTIVE,
        );
    }
    let h = Harness::standard(Duration::ZERO);
    let issued = issue(&h).await;
    h.chains.edit(&chain_id(&h), |c| c.revoked_at = Some(NOW));
    assert_err(
        refresh(&h, "trading-web", refresh_value(&issued)).await,
        CHAIN_INACTIVE,
    );
}

#[tokio::test]
async fn absolute_and_inactive_expiry() {
    type Edit = fn(&mut auth_core::domain::RefreshTokenChain);
    let cases: [(&str, Edit, Option<&str>); 4] = [
        (
            "absolute passed",
            |c| c.absolute_expires_at = NOW - Duration::seconds(1),
            Some(EXPIRED),
        ),
        (
            "inactive passed",
            |c| c.inactive_expires_at = NOW - Duration::seconds(1),
            Some(EXPIRED),
        ),
        ("absolute at now", |c| c.absolute_expires_at = NOW, None),
        ("inactive at now", |c| c.inactive_expires_at = NOW, None),
    ];
    for (name, edit, want) in cases {
        let h = Harness::standard(Duration::ZERO);
        let issued = issue(&h).await;
        h.chains.edit(&chain_id(&h), edit);
        // A revoked session would fail later; expiry must win.
        if want.is_some() {
            h.sessions.put(SsoSession {
                status: SsoSessionStatus::Revoked,
                ..MemorySessions::active(SESSION_ID, NOW + Duration::hours(1))
            });
        }
        let result = refresh(&h, "trading-web", refresh_value(&issued)).await;
        match want {
            Some(want) => assert_err(result, want),
            None => {
                result.unwrap_or_else(|e| panic!("{name}: {e}"));
            }
        }
    }
}

#[tokio::test]
async fn inactivity_window_slides_on_each_refresh() {
    let h = Harness::standard(Duration::ZERO);
    h.sessions
        .put(MemorySessions::active(SESSION_ID, NOW + Duration::days(60)));
    let mut current = issue(&h).await;
    // Six days apart, three times: past the original 7-day inactive limit but
    // each refresh slides it.
    for _ in 0..3 {
        h.clock.advance(Duration::days(6));
        current = refresh(&h, "trading-web", refresh_value(&current))
            .await
            .expect("slide");
    }
    // Day 18 (inactive limit now day 25); day 26 is still inside the
    // 30-day absolute lifetime, so only the inactive window rejects it.
    h.clock.advance(Duration::days(8));
    assert_err(
        refresh(&h, "trading-web", refresh_value(&current)).await,
        EXPIRED,
    );
}

#[tokio::test]
async fn absolute_lifetime_caps_rotation() {
    let h = Harness::standard(Duration::ZERO);
    h.sessions
        .put(MemorySessions::active(SESSION_ID, NOW + Duration::days(90)));
    let mut current = issue(&h).await;
    for _ in 0..5 {
        h.clock.advance(Duration::days(6));
        current = refresh(&h, "trading-web", refresh_value(&current))
            .await
            .expect("rotate");
        assert_eq!(
            current.refresh_token_expires_at,
            Some(NOW + Duration::days(30))
        );
    }
    // Day 30 + 1s: the token itself (expires_at = absolute) is expired.
    h.clock.set(NOW + Duration::days(30) + Duration::seconds(1));
    assert_err(
        refresh(&h, "trading-web", refresh_value(&current)).await,
        EXPIRED,
    );
}

// ---- client_credentials scope rule (router.go handleClientCredentials) ----

#[test]
fn client_credentials_scope_rules() {
    let allowed = Scopes::parse("trading.read trading.write openid profile email");
    let cases = [
        ("", true),
        ("trading.read", true),
        ("trading.write,trading.read", true),
        ("trading.admin", false),
        ("openid", false),
        ("email trading.read", false),
        ("profile", false),
    ];
    for (requested, want) in cases {
        assert_eq!(
            client_credentials_scope_permitted(&Scopes::parse(requested), &allowed),
            want,
            "{requested:?}"
        );
    }
    assert!(!client_credentials_scope_permitted(
        &Scopes::parse("a"),
        &Scopes::parse("")
    ));
}

#[test]
fn debug_output_redacts_secrets() {
    let request = refresh_request("c", "super-secret-refresh");
    assert!(!format!("{request:?}").contains("super-secret-refresh"));
    let user = format!("{:?}", user_request());
    assert!(!user.contains("user@example.com"));
    assert!(!user.contains("Trader"));
}
