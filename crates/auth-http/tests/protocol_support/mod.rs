//! In-memory [`AppState`] fixture for the protocol handler tests: fake
//! repositories with failure switches, a settable clock, a scripted random
//! source and the real `JwksManager` loaded from the test-only key in
//! `testdata/golden/keys/`.

#![allow(dead_code)]

#[path = "../common/cleanup.rs"]
mod cleanup;
#[path = "../common/otp_rate_limit.rs"]
mod otp_rate_limit;

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use auth_adapters::{config::Config, jwks::JwksManager};
use auth_core::{
    crypto::{b64url_encode, sha256_b64url},
    domain::{
        AccessTokenRecord, Account, AccountId, AccountProvider, AccountStatus, AuthorizationCode,
        ChainId, ClientId, ClientType, ConsentGrant, OAuthClient, OtpChallenge, OtpChallengeId,
        RefreshToken, RefreshTokenChain, RefreshTokenChainStatus, SessionId, SsoSession,
        SsoSessionStatus,
    },
    flow::{FlowConfig, FlowPorts, FlowService, IssueDirectCodeRequest},
    identity::{FixedOtpCodeGenerator, IdentityConfig, IdentityDeps, IdentityService},
    oauth::{AuthorizeRequestValidator, envelope::EnvelopeSigner},
    ports::{
        AccessTokenRepository, AccountProviderRepository, AccountRepository,
        AuthorizationCodeRepository, Clock, ConsentGrantRepository, IdGenerator, JwksProvider,
        JwtError, OAuthClientRepository, OtpChallengeRepository, RandomError, RandomSource,
        ReadinessProbe, RefreshTokenChainRepository, RefreshTokenRepository, RepoError, RepoResult,
        RepositoryJtiStore, SignedStateJtiRepository, SsoSessionRepository, SupportAccountSummary,
        SupportRepository,
    },
    token::{TokenConfig, TokenService, TokenServiceDeps},
};
use auth_http::{
    AppState, GlobalLayers,
    cookies::CookiePolicy,
    handlers::protocol::{self, OtpHintSource},
    middleware::{AccessLog, SupportAuth},
    routing::GinRouter,
};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode},
};
use secrecy::SecretString;
use serde_json::Value;
use time::{Duration, OffsetDateTime, macros::datetime};
use tower::ServiceExt;

pub const ISSUER: &str = "https://auth.example";
pub const AUDIENCE: &str = "platform-api";
pub const UI: &str = "https://auth-ui.example";
pub const SUPPORT_TOKEN: &str = "support-secret";
pub const HINT_EMAIL: &str = "ci@example.com";
/// The fixture's start time.
pub const NOW: OffsetDateTime = datetime!(2026-11-26 10:00:00.5 UTC);

pub const BROWSER: &str = "browser-web";
pub const WORKER: &str = "worker-svc";
pub const WORKER_SECRET: &str = "worker-secret";
pub const LEGACY: &str = "legacy-svc";
pub const LEGACY_SECRET: &str = "legacy plaintext";

pub fn golden(name: &str) -> Value {
    let path = format!(
        "{}/../../testdata/golden/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn key(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../testdata/golden/keys/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap()
}

pub fn config_with(overrides: &[(&str, &str)]) -> Config {
    let mut env: HashMap<String, String> = [
        ("PUBLIC_BASE_URL", ISSUER),
        ("AUTH_UI_BASE_URL", "https://auth-ui.example/"),
        ("DATABASE_URL", "postgres://localhost/unused"),
        ("JWT_ISSUER", ISSUER),
        ("JWT_PRIVATE_KEY_PEM", "unused"),
        ("JWT_PUBLIC_KEY_PEM", "unused"),
        ("PLATFORM_AUDIENCE", AUDIENCE),
        ("SUPPORT_API_TOKEN", SUPPORT_TOKEN),
        (
            "OTP_TEST_HINT_ALLOWLIST",
            " CI@example.com ,other@example.com",
        ),
        (
            "POST_LOGOUT_REDIRECT_ALLOWLIST",
            "https://community.example",
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    for (key, value) in overrides {
        if value.is_empty() {
            env.remove(*key);
        } else {
            env.insert((*key).to_owned(), (*value).to_owned());
        }
    }
    Config::from_env(|key| env.get(key).cloned()).expect("test config")
}

// ---------------------------------------------------------------- system

pub struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    pub fn set(&self, now: OffsetDateTime) {
        *self.0.lock().unwrap() = now;
    }

    pub fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

/// Scripted bytes first, then a counter pattern; `fail` makes it error.
#[derive(Default)]
pub struct TestRandom {
    pub queue: Mutex<VecDeque<Vec<u8>>>,
    pub fail: AtomicBool,
    counter: AtomicU64,
}

impl RandomSource for TestRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(RandomError::new("entropy unavailable"));
        }
        if let Some(bytes) = self.queue.lock().unwrap().pop_front() {
            dest.copy_from_slice(&bytes);
            return Ok(());
        }
        let seed = self.counter.fetch_add(1, Ordering::SeqCst).to_be_bytes();
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = seed[i % 8] ^ (i as u8).wrapping_mul(31);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct TestIds;

impl IdGenerator for TestIds {
    fn new_id(&self) -> String {
        uuid::Uuid::now_v7().to_string()
    }
}

// ---------------------------------------------------------------- repos

/// A failure switch: `Other` errors while set.
#[derive(Default)]
pub struct Fail(AtomicBool);

impl Fail {
    pub fn set(&self, on: bool) {
        self.0.store(on, Ordering::SeqCst);
    }

    fn check(&self) -> RepoResult<()> {
        if self.0.load(Ordering::SeqCst) {
            Err(RepoError::other("database is down"))
        } else {
            Ok(())
        }
    }
}

fn new_id(id: &str) -> String {
    if id.is_empty() {
        uuid::Uuid::now_v7().to_string()
    } else {
        id.to_owned()
    }
}

#[derive(Default)]
pub struct Accounts {
    pub rows: Mutex<Vec<Account>>,
    pub fail: Fail,
}

#[async_trait]
impl AccountRepository for Accounts {
    async fn create(&self, mut account: Account) -> RepoResult<Account> {
        self.fail.check()?;
        account.id = AccountId::new(new_id(account.id.as_str()));
        self.rows.lock().unwrap().push(account.clone());
        Ok(account)
    }
    async fn find_by_id(&self, id: &AccountId) -> RepoResult<Account> {
        self.fail.check()?;
        let rows = self.rows.lock().unwrap();
        rows.iter()
            .find(|a| &a.id == id)
            .cloned()
            .ok_or(RepoError::NotFound)
    }
    async fn find_by_primary_verified_email(&self, email: &str) -> RepoResult<Account> {
        self.fail.check()?;
        let rows = self.rows.lock().unwrap();
        let found = rows
            .iter()
            .find(|a| a.primary_verified_email.to_lowercase() == email.to_lowercase());
        found.cloned().ok_or(RepoError::NotFound)
    }
    async fn update(&self, account: Account) -> RepoResult<Account> {
        self.fail.check()?;
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|a| a.id == account.id)
            .ok_or(RepoError::NotFound)?;
        *row = account.clone();
        Ok(account)
    }
}

#[derive(Default)]
pub struct Clients {
    pub rows: Mutex<Vec<OAuthClient>>,
    pub fail: Fail,
}

#[async_trait]
impl OAuthClientRepository for Clients {
    async fn create(&self, client: OAuthClient) -> RepoResult<OAuthClient> {
        self.fail.check()?;
        self.rows.lock().unwrap().push(client.clone());
        Ok(client)
    }
    async fn find_by_client_id(&self, client_id: &ClientId) -> RepoResult<OAuthClient> {
        self.fail.check()?;
        let rows = self.rows.lock().unwrap();
        let found = rows.iter().find(|c| &c.client_id == client_id);
        found.cloned().ok_or(RepoError::NotFound)
    }
}

#[derive(Default)]
pub struct Codes {
    pub rows: Mutex<Vec<AuthorizationCode>>,
}

#[async_trait]
impl AuthorizationCodeRepository for Codes {
    async fn create(&self, mut code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        code.id = new_id(code.id.as_str()).into();
        self.rows.lock().unwrap().push(code.clone());
        Ok(code)
    }
    async fn find_by_code_hash(&self, code_hash: &str) -> RepoResult<AuthorizationCode> {
        let rows = self.rows.lock().unwrap();
        let found = rows.iter().find(|c| c.code_hash == code_hash);
        found.cloned().ok_or(RepoError::NotFound)
    }
    async fn update(&self, code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|c| c.id == code.id)
            .ok_or(RepoError::NotFound)?;
        *row = code.clone();
        Ok(code)
    }
}

#[derive(Default)]
pub struct Consents {
    pub rows: Mutex<Vec<ConsentGrant>>,
}

#[async_trait]
impl ConsentGrantRepository for Consents {
    async fn find_by_account_and_client(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
    ) -> RepoResult<ConsentGrant> {
        let rows = self.rows.lock().unwrap();
        let found = rows
            .iter()
            .find(|g| &g.account_id == account_id && &g.client_id == client_id);
        found.cloned().ok_or(RepoError::NotFound)
    }
    async fn upsert(&self, mut grant: ConsentGrant) -> RepoResult<ConsentGrant> {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|g| !(g.account_id == grant.account_id && g.client_id == grant.client_id));
        grant.id = new_id(grant.id.as_str()).into();
        rows.push(grant.clone());
        Ok(grant)
    }
}

#[derive(Default)]
pub struct Sessions {
    pub rows: Mutex<Vec<SsoSession>>,
    pub fail: Fail,
}

impl Sessions {
    pub fn get(&self, id: &str) -> SsoSession {
        let rows = self.rows.lock().unwrap();
        rows.iter().find(|s| s.id == id).cloned().unwrap()
    }
}

#[async_trait]
impl SsoSessionRepository for Sessions {
    async fn create(&self, mut session: SsoSession) -> RepoResult<SsoSession> {
        self.fail.check()?;
        session.id = new_id(session.id.as_str()).into();
        self.rows.lock().unwrap().push(session.clone());
        Ok(session)
    }
    async fn find_by_id(&self, id: &SessionId) -> RepoResult<SsoSession> {
        self.fail.check()?;
        let rows = self.rows.lock().unwrap();
        rows.iter()
            .find(|s| &s.id == id)
            .cloned()
            .ok_or(RepoError::NotFound)
    }
    async fn update(&self, session: SsoSession) -> RepoResult<SsoSession> {
        self.fail.check()?;
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|s| s.id == session.id)
            .ok_or(RepoError::NotFound)?;
        *row = session.clone();
        Ok(session)
    }
    async fn revoke_by_id(&self, id: &SessionId) -> RepoResult<()> {
        self.fail.check()?;
        let mut rows = self.rows.lock().unwrap();
        for row in rows.iter_mut().filter(|s| &s.id == id) {
            row.status = SsoSessionStatus::Revoked;
            row.revoked_at = Some(NOW);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Chains {
    pub rows: Mutex<Vec<RefreshTokenChain>>,
    pub fail: Fail,
}

impl Chains {
    pub fn get(&self, id: &ChainId) -> RefreshTokenChain {
        let rows = self.rows.lock().unwrap();
        rows.iter().find(|c| &c.id == id).cloned().unwrap()
    }

    pub fn all(&self) -> Vec<RefreshTokenChain> {
        self.rows.lock().unwrap().clone()
    }
}

#[async_trait]
impl RefreshTokenChainRepository for Chains {
    async fn create(&self, mut chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        self.fail.check()?;
        chain.id = new_id(chain.id.as_str()).into();
        self.rows.lock().unwrap().push(chain.clone());
        Ok(chain)
    }
    async fn find_by_id(&self, id: &ChainId) -> RepoResult<RefreshTokenChain> {
        self.fail.check()?;
        let rows = self.rows.lock().unwrap();
        rows.iter()
            .find(|c| &c.id == id)
            .cloned()
            .ok_or(RepoError::NotFound)
    }
    async fn list_active_ids_by_sso_session_id(
        &self,
        sso_session_id: &SessionId,
    ) -> RepoResult<Vec<ChainId>> {
        self.fail.check()?;
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .filter(|c| {
                &c.sso_session_id == sso_session_id && c.status == RefreshTokenChainStatus::Active
            })
            .map(|c| c.id.clone())
            .collect())
    }
    async fn update(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        self.fail.check()?;
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|c| c.id == chain.id)
            .ok_or(RepoError::NotFound)?;
        *row = chain.clone();
        Ok(chain)
    }
    async fn revoke_by_id(&self, id: &ChainId) -> RepoResult<()> {
        self.fail.check()?;
        let mut rows = self.rows.lock().unwrap();
        for row in rows.iter_mut().filter(|c| &c.id == id) {
            row.status = RefreshTokenChainStatus::Revoked;
            row.revoked_at = Some(NOW);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Tokens {
    pub rows: Mutex<Vec<RefreshToken>>,
    pub fail: Fail,
}

impl Tokens {
    pub fn all(&self) -> Vec<RefreshToken> {
        self.rows.lock().unwrap().clone()
    }
}

#[async_trait]
impl RefreshTokenRepository for Tokens {
    async fn create(&self, mut token: RefreshToken) -> RepoResult<RefreshToken> {
        self.fail.check()?;
        token.id = new_id(token.id.as_str()).into();
        self.rows.lock().unwrap().push(token.clone());
        Ok(token)
    }
    async fn find_by_token_hash(&self, token_hash: &str) -> RepoResult<RefreshToken> {
        self.fail.check()?;
        let rows = self.rows.lock().unwrap();
        let found = rows.iter().find(|t| t.token_hash == token_hash);
        found.cloned().ok_or(RepoError::NotFound)
    }
    async fn update(&self, token: RefreshToken) -> RepoResult<RefreshToken> {
        self.fail.check()?;
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|t| t.id == token.id)
            .ok_or(RepoError::NotFound)?;
        *row = token.clone();
        Ok(token)
    }
    async fn revoke_by_chain_id(&self, chain_id: &ChainId) -> RepoResult<()> {
        self.fail.check()?;
        let mut rows = self.rows.lock().unwrap();
        for row in rows
            .iter_mut()
            .filter(|t| &t.refresh_token_chain_id == chain_id && t.revoked_at.is_none())
        {
            row.revoked_at = Some(NOW);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct AccessAudit {
    pub rows: Mutex<Vec<AccessTokenRecord>>,
}

#[async_trait]
impl AccessTokenRepository for AccessAudit {
    async fn create(&self, mut record: AccessTokenRecord) -> RepoResult<AccessTokenRecord> {
        record.id = new_id(record.id.as_str()).into();
        self.rows.lock().unwrap().push(record.clone());
        Ok(record)
    }
}

#[derive(Default)]
pub struct Providers;

#[async_trait]
impl AccountProviderRepository for Providers {
    async fn create(&self, provider: AccountProvider) -> RepoResult<AccountProvider> {
        Ok(provider)
    }
    async fn find_by_provider_account_id(&self, _: &str, _: &str) -> RepoResult<AccountProvider> {
        Err(RepoError::NotFound)
    }
    async fn find_by_account_id_and_provider(
        &self,
        _: &AccountId,
        _: &str,
    ) -> RepoResult<AccountProvider> {
        Err(RepoError::NotFound)
    }
}

/// OTP challenges; `find_latest_active_by_email` filters like the Postgres
/// adapter, with the fixture clock.
pub struct Otps {
    pub rows: Mutex<Vec<OtpChallenge>>,
    clock: Arc<TestClock>,
}

#[async_trait]
impl OtpChallengeRepository for Otps {
    async fn create(&self, challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        self.rows.lock().unwrap().push(challenge.clone());
        Ok(challenge)
    }
    async fn find_active_by_request_and_email(&self, _: &str, _: &str) -> RepoResult<OtpChallenge> {
        Err(RepoError::NotFound)
    }
    async fn find_by_id(&self, id: &OtpChallengeId) -> RepoResult<OtpChallenge> {
        let rows = self.rows.lock().unwrap();
        rows.iter()
            .find(|c| &c.id == id)
            .cloned()
            .ok_or(RepoError::NotFound)
    }
    async fn update(&self, challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        Ok(challenge)
    }
    async fn find_latest_active_by_email(&self, email: &str) -> RepoResult<OtpChallenge> {
        let now = self.clock.now();
        let rows = self.rows.lock().unwrap();
        rows.iter()
            .filter(|c| {
                c.email.to_lowercase() == email.to_lowercase()
                    && c.verified_at.is_none()
                    && now <= c.expires_at
            })
            .max_by_key(|c| c.created_at)
            .cloned()
            .ok_or(RepoError::NotFound)
    }
}

#[derive(Default)]
pub struct Jtis;

#[async_trait]
impl SignedStateJtiRepository for Jtis {
    async fn insert(&self, _: &str, _: OffsetDateTime) -> RepoResult<()> {
        Ok(())
    }
    async fn prune_expired(&self, _: OffsetDateTime) -> RepoResult<()> {
        Ok(())
    }
}

/// One recorded `SupportRepository::sign_out` call.
pub type SignOut = (Vec<SessionId>, Vec<ChainId>, OffsetDateTime);

/// Support repository: a scripted summary result and recorded sign-outs.
#[derive(Default)]
pub struct Support {
    pub summary: Mutex<Option<SupportAccountSummary>>,
    pub summary_error: Mutex<Option<RepoError>>,
    pub sign_out_fail: Fail,
    pub requested: Mutex<Vec<AccountId>>,
    pub sign_outs: Mutex<Vec<SignOut>>,
}

#[async_trait]
impl SupportRepository for Support {
    async fn load_account_summary(
        &self,
        account_id: &AccountId,
    ) -> RepoResult<SupportAccountSummary> {
        self.requested.lock().unwrap().push(account_id.clone());
        if let Some(error) = self.summary_error.lock().unwrap().take() {
            return Err(error);
        }
        self.summary
            .lock()
            .unwrap()
            .clone()
            .filter(|summary| &summary.account.id == account_id)
            .ok_or(RepoError::NotFound)
    }
    async fn sign_out(
        &self,
        session_ids: &[SessionId],
        chain_ids: &[ChainId],
        now: OffsetDateTime,
    ) -> RepoResult<()> {
        self.sign_out_fail.check()?;
        self.sign_outs
            .lock()
            .unwrap()
            .push((session_ids.to_vec(), chain_ids.to_vec(), now));
        Ok(())
    }
}

#[derive(Default)]
pub struct Readiness {
    pub fail: Fail,
}

#[async_trait]
impl ReadinessProbe for Readiness {
    async fn ping(&self) -> RepoResult<()> {
        self.fail.check()
    }
}

pub struct FailingJwks;

impl JwksProvider for FailingJwks {
    fn public_jwks(&self) -> Result<Vec<u8>, JwtError> {
        Err(JwtError::new("no key"))
    }
}

// ---------------------------------------------------------------- fixture

pub struct Fixture {
    pub config: Config,
    pub clock: Arc<TestClock>,
    pub random: Arc<TestRandom>,
    pub accounts: Arc<Accounts>,
    pub clients: Arc<Clients>,
    pub codes: Arc<Codes>,
    pub sessions: Arc<Sessions>,
    pub chains: Arc<Chains>,
    pub tokens: Arc<Tokens>,
    pub access: Arc<AccessAudit>,
    pub otps: Arc<Otps>,
    pub support: Arc<Support>,
    pub readiness: Arc<Readiness>,
    pub jwks: Arc<JwksManager>,
    pub state: AppState,
    /// Mount the OTP hint source extension.
    pub with_hint_source: bool,
    /// Use `register_for` (Go's conditional mounting) instead of `register`.
    pub conditional_routes: bool,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_config(config_with(&[]))
    }

    pub fn with_config(config: Config) -> Self {
        let clock = Arc::new(TestClock(Mutex::new(NOW)));
        let random = Arc::new(TestRandom::default());
        let ids: Arc<dyn IdGenerator> = Arc::new(TestIds);
        let accounts = Arc::new(Accounts::default());
        let clients = Arc::new(Clients::default());
        let codes = Arc::new(Codes::default());
        let consents = Arc::new(Consents::default());
        let sessions = Arc::new(Sessions::default());
        let chains = Arc::new(Chains::default());
        let tokens = Arc::new(Tokens::default());
        let access = Arc::new(AccessAudit::default());
        let otps = Arc::new(Otps {
            rows: Mutex::new(Vec::new()),
            clock: clock.clone(),
        });
        let support = Arc::new(Support::default());
        let readiness = Arc::new(Readiness::default());
        let jwks = Arc::new(
            JwksManager::from_pem(
                "RS256",
                &key("test-only-rsa-2048-private-pkcs8.pem"),
                &key("test-only-rsa-2048-public-pkix.pem"),
            )
            .expect("test key")
            .with_clock(clock.clone()),
        );

        let flow = Arc::new(FlowService::new(
            FlowConfig {
                authorization_code_ttl: config.authorization_code_ttl,
                sso_session_ttl: config.sso_session_ttl,
            },
            FlowPorts {
                clock: clock.clone(),
                id_generator: ids.clone(),
                random: random.clone(),
                authorization_codes: codes.clone(),
                consent_grants: consents,
                sso_sessions: sessions.clone(),
                refresh_token_chains: chains.clone(),
                refresh_tokens: tokens.clone(),
            },
        ));
        let token = Arc::new(TokenService::new(
            TokenConfig {
                issuer: config.jwt_issuer.clone(),
                audience: config.platform_audience.clone(),
                access_token_ttl: config.access_token_ttl,
                id_token_ttl: config.id_token_ttl,
                refresh_token_absolute_ttl: config.refresh_absolute_ttl,
                refresh_token_inactive_ttl: config.refresh_inactive_ttl,
                refresh_reuse_grace: config.refresh_reuse_grace,
            },
            TokenServiceDeps {
                clock: clock.clone(),
                ids,
                random: random.clone(),
                signer: jwks.clone(),
                access_tokens: access.clone(),
                sso_sessions: sessions.clone(),
                refresh_token_chains: chains.clone(),
                refresh_tokens: tokens.clone(),
            },
        ));
        let identity = Arc::new(IdentityService::new(
            IdentityConfig {
                otp_challenge_ttl: config.otp_challenge_ttl,
                otp_max_attempts: config.otp_max_attempts,
                otp_max_resends: config.otp_max_resends,
                otp_resend_cooldown: config.otp_resend_cooldown,
            },
            IdentityDeps {
                clock: clock.clone(),
                otp_code_generator: Arc::new(FixedOtpCodeGenerator::new("ABCDEFGH")),
                accounts: accounts.clone(),
                account_providers: Arc::new(Providers),
                otp_challenges: otps.clone(),
                otp_mailer: None,
                sso_sessions: flow.clone(),
            },
        ));
        let envelope = Arc::new(
            EnvelopeSigner::new(
                vec![7_u8; 32],
                Duration::minutes(10),
                Arc::new(RepositoryJtiStore::new(Arc::new(Jtis))),
                clock.clone(),
                random.clone(),
            )
            .expect("envelope signer"),
        );

        let state = AppState {
            config: Arc::new(config.clone()),
            clock: clock.clone(),
            random: random.clone(),
            clients: clients.clone(),
            accounts: accounts.clone(),
            sso_sessions: sessions.clone(),
            refresh_token_chains: chains.clone(),
            refresh_tokens: tokens.clone(),
            support: support.clone(),
            readiness: readiness.clone(),
            validator: Arc::new(AuthorizeRequestValidator::new(clients.clone())),
            flow,
            token,
            identity,
            envelope,
            jwks: jwks.clone(),
            jwt_verifier: jwks.clone(),
            providers: Arc::new(BTreeMap::new()),
            cookies: Arc::new(CookiePolicy::from_config(&config)),
            otp_rate_limiter: Arc::new(otp_rate_limit::TestOtpRateLimiter::default()),
            cleanup: Arc::new(cleanup::TestCleanup),
            support_auth: Arc::new(SupportAuth::from_config(&config)),
        };

        let fixture = Self {
            config,
            clock,
            random,
            accounts,
            clients,
            codes,
            sessions,
            chains,
            tokens,
            access,
            otps,
            support,
            readiness,
            jwks,
            state,
            with_hint_source: true,
            conditional_routes: false,
        };
        fixture.seed();
        fixture
    }

    fn seed(&self) {
        let client = |id: &str, kind: ClientType, secret: &str, scopes: &str| OAuthClient {
            id: format!("rec-{id}").into(),
            client_id: ClientId::new(id),
            client_type: kind,
            client_secret_hash: SecretString::from(secret.to_owned()),
            display_name: format!("{id} display"),
            logo_uri: format!("https://cdn.example/{id}.png"),
            redirect_uris: vec![format!("https://{id}.example/callback")],
            allowed_scopes: scopes.to_owned(),
            ..OAuthClient::default()
        };
        let mut rows = self.clients.rows.lock().unwrap();
        rows.push(client(
            BROWSER,
            ClientType::Public,
            "",
            "profile, openid email\topenid offline_access",
        ));
        rows.push(client(
            WORKER,
            ClientType::Confidential,
            &format!("sha256:{}", sha256_b64url(WORKER_SECRET)),
            "trading.read,trading.write",
        ));
        rows.push(client(
            LEGACY,
            ClientType::Confidential,
            LEGACY_SECRET,
            "trading.read",
        ));
    }

    /// The router as the entrypoint would build it.
    pub fn router(&self) -> Router {
        let routes = if self.conditional_routes {
            protocol::register_for(GinRouter::new(), &self.config)
        } else {
            protocol::register(GinRouter::new())
        };
        let layers =
            GlobalLayers::from_config(&self.config).with_access_log(AccessLog::new(|_| {}));
        let router = routes.with_state(self.state.clone()).into_router(&layers);
        if self.with_hint_source {
            router.layer(Extension(OtpHintSource(self.otps.clone())))
        } else {
            router
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// An active account with an active SSO session; returns both IDs.
    pub fn login(&self, email: &str) -> (AccountId, SessionId) {
        let account = Account {
            id: AccountId::new(uuid::Uuid::now_v7().to_string()),
            primary_verified_email: email.to_owned(),
            display_name: email.split('@').next().unwrap().to_owned(),
            avatar_url: format!("https://cdn.example/{email}.png"),
            status: AccountStatus::Active,
            created_at: NOW,
            updated_at: NOW,
        };
        let session = SsoSession {
            id: SessionId::new(uuid::Uuid::now_v7().to_string()),
            account_id: account.id.clone(),
            status: SsoSessionStatus::Active,
            login_method: "email_otp".to_owned(),
            authenticated_at: NOW - Duration::minutes(5),
            last_seen_at: NOW,
            expires_at: NOW + Duration::days(1),
            ..SsoSession::default()
        };
        let ids = (account.id.clone(), session.id.clone());
        self.accounts.rows.lock().unwrap().push(account);
        self.sessions.rows.lock().unwrap().push(session);
        ids
    }

    /// Issues an authorization code for `client` through the real flow
    /// service; returns the code value.
    pub async fn issue_code(
        &self,
        account: &AccountId,
        session: &SessionId,
        client: &str,
        scopes: &[&str],
        challenge: &str,
        method: &str,
    ) -> String {
        self.issue_code_with_nonce(account, session, client, scopes, challenge, method, "")
            .await
    }

    /// [`Self::issue_code`] with the authorization request's OIDC `nonce`.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_code_with_nonce(
        &self,
        account: &AccountId,
        session: &SessionId,
        client: &str,
        scopes: &[&str],
        challenge: &str,
        method: &str,
        nonce: &str,
    ) -> String {
        let (code, _) = self
            .state
            .flow
            .issue_direct_code(IssueDirectCodeRequest {
                account_id: account.clone(),
                client_id: ClientId::new(client),
                sso_session_id: Some(session.clone()),
                redirect_uri: format!("https://{client}.example/callback"),
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                pkce_code_challenge: challenge.to_owned(),
                pkce_code_challenge_method: method.to_owned(),
                nonce: nonce.to_owned(),
                auth_time: NOW - Duration::minutes(5),
            })
            .await
            .expect("issue code");
        code
    }
}

// ---------------------------------------------------------------- HTTP

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|value| value.to_str().unwrap())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("JSON body ({e}): {}", self.body))
    }

    pub fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    /// Status, `application/json; charset=utf-8` and the exact body.
    #[track_caller]
    pub fn assert_json(&self, status: StatusCode, body: &str) {
        assert_eq!(self.status, status, "body: {}", self.body);
        assert_eq!(
            self.header("content-type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(self.body, body);
    }

    /// A gin `c.Redirect(302)` for GET.
    #[track_caller]
    pub fn assert_found(&self, location: &str) {
        assert_eq!(self.status, StatusCode::FOUND, "body: {}", self.body);
        assert_eq!(self.header("location"), Some(location));
        assert_eq!(
            self.header("content-type"),
            Some("text/html; charset=utf-8")
        );
    }
}

pub async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

pub async fn get(router: &Router, uri: &str, headers: &[(&str, &str)]) -> Reply {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    send(router, builder.body(Body::empty()).unwrap()).await
}

pub async fn post(router: &Router, uri: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut builder = Request::builder().method(Method::POST).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    send(router, builder.body(Body::from(body.to_owned())).unwrap()).await
}

/// `application/x-www-form-urlencoded` POST.
pub async fn post_form(
    router: &Router,
    uri: &str,
    headers: &[(&str, &str)],
    fields: &[(&str, &str)],
) -> Reply {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                auth_http::go_url::query_escape(k),
                auth_http::go_url::query_escape(v)
            )
        })
        .collect();
    let mut all = vec![("content-type", "application/x-www-form-urlencoded")];
    all.extend_from_slice(headers);
    post(router, uri, &all, &body.join("&")).await
}

/// `Basic base64(user:pass)` with standard padded base64.
pub fn basic(user: &str, pass: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{pass}").into_bytes();
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    format!("Basic {out}")
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// A refresh token stored for `chain`; returns the opaque value.
pub fn store_refresh_token(
    fixture: &Fixture,
    chain: &RefreshTokenChain,
    value: &str,
) -> RefreshToken {
    let token = RefreshToken {
        id: uuid::Uuid::now_v7().to_string().into(),
        refresh_token_chain_id: chain.id.clone(),
        token_hash: sha256_b64url(value),
        issued_at: NOW - Duration::minutes(1),
        expires_at: NOW + Duration::days(30),
        ..RefreshToken::default()
    };
    fixture.tokens.rows.lock().unwrap().push(token.clone());
    token
}

/// An active chain for `client` bound to `session`.
pub fn store_chain(
    fixture: &Fixture,
    account: &AccountId,
    session: &SessionId,
    client: &str,
) -> RefreshTokenChain {
    let chain = RefreshTokenChain {
        id: ChainId::new(uuid::Uuid::now_v7().to_string()),
        account_id: account.clone(),
        client_id: ClientId::new(client),
        sso_session_id: session.clone(),
        scope: "email openid".to_owned(),
        status: RefreshTokenChainStatus::Active,
        absolute_expires_at: NOW + Duration::days(30),
        inactive_expires_at: NOW + Duration::days(7),
        last_used_at: NOW,
        ..RefreshTokenChain::default()
    };
    fixture.chains.rows.lock().unwrap().push(chain.clone());
    chain
}

pub fn b64url(bytes: &[u8]) -> String {
    b64url_encode(bytes)
}
