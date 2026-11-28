//! `AppState` fixture for the flow handler tests: in-memory repositories, a
//! settable clock, deterministic randomness and IDs, and fake identity
//! providers.

#![allow(dead_code)]

#[path = "../common/cleanup.rs"]
mod cleanup;
#[path = "../common/otp_rate_limit.rs"]
mod otp_rate_limit;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use auth_adapters::config::Config;
use auth_core::{
    crypto::hash_opaque,
    domain::{
        AccessTokenRecord, Account, AccountId, AccountProvider, AuthorizationCode, ChainId,
        ClientId, ClientStatus, ClientType, ConsentGrant, OAuthClient, OtpChallenge,
        OtpChallengeId, RefreshToken, RefreshTokenChain, SessionId, SsoSession, SsoSessionStatus,
    },
    flow::{FlowConfig, FlowPorts, FlowService},
    identity::{FixedOtpCodeGenerator, IdentityConfig, IdentityDeps, IdentityService},
    oauth::{AuthorizeRequestValidator, envelope::EnvelopeSigner},
    ports::{
        AccessTokenRepository, AccountProviderRepository, AccountRepository,
        AuthorizationCodeRepository, Clock, ConsentGrantRepository, IdGenerator, IdentityProvider,
        JtiStore, JtiStoreError, JwksProvider, JwtClaims, JwtError, JwtSigner, JwtVerifier,
        OAuthClientRepository, OtpChallengeRepository, ProviderError, ProviderProfile, RandomError,
        RandomSource, ReadinessProbe, RefreshTokenChainRepository, RefreshTokenRepository,
        RepoError, RepoResult, SignedJwt, SsoSessionRepository, SupportAccountSummary,
        SupportRepository,
    },
    token::{TokenConfig, TokenService, TokenServiceDeps},
};
use auth_http::{
    AppState, GinRouter, GlobalLayers,
    cookies::CookiePolicy,
    handlers::flow,
    middleware::{AccessLog, SupportAuth},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use secrecy::SecretString;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

pub const UI: &str = "https://auth-ui.example.com/";
/// golden `otp_start_response.now_unix`.
pub const NOW_UNIX: i64 = 1_775_044_800;
pub const OTP_CODE: &str = "12345678";
pub const GOOGLE_REDIRECT: &str = "https://auth.example.com/v1/auth/login/callback/google";
pub const GITHUB_REDIRECT: &str = "https://auth.example.com/v1/auth/login/callback/github";
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub const CLIENT: &str = "trading-web";
pub const CALLBACK: &str = "https://trading.example.com/callback";

// ---------------------------------------------------------------- system

pub struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    pub fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }

    pub fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        TestClock::now(self)
    }
}

/// Deterministic bytes: every call yields a fresh run of a counter.
#[derive(Default)]
pub struct SeqRandom(Mutex<u8>);

impl RandomSource for SeqRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        let mut next = self.0.lock().unwrap();
        for byte in dest {
            *next = next.wrapping_add(1);
            *byte = *next;
        }
        Ok(())
    }
}

/// UUID-shaped sequential IDs; queued IDs are handed out first.
#[derive(Default)]
pub struct Ids {
    counter: Mutex<u64>,
    queued: Mutex<VecDeque<String>>,
}

impl Ids {
    pub fn queue(&self, id: &str) {
        self.queued.lock().unwrap().push_back(id.to_owned());
    }
}

impl IdGenerator for Ids {
    fn new_id(&self) -> String {
        if let Some(id) = self.queued.lock().unwrap().pop_front() {
            return id;
        }
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        format!("0195f0a2-0000-7000-8000-{:012x}", *counter)
    }
}

// ---------------------------------------------------------------- storage

/// Every repository the flow handlers reach, in memory.
#[derive(Default)]
pub struct Db {
    pub ids: Ids,
    pub clients: Mutex<BTreeMap<String, OAuthClient>>,
    pub accounts: Mutex<Vec<Account>>,
    pub account_providers: Mutex<Vec<AccountProvider>>,
    pub codes: Mutex<Vec<AuthorizationCode>>,
    pub consents: Mutex<Vec<ConsentGrant>>,
    pub sessions: Mutex<Vec<SsoSession>>,
    /// Makes `AccountRepository::create` fail with `db down`.
    pub fail_account_create: Mutex<bool>,
    pub otps: Mutex<Vec<OtpChallenge>>,
    pub jtis: Mutex<BTreeSet<String>>,
}

impl Db {
    fn id(&self, current: &str) -> String {
        if current.is_empty() {
            self.ids.new_id()
        } else {
            current.to_owned()
        }
    }

    /// Drops a queued ID that was not consumed.
    pub fn ids_take(&self) -> Option<String> {
        self.ids.queued.lock().unwrap().pop_front()
    }

    pub fn add_client(&self, client: OAuthClient) {
        self.clients
            .lock()
            .unwrap()
            .insert(client.client_id.as_str().to_owned(), client);
    }

    pub fn add_account(&self, id: &str, email: &str) -> Account {
        let account = Account {
            id: AccountId::new(id),
            primary_verified_email: email.to_owned(),
            display_name: email.split('@').next().unwrap_or_default().to_owned(),
            ..Account::default()
        };
        self.accounts.lock().unwrap().push(account.clone());
        account
    }

    pub fn add_session(&self, id: &str, account_id: &str, now: OffsetDateTime) -> SsoSession {
        let session = SsoSession {
            id: SessionId::new(id),
            account_id: AccountId::new(account_id),
            status: SsoSessionStatus::Active,
            login_method: "email_otp".to_owned(),
            authenticated_at: now - Duration::hours(1),
            last_seen_at: now,
            expires_at: now + Duration::days(1),
            created_at: now,
            updated_at: now,
            ..SsoSession::default()
        };
        self.sessions.lock().unwrap().push(session.clone());
        session
    }

    pub fn add_consent(&self, account_id: &str, client_id: &str, scopes: &str) {
        self.consents.lock().unwrap().push(ConsentGrant {
            id: self.ids.new_id().into(),
            account_id: AccountId::new(account_id),
            client_id: ClientId::new(client_id),
            granted_scopes: scopes.to_owned(),
            ..ConsentGrant::default()
        });
    }

    /// The stored code whose hash matches `value`.
    pub fn code(&self, value: &str) -> AuthorizationCode {
        let hash = hash_opaque(value).unwrap();
        self.codes
            .lock()
            .unwrap()
            .iter()
            .find(|code| code.code_hash == hash)
            .cloned()
            .expect("issued code")
    }

    pub fn session(&self, id: &str) -> SsoSession {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .find(|session| session.id == id)
            .cloned()
            .expect("session")
    }

    pub fn consent(&self, account_id: &str) -> Option<ConsentGrant> {
        self.consents
            .lock()
            .unwrap()
            .iter()
            .find(|grant| grant.account_id == account_id)
            .cloned()
    }

    pub fn otp(&self, id: &str) -> OtpChallenge {
        self.otps
            .lock()
            .unwrap()
            .iter()
            .find(|otp| otp.id == id)
            .cloned()
            .expect("otp challenge")
    }
}

fn found<T: Clone>(item: Option<&T>) -> RepoResult<T> {
    item.cloned().ok_or(RepoError::NotFound)
}

#[async_trait]
impl OAuthClientRepository for Db {
    async fn create(&self, client: OAuthClient) -> RepoResult<OAuthClient> {
        self.add_client(client.clone());
        Ok(client)
    }

    async fn find_by_client_id(&self, client_id: &ClientId) -> RepoResult<OAuthClient> {
        found(self.clients.lock().unwrap().get(client_id.as_str()))
    }
}

#[async_trait]
impl AccountRepository for Db {
    async fn create(&self, mut account: Account) -> RepoResult<Account> {
        if *self.fail_account_create.lock().unwrap() {
            return Err(RepoError::other("db down"));
        }
        account.id = self.id(account.id.as_str()).into();
        self.accounts.lock().unwrap().push(account.clone());
        Ok(account)
    }

    async fn find_by_id(&self, id: &AccountId) -> RepoResult<Account> {
        found(self.accounts.lock().unwrap().iter().find(|a| &a.id == id))
    }

    async fn find_by_primary_verified_email(&self, email: &str) -> RepoResult<Account> {
        found(
            self.accounts
                .lock()
                .unwrap()
                .iter()
                .find(|a| a.primary_verified_email.to_lowercase() == email.to_lowercase()),
        )
    }

    async fn update(&self, account: Account) -> RepoResult<Account> {
        Ok(account)
    }
}

#[async_trait]
impl AccountProviderRepository for Db {
    async fn create(&self, mut provider: AccountProvider) -> RepoResult<AccountProvider> {
        provider.id = self.id(provider.id.as_str()).into();
        self.account_providers
            .lock()
            .unwrap()
            .push(provider.clone());
        Ok(provider)
    }

    async fn find_by_provider_account_id(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> RepoResult<AccountProvider> {
        found(
            self.account_providers
                .lock()
                .unwrap()
                .iter()
                .find(|p| p.provider == provider && p.provider_account_id == provider_account_id),
        )
    }

    async fn find_by_account_id_and_provider(
        &self,
        account_id: &AccountId,
        provider: &str,
    ) -> RepoResult<AccountProvider> {
        found(
            self.account_providers
                .lock()
                .unwrap()
                .iter()
                .find(|p| &p.account_id == account_id && p.provider == provider),
        )
    }
}

#[async_trait]
impl AuthorizationCodeRepository for Db {
    async fn create(&self, mut code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        code.id = self.id(code.id.as_str()).into();
        self.codes.lock().unwrap().push(code.clone());
        Ok(code)
    }

    async fn find_by_code_hash(&self, code_hash: &str) -> RepoResult<AuthorizationCode> {
        found(
            self.codes
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.code_hash == code_hash),
        )
    }

    async fn update(&self, code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        Ok(code)
    }
}

#[async_trait]
impl ConsentGrantRepository for Db {
    async fn find_by_account_and_client(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
    ) -> RepoResult<ConsentGrant> {
        found(
            self.consents
                .lock()
                .unwrap()
                .iter()
                .find(|g| &g.account_id == account_id && &g.client_id == client_id),
        )
    }

    async fn upsert(&self, mut grant: ConsentGrant) -> RepoResult<ConsentGrant> {
        grant.id = self.id(grant.id.as_str()).into();
        let mut consents = self.consents.lock().unwrap();
        consents.retain(|g| !(g.account_id == grant.account_id && g.client_id == grant.client_id));
        consents.push(grant.clone());
        Ok(grant)
    }
}

#[async_trait]
impl SsoSessionRepository for Db {
    async fn create(&self, mut session: SsoSession) -> RepoResult<SsoSession> {
        session.id = self.id(session.id.as_str()).into();
        self.sessions.lock().unwrap().push(session.clone());
        Ok(session)
    }

    async fn find_by_id(&self, id: &SessionId) -> RepoResult<SsoSession> {
        found(self.sessions.lock().unwrap().iter().find(|s| &s.id == id))
    }

    async fn update(&self, session: SsoSession) -> RepoResult<SsoSession> {
        Ok(session)
    }

    async fn revoke_by_id(&self, _: &SessionId) -> RepoResult<()> {
        Ok(())
    }
}

#[async_trait]
impl OtpChallengeRepository for Db {
    async fn create(&self, mut challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        challenge.id = self.id(challenge.id.as_str()).into();
        self.otps.lock().unwrap().push(challenge.clone());
        Ok(challenge)
    }

    async fn find_active_by_request_and_email(&self, _: &str, _: &str) -> RepoResult<OtpChallenge> {
        Err(RepoError::NotFound)
    }

    async fn find_by_id(&self, id: &OtpChallengeId) -> RepoResult<OtpChallenge> {
        found(self.otps.lock().unwrap().iter().find(|c| &c.id == id))
    }

    async fn update(&self, challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        let mut otps = self.otps.lock().unwrap();
        if let Some(stored) = otps.iter_mut().find(|c| c.id == challenge.id) {
            *stored = challenge.clone();
        }
        Ok(challenge)
    }

    async fn find_latest_active_by_email(&self, _: &str) -> RepoResult<OtpChallenge> {
        Err(RepoError::NotFound)
    }
}

#[async_trait]
impl JtiStore for Db {
    async fn insert(&self, jti: &str, _: OffsetDateTime) -> Result<(), JtiStoreError> {
        if self.jtis.lock().unwrap().insert(jti.to_owned()) {
            Ok(())
        } else {
            Err(JtiStoreError::Replay)
        }
    }
}

// Token and support ports are only needed to build the state.

#[async_trait]
impl AccessTokenRepository for Db {
    async fn create(&self, record: AccessTokenRecord) -> RepoResult<AccessTokenRecord> {
        Ok(record)
    }
}

#[async_trait]
impl RefreshTokenChainRepository for Db {
    async fn create(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        Ok(chain)
    }

    async fn find_by_id(&self, _: &ChainId) -> RepoResult<RefreshTokenChain> {
        Err(RepoError::NotFound)
    }

    async fn list_active_ids_by_sso_session_id(&self, _: &SessionId) -> RepoResult<Vec<ChainId>> {
        Ok(Vec::new())
    }

    async fn update(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        Ok(chain)
    }

    async fn revoke_by_id(&self, _: &ChainId) -> RepoResult<()> {
        Ok(())
    }
}

#[async_trait]
impl RefreshTokenRepository for Db {
    async fn create(&self, token: RefreshToken) -> RepoResult<RefreshToken> {
        Ok(token)
    }

    async fn find_by_token_hash(&self, _: &str) -> RepoResult<RefreshToken> {
        Err(RepoError::NotFound)
    }

    async fn update(&self, token: RefreshToken) -> RepoResult<RefreshToken> {
        Ok(token)
    }

    async fn revoke_by_chain_id(&self, _: &ChainId) -> RepoResult<()> {
        Ok(())
    }
}

#[async_trait]
impl SupportRepository for Db {
    async fn load_account_summary(&self, _: &AccountId) -> RepoResult<SupportAccountSummary> {
        Err(RepoError::NotFound)
    }

    async fn sign_out(&self, _: &[SessionId], _: &[ChainId], _: OffsetDateTime) -> RepoResult<()> {
        Ok(())
    }
}

#[async_trait]
impl ReadinessProbe for Db {
    async fn ping(&self) -> RepoResult<()> {
        Ok(())
    }
}

pub struct NoJwt;

impl JwtSigner for NoJwt {
    fn sign(&self, _: &JwtClaims) -> Result<SignedJwt, JwtError> {
        Err(JwtError::new("not used"))
    }
}

impl JwksProvider for NoJwt {
    fn public_jwks(&self) -> Result<Vec<u8>, JwtError> {
        Err(JwtError::new("not used"))
    }
}

impl JwtVerifier for NoJwt {
    fn verify(&self, _: &str) -> Result<JwtClaims, JwtError> {
        Err(JwtError::new("not used"))
    }
}

// ---------------------------------------------------------------- providers

/// Identity provider returning a configured profile (or error) and
/// recording each exchange.
pub struct FakeProvider {
    name: String,
    pub outcome: Mutex<Result<ProviderProfile, String>>,
    pub exchanges: Mutex<Vec<(String, String)>>,
}

impl FakeProvider {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            outcome: Mutex::new(Err("no profile configured".to_owned())),
            exchanges: Mutex::default(),
        }
    }

    pub fn returns(&self, account_id: &str, email: &str, verified: bool) {
        *self.outcome.lock().unwrap() = Ok(ProviderProfile {
            name: self.name.clone(),
            account_id: account_id.to_owned(),
            email: email.to_owned(),
            email_verified: verified,
            display_name: "Provider User".to_owned(),
            avatar_url: "https://avatar.example/x.png".to_owned(),
        });
    }

    pub fn fails(&self, message: &str) {
        *self.outcome.lock().unwrap() = Err(message.to_owned());
    }
}

#[async_trait]
impl IdentityProvider for FakeProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn exchange_authorization_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<ProviderProfile, ProviderError> {
        self.exchanges
            .lock()
            .unwrap()
            .push((code.to_owned(), redirect_uri.to_owned()));
        self.outcome
            .lock()
            .unwrap()
            .clone()
            .map_err(ProviderError::new)
    }
}

// ---------------------------------------------------------------- harness

pub fn public_client(client_id: &str, redirect_uris: &[&str], scopes: &str) -> OAuthClient {
    OAuthClient {
        client_id: ClientId::new(client_id),
        client_type: ClientType::Public,
        display_name: "Trading".to_owned(),
        redirect_uris: redirect_uris.iter().map(|uri| (*uri).to_owned()).collect(),
        allowed_scopes: scopes.to_owned(),
        status: ClientStatus::Active,
        client_secret_hash: SecretString::default(),
        ..OAuthClient::default()
    }
}

pub struct Harness {
    pub router: Router,
    pub state: AppState,
    pub db: Arc<Db>,
    pub clock: Arc<TestClock>,
    pub google: Arc<FakeProvider>,
    pub github: Arc<FakeProvider>,
}

pub struct Options {
    pub env: Vec<(&'static str, String)>,
    /// Register the fake providers in `AppState::providers`.
    pub providers: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            env: Vec::new(),
            providers: true,
        }
    }
}

pub fn config(overrides: &[(&'static str, String)]) -> Config {
    let mut env: HashMap<&str, String> = [
        ("PUBLIC_BASE_URL", "https://auth.example.com"),
        ("AUTH_UI_BASE_URL", UI),
        ("DATABASE_URL", "postgres://localhost/unused"),
        ("JWT_ISSUER", "https://auth.example.com"),
        ("JWT_PRIVATE_KEY_PEM", "unused"),
        ("JWT_PUBLIC_KEY_PEM", "unused"),
        (
            "GOOGLE_CLIENT_ID",
            "google-client-id.apps.googleusercontent.com",
        ),
        ("GOOGLE_CLIENT_SECRET", "test-placeholder"),
        ("GOOGLE_REDIRECT_URL", GOOGLE_REDIRECT),
        ("GITHUB_CLIENT_ID", "Iv1.githubclientid"),
        ("GITHUB_CLIENT_SECRET", "test-placeholder"),
        ("GITHUB_REDIRECT_URL", GITHUB_REDIRECT),
        (
            "FLOW_ENVELOPE_SECRET",
            "flow-envelope-test-secret-0123456789abcdef",
        ),
        ("OTP_CHALLENGE_TTL", "10m"),
    ]
    .into_iter()
    .map(|(k, v)| (k, v.to_owned()))
    .collect();
    for (key, value) in overrides {
        env.insert(key, value.clone());
    }
    Config::from_env(|key| env.get(key).cloned()).expect("test config")
}

pub fn harness() -> Harness {
    harness_with(Options::default())
}

pub fn harness_with(options: Options) -> Harness {
    let config = Arc::new(config(&options.env));
    let clock = Arc::new(TestClock(Mutex::new(
        OffsetDateTime::from_unix_timestamp(NOW_UNIX).unwrap(),
    )));
    let random: Arc<dyn RandomSource> = Arc::new(SeqRandom::default());
    let db = Arc::new(Db::default());
    db.add_client(public_client(
        CLIENT,
        &[CALLBACK, "https://trading.example.com/cb?tenant=a"],
        "openid email profile offline_access trading.read",
    ));

    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let flow = Arc::new(FlowService::new(
        FlowConfig {
            authorization_code_ttl: config.authorization_code_ttl,
            sso_session_ttl: config.sso_session_ttl,
        },
        FlowPorts {
            clock: dyn_clock.clone(),
            id_generator: Arc::new(Ids::default()),
            random: random.clone(),
            authorization_codes: db.clone(),
            consent_grants: db.clone(),
            sso_sessions: db.clone(),
            refresh_token_chains: db.clone(),
            refresh_tokens: db.clone(),
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
            clock: dyn_clock.clone(),
            otp_code_generator: Arc::new(FixedOtpCodeGenerator::new(OTP_CODE)),
            accounts: db.clone(),
            account_providers: db.clone(),
            otp_challenges: db.clone(),
            otp_mailer: None,
            sso_sessions: flow.clone(),
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
            clock: dyn_clock.clone(),
            ids: Arc::new(Ids::default()),
            random: random.clone(),
            signer: Arc::new(NoJwt),
            access_tokens: db.clone(),
            sso_sessions: db.clone(),
            refresh_token_chains: db.clone(),
            refresh_tokens: db.clone(),
        },
    ));
    let envelope = Arc::new(
        EnvelopeSigner::new(
            "flow-envelope-test-secret-0123456789abcdef",
            config.flow_envelope_ttl,
            db.clone(),
            dyn_clock.clone(),
            random.clone(),
        )
        .unwrap(),
    );
    let google = Arc::new(FakeProvider::new("google"));
    let github = Arc::new(FakeProvider::new("github"));
    let mut providers: BTreeMap<String, Arc<dyn IdentityProvider>> = BTreeMap::new();
    if options.providers {
        providers.insert("google".to_owned(), google.clone());
        providers.insert("github".to_owned(), github.clone());
    }

    let state = AppState {
        config: config.clone(),
        clock: dyn_clock,
        random,
        clients: db.clone(),
        accounts: db.clone(),
        sso_sessions: db.clone(),
        refresh_token_chains: db.clone(),
        refresh_tokens: db.clone(),
        support: db.clone(),
        readiness: db.clone(),
        validator: Arc::new(AuthorizeRequestValidator::new(db.clone())),
        flow,
        token,
        identity,
        envelope,
        jwks: Arc::new(NoJwt),
        jwt_verifier: Arc::new(NoJwt),
        providers: Arc::new(providers),
        cookies: Arc::new(CookiePolicy::from_config(&config)),
        otp_rate_limiter: Arc::new(otp_rate_limit::TestOtpRateLimiter::default()),
        cleanup: Arc::new(cleanup::TestCleanup),
        support_auth: Arc::new(SupportAuth::from_config(&config)),
    };
    let layers = GlobalLayers::from_config(&config).with_access_log(AccessLog::new(|_| {}));
    let router = flow::register(GinRouter::new())
        .with_state(state.clone())
        .into_router(&layers);
    Harness {
        router,
        state,
        db,
        clock,
        google,
        github,
    }
}

// ---------------------------------------------------------------- requests

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|value| value.to_str().unwrap())
    }

    pub fn location(&self) -> &str {
        self.header("location").expect("Location header")
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("JSON body")
    }

    pub fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect()
    }

    /// The `auth_sso_session` value set by this response.
    pub fn sso_cookie(&self) -> Option<String> {
        self.set_cookies().into_iter().find_map(|cookie| {
            cookie
                .strip_prefix("auth_sso_session=")
                .map(|rest| rest.split(';').next().unwrap_or_default().to_owned())
        })
    }

    #[track_caller]
    pub fn assert_json(&self, status: StatusCode, body: &str) {
        assert_eq!(self.status, status, "body: {}", self.body);
        assert_eq!(
            self.header("content-type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(self.body, body);
    }

    #[track_caller]
    pub fn assert_found(&self, location: &str) {
        assert_eq!(self.status, StatusCode::FOUND, "body: {}", self.body);
        assert_eq!(self.location(), location);
    }
}

impl Harness {
    pub async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        Reply {
            status,
            headers,
            body: String::from_utf8(body.to_vec()).unwrap(),
        }
    }

    pub async fn get(&self, path_and_query: &str, cookie: Option<&str>) -> Reply {
        let mut builder = Request::builder().method(Method::GET).uri(path_and_query);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(builder.body(Body::empty()).unwrap()).await
    }

    pub async fn post(&self, path: &str, body: &str, cookie: Option<&str>) -> Reply {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(builder.body(Body::from(body.to_owned())).unwrap())
            .await
    }

    pub async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
        cookie: Option<&str>,
    ) -> Reply {
        self.post(path, &body.to_string(), cookie).await
    }
}

/// A valid authorize request for [`CLIENT`] as `(key, value)` pairs.
pub fn oauth_params(scope: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_owned()),
        ("client_id", CLIENT.to_owned()),
        ("redirect_uri", CALLBACK.to_owned()),
        ("scope", scope.to_owned()),
        ("state", "st 1&x".to_owned()),
        ("nonce", "n".to_owned()),
        ("code_challenge", CHALLENGE.to_owned()),
        ("code_challenge_method", "S256".to_owned()),
    ]
}

pub fn with(
    mut params: Vec<(&'static str, String)>,
    key: &'static str,
    value: &str,
) -> Vec<(&'static str, String)> {
    params.retain(|(k, _)| *k != key);
    params.push((key, value.to_owned()));
    params
}

pub fn json_body(params: &[(&'static str, String)]) -> serde_json::Value {
    serde_json::Value::Object(
        params
            .iter()
            .map(|(k, v)| ((*k).to_owned(), serde_json::Value::from(v.as_str())))
            .collect(),
    )
}

/// Go `url.QueryEscape`-encoded query (sorted, like `Values.Encode`).
pub fn encode(params: &[(&str, String)]) -> String {
    let mut sorted: Vec<_> = params.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                auth_http::go_url::query_escape(k),
                auth_http::go_url::query_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}
