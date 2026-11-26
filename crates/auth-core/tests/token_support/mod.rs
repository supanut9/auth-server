//! In-memory fakes for `TokenService` tests (port of the Go
//! `token/service_test.go` fakes).
#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use auth_core::crypto::gojson;
use auth_core::domain::{
    AccessTokenRecord, AccessTokenRecordId, ChainId, RefreshToken, RefreshTokenChain,
    RefreshTokenChainStatus, RefreshTokenId, SessionId, SsoSession, SsoSessionStatus,
};
use auth_core::ports::{
    AccessTokenRepository, Clock, IdGenerator, JwtClaims, JwtError, JwtSigner, RandomError,
    RandomSource, RefreshTokenChainRepository, RefreshTokenRepository, RepoError, RepoResult,
    SignedJwt, SsoSessionRepository,
};
use auth_core::token::{TokenConfig, TokenService, TokenServiceDeps};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

pub const NOW: OffsetDateTime = datetime!(2026-04-01 12:00 UTC);
pub const SESSION_ID: &str = "sso-123";

/// The config every Go service test uses (`RefreshReuseGrace` varies).
pub fn config(grace: Duration) -> TokenConfig {
    TokenConfig {
        issuer: "http://localhost:8050".into(),
        audience: "platform-api".into(),
        access_token_ttl: Duration::minutes(10),
        id_token_ttl: Duration::minutes(10),
        refresh_token_absolute_ttl: Duration::days(30),
        refresh_token_inactive_ttl: Duration::days(7),
        refresh_reuse_grace: grace,
    }
}

/// Settable clock.
pub struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    pub fn new(now: OffsetDateTime) -> Self {
        Self(Mutex::new(now))
    }

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

/// Hands out scripted IDs first, then `id-N`.
#[derive(Default)]
pub struct TestIds {
    scripted: Mutex<VecDeque<String>>,
    next: AtomicU64,
}

impl TestIds {
    pub fn scripted(ids: &[&str]) -> Self {
        Self {
            scripted: Mutex::new(ids.iter().map(|id| (*id).to_owned()).collect()),
            next: AtomicU64::new(0),
        }
    }
}

impl IdGenerator for TestIds {
    fn new_id(&self) -> String {
        if let Some(id) = self.scripted.lock().unwrap().pop_front() {
            return id;
        }
        format!("id-{}", self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

/// Counter-based random bytes (distinct per call); can be made to fail.
#[derive(Default)]
pub struct TestRandom {
    counter: AtomicU64,
    pub fail: AtomicBool,
}

impl RandomSource for TestRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(RandomError::new("entropy unavailable"));
        }
        let n = self.counter.fetch_add(1, Ordering::SeqCst).to_be_bytes();
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = n[i % n.len()] ^ (i as u8);
        }
        Ok(())
    }
}

/// Records every claim set; the token is `jwt-N.<Go JSON claims>`.
#[derive(Default)]
pub struct RecordingSigner {
    pub claims: Mutex<Vec<JwtClaims>>,
    pub fail: AtomicBool,
}

impl RecordingSigner {
    pub fn recorded(&self) -> Vec<JwtClaims> {
        self.claims.lock().unwrap().clone()
    }

    /// Go `json.Marshal` bytes of the `index`-th signed claim set.
    pub fn claims_json(&self, index: usize) -> String {
        gojson::to_string(&serde_json::Value::Object(self.recorded()[index].clone()))
    }
}

impl JwtSigner for RecordingSigner {
    fn sign(&self, claims: &JwtClaims) -> Result<SignedJwt, JwtError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(JwtError::new("signer unavailable"));
        }
        let mut all = self.claims.lock().unwrap();
        all.push(claims.clone());
        Ok(SignedJwt {
            token: format!(
                "jwt-{}.{}",
                all.len(),
                gojson::to_string(&serde_json::Value::Object(claims.clone()))
            ),
            key_id: "test-kid".into(),
            alg: "RS256".into(),
        })
    }
}

#[derive(Default)]
pub struct MemoryAccessTokens {
    pub records: Mutex<Vec<AccessTokenRecord>>,
}

impl MemoryAccessTokens {
    pub fn all(&self) -> Vec<AccessTokenRecord> {
        self.records.lock().unwrap().clone()
    }
}

#[async_trait]
impl AccessTokenRepository for MemoryAccessTokens {
    async fn create(&self, mut record: AccessTokenRecord) -> RepoResult<AccessTokenRecord> {
        let mut records = self.records.lock().unwrap();
        if record.id.is_empty() {
            record.id = AccessTokenRecordId::new(format!("at-{}", records.len() + 1));
        }
        records.push(record.clone());
        Ok(record)
    }
}

#[derive(Default)]
pub struct MemorySessions {
    pub sessions: Mutex<BTreeMap<String, SsoSession>>,
}

impl MemorySessions {
    pub fn put(&self, session: SsoSession) {
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id.as_str().to_owned(), session);
    }

    pub fn remove(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }

    pub fn active(id: &str, expires_at: OffsetDateTime) -> SsoSession {
        SsoSession {
            id: SessionId::new(id),
            status: SsoSessionStatus::Active,
            expires_at,
            ..SsoSession::default()
        }
    }
}

#[async_trait]
impl SsoSessionRepository for MemorySessions {
    async fn create(&self, session: SsoSession) -> RepoResult<SsoSession> {
        self.put(session.clone());
        Ok(session)
    }

    async fn find_by_id(&self, id: &SessionId) -> RepoResult<SsoSession> {
        self.sessions
            .lock()
            .unwrap()
            .get(id.as_str())
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn update(&self, session: SsoSession) -> RepoResult<SsoSession> {
        self.put(session.clone());
        Ok(session)
    }

    async fn revoke_by_id(&self, id: &SessionId) -> RepoResult<()> {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(id.as_str()) {
            session.status = SsoSessionStatus::Revoked;
            session.revoked_at = Some(NOW);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryChains {
    pub chains: Mutex<BTreeMap<String, RefreshTokenChain>>,
    pub updates: AtomicU64,
}

impl MemoryChains {
    pub fn get(&self, id: &ChainId) -> RefreshTokenChain {
        self.chains.lock().unwrap()[id.as_str()].clone()
    }

    pub fn only(&self) -> RefreshTokenChain {
        let chains = self.chains.lock().unwrap();
        assert_eq!(chains.len(), 1, "expected exactly one chain");
        chains.values().next().unwrap().clone()
    }

    pub fn edit(&self, id: &ChainId, f: impl FnOnce(&mut RefreshTokenChain)) {
        f(self.chains.lock().unwrap().get_mut(id.as_str()).unwrap());
    }

    pub fn remove(&self, id: &ChainId) {
        self.chains.lock().unwrap().remove(id.as_str());
    }
}

#[async_trait]
impl RefreshTokenChainRepository for MemoryChains {
    async fn create(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        self.chains
            .lock()
            .unwrap()
            .insert(chain.id.as_str().to_owned(), chain.clone());
        Ok(chain)
    }

    async fn find_by_id(&self, id: &ChainId) -> RepoResult<RefreshTokenChain> {
        self.chains
            .lock()
            .unwrap()
            .get(id.as_str())
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn list_active_ids_by_sso_session_id(
        &self,
        sso_session_id: &SessionId,
    ) -> RepoResult<Vec<ChainId>> {
        Ok(self
            .chains
            .lock()
            .unwrap()
            .values()
            .filter(|c| {
                &c.sso_session_id == sso_session_id
                    && c.status == RefreshTokenChainStatus::Active
                    && c.revoked_at.is_none()
            })
            .map(|c| c.id.clone())
            .collect())
    }

    async fn update(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        self.updates.fetch_add(1, Ordering::SeqCst);
        self.chains
            .lock()
            .unwrap()
            .insert(chain.id.as_str().to_owned(), chain.clone());
        Ok(chain)
    }

    async fn revoke_by_id(&self, id: &ChainId) -> RepoResult<()> {
        if let Some(chain) = self.chains.lock().unwrap().get_mut(id.as_str()) {
            chain.status = RefreshTokenChainStatus::Revoked;
            chain.revoked_at = Some(NOW);
        }
        Ok(())
    }
}

/// Assigns `rt-N` IDs on create, like the real adapter assigns UUIDv7s.
#[derive(Default)]
pub struct MemoryRefreshTokens {
    pub tokens: Mutex<Vec<RefreshToken>>,
}

impl MemoryRefreshTokens {
    pub fn all(&self) -> Vec<RefreshToken> {
        self.tokens.lock().unwrap().clone()
    }

    pub fn by_hash(&self, hash: &str) -> RefreshToken {
        self.all()
            .into_iter()
            .find(|t| t.token_hash == hash)
            .expect("token by hash")
    }

    pub fn edit_by_hash(&self, hash: &str, f: impl FnOnce(&mut RefreshToken)) {
        let mut tokens = self.tokens.lock().unwrap();
        f(tokens.iter_mut().find(|t| t.token_hash == hash).unwrap());
    }
}

#[async_trait]
impl RefreshTokenRepository for MemoryRefreshTokens {
    async fn create(&self, mut token: RefreshToken) -> RepoResult<RefreshToken> {
        let mut tokens = self.tokens.lock().unwrap();
        if token.id.is_empty() {
            token.id = RefreshTokenId::new(format!("rt-{}", tokens.len() + 1));
        }
        tokens.push(token.clone());
        Ok(token)
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> RepoResult<RefreshToken> {
        self.tokens
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.token_hash == token_hash)
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn update(&self, token: RefreshToken) -> RepoResult<RefreshToken> {
        let mut tokens = self.tokens.lock().unwrap();
        let slot = tokens
            .iter_mut()
            .find(|t| t.id == token.id)
            .ok_or(RepoError::NotFound)?;
        *slot = token.clone();
        Ok(token)
    }

    async fn revoke_by_chain_id(&self, chain_id: &ChainId) -> RepoResult<()> {
        for token in self.tokens.lock().unwrap().iter_mut() {
            if &token.refresh_token_chain_id == chain_id {
                token.revoked_at = Some(NOW);
            }
        }
        Ok(())
    }
}

/// A service wired to fresh fakes, with handles to inspect them.
pub struct Harness {
    pub clock: Arc<TestClock>,
    pub ids: Arc<TestIds>,
    pub random: Arc<TestRandom>,
    pub signer: Arc<RecordingSigner>,
    pub access: Arc<MemoryAccessTokens>,
    pub sessions: Arc<MemorySessions>,
    pub chains: Arc<MemoryChains>,
    pub refresh: Arc<MemoryRefreshTokens>,
    pub service: TokenService,
}

impl Harness {
    pub fn new(config: TokenConfig, ids: TestIds) -> Self {
        let clock = Arc::new(TestClock::new(NOW));
        let ids = Arc::new(ids);
        let random = Arc::new(TestRandom::default());
        let signer = Arc::new(RecordingSigner::default());
        let access = Arc::new(MemoryAccessTokens::default());
        let sessions = Arc::new(MemorySessions::default());
        let chains = Arc::new(MemoryChains::default());
        let refresh = Arc::new(MemoryRefreshTokens::default());
        let service = TokenService::new(
            config,
            TokenServiceDeps {
                clock: clock.clone(),
                ids: ids.clone(),
                random: random.clone(),
                signer: signer.clone(),
                access_tokens: access.clone(),
                sso_sessions: sessions.clone(),
                refresh_token_chains: chains.clone(),
                refresh_tokens: refresh.clone(),
            },
        );
        Self {
            clock,
            ids,
            random,
            signer,
            access,
            sessions,
            chains,
            refresh,
            service,
        }
    }

    /// Go-test default: grace off, sequential IDs, active `sso-123` for 1h.
    pub fn standard(grace: Duration) -> Self {
        let harness = Self::new(config(grace), TestIds::default());
        harness
            .sessions
            .put(MemorySessions::active(SESSION_ID, NOW + Duration::hours(1)));
        harness
    }
}
