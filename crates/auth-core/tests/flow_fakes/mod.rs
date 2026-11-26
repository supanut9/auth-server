//! In-memory ports for the flow service tests (port of the fakes in
//! `internal/application/flow/service_test.go`).
//!
//! Every repository call is appended to a shared [`CallLog`] so tests can
//! assert call order, and any call can be made to fail by name.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use auth_core::domain::{
    AccountId, AuthorizationCode, AuthorizationCodeId, ChainId, ClientId, ConsentGrant,
    ConsentGrantId, RefreshToken, RefreshTokenChain, RefreshTokenChainStatus, SessionId,
    SsoSession, SsoSessionStatus,
};
use auth_core::flow::{FlowConfig, FlowPorts, FlowService};
use auth_core::ports::{
    AuthorizationCodeRepository, Clock, ConsentGrantRepository, IdGenerator, RandomError,
    RandomSource, RefreshTokenChainRepository, RefreshTokenRepository, RepoError, RepoResult,
    SsoSessionRepository,
};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

/// 2026-04-01T12:00:00Z, the Go test's fixed clock.
pub const NOW: OffsetDateTime = datetime!(2026-04-01 12:00 UTC);
/// Instant the fakes stamp on revoked rows (Go fakes used `time.Now()`).
pub const REVOKED_AT: OffsetDateTime = datetime!(2026-04-01 12:30 UTC);

pub fn config() -> FlowConfig {
    FlowConfig {
        authorization_code_ttl: Duration::minutes(5),
        sso_session_ttl: Duration::hours(24),
    }
}

/// Shared, ordered log of repository calls plus failure injection.
#[derive(Default)]
pub struct CallLog {
    calls: Mutex<Vec<String>>,
    failing: Mutex<BTreeSet<String>>,
}

impl CallLog {
    /// Records `call` and fails it when its name (the part before `(`) was
    /// registered with [`CallLog::fail`].
    fn record(&self, call: String) -> RepoResult<()> {
        let name = call.split('(').next().unwrap_or_default().to_owned();
        self.calls.lock().expect("lock").push(call);
        if self.failing.lock().expect("lock").contains(&name) {
            return Err(RepoError::other(format!("{name} failed")));
        }
        Ok(())
    }

    pub fn fail(&self, name: &str) {
        self.failing.lock().expect("lock").insert(name.to_owned());
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("lock").clone()
    }

    pub fn clear(&self) {
        self.calls.lock().expect("lock").clear();
    }
}

pub struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    pub fn set(&self, now: OffsetDateTime) {
        *self.0.lock().expect("lock") = now;
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("lock")
    }
}

/// Go `sequentialIDs`. Never called by the flow service.
#[derive(Default)]
pub struct SequentialIds(Mutex<u64>);

impl IdGenerator for SequentialIds {
    fn new_id(&self) -> String {
        let mut next = self.0.lock().expect("lock");
        *next += 1;
        format!("id-{next}")
    }
}

/// Hands out queued bytes; when the queue is empty it yields a counter
/// pattern, unless `exhausted` is set, in which case it fails.
#[derive(Default)]
pub struct TestRandom {
    queued: Mutex<VecDeque<u8>>,
    counter: Mutex<u8>,
    exhausted: Mutex<bool>,
    draws: Mutex<usize>,
}

impl TestRandom {
    pub fn push(&self, bytes: impl IntoIterator<Item = u8>) {
        self.queued.lock().expect("lock").extend(bytes);
    }

    pub fn fail(&self) {
        *self.exhausted.lock().expect("lock") = true;
    }

    pub fn draws(&self) -> usize {
        *self.draws.lock().expect("lock")
    }
}

impl RandomSource for TestRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        *self.draws.lock().expect("lock") += 1;
        if *self.exhausted.lock().expect("lock") {
            return Err(RandomError::new("random source exhausted"));
        }
        let mut queued = self.queued.lock().expect("lock");
        let mut counter = self.counter.lock().expect("lock");
        for byte in dest.iter_mut() {
            *byte = queued.pop_front().unwrap_or_else(|| {
                *counter = counter.wrapping_add(1);
                *counter
            });
        }
        Ok(())
    }
}

/// Go `memoryAuthorizationCodeRepo`, except that an unknown hash returns
/// `NotFound` like the real adapter.
pub struct MemoryCodes {
    log: Arc<CallLog>,
    pub items: Mutex<BTreeMap<String, AuthorizationCode>>,
}

impl MemoryCodes {
    pub fn get(&self, id: &str) -> AuthorizationCode {
        self.items.lock().expect("lock")[id].clone()
    }

    pub fn insert(&self, code: AuthorizationCode) {
        self.items
            .lock()
            .expect("lock")
            .insert(code.id.to_string(), code);
    }

    pub fn len(&self) -> usize {
        self.items.lock().expect("lock").len()
    }
}

#[async_trait]
impl AuthorizationCodeRepository for MemoryCodes {
    async fn create(&self, mut code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        self.log
            .record(format!("codes.create({})", code.code_hash))?;
        let mut items = self.items.lock().expect("lock");
        if code.id.is_empty() {
            code.id = AuthorizationCodeId::new(format!("code-{}", items.len() + 1));
        }
        items.insert(code.id.to_string(), code.clone());
        Ok(code)
    }

    async fn find_by_code_hash(&self, code_hash: &str) -> RepoResult<AuthorizationCode> {
        self.log
            .record(format!("codes.find_by_code_hash({code_hash})"))?;
        self.items
            .lock()
            .expect("lock")
            .values()
            .find(|code| code.code_hash == code_hash)
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn update(&self, code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        self.log.record(format!("codes.update({})", code.id))?;
        self.items
            .lock()
            .expect("lock")
            .insert(code.id.to_string(), code.clone());
        Ok(code)
    }
}

/// Go `memoryConsentGrantRepo`; a missing grant returns `NotFound`. `upsert`
/// stores exactly what the service passes, except that an empty ID is
/// assigned.
pub struct MemoryConsents {
    log: Arc<CallLog>,
    pub items: Mutex<BTreeMap<(String, String), ConsentGrant>>,
    /// Every grant passed to `upsert`, as received.
    pub upserts: Mutex<Vec<ConsentGrant>>,
}

impl MemoryConsents {
    pub fn insert(&self, grant: ConsentGrant) {
        self.items.lock().expect("lock").insert(
            (grant.account_id.to_string(), grant.client_id.to_string()),
            grant,
        );
    }

    pub fn get(&self, account_id: &str, client_id: &str) -> Option<ConsentGrant> {
        self.items
            .lock()
            .expect("lock")
            .get(&(account_id.to_owned(), client_id.to_owned()))
            .cloned()
    }

    pub fn upserts(&self) -> Vec<ConsentGrant> {
        self.upserts.lock().expect("lock").clone()
    }
}

#[async_trait]
impl ConsentGrantRepository for MemoryConsents {
    async fn find_by_account_and_client(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
    ) -> RepoResult<ConsentGrant> {
        self.log.record(format!(
            "consents.find_by_account_and_client({account_id}|{client_id})"
        ))?;
        self.get(account_id.as_str(), client_id.as_str())
            .ok_or(RepoError::NotFound)
    }

    async fn upsert(&self, mut grant: ConsentGrant) -> RepoResult<ConsentGrant> {
        self.log.record(format!(
            "consents.upsert({}|{})",
            grant.account_id, grant.client_id
        ))?;
        self.upserts.lock().expect("lock").push(grant.clone());
        if grant.id.is_empty() {
            grant.id = ConsentGrantId::new(format!("consent-{}", self.upserts().len()));
        }
        self.insert(grant.clone());
        Ok(grant)
    }
}

/// Go `memorySSOSessionRepo`.
pub struct MemorySessions {
    log: Arc<CallLog>,
    pub items: Mutex<BTreeMap<String, SsoSession>>,
}

impl MemorySessions {
    pub fn insert(&self, session: SsoSession) {
        self.items
            .lock()
            .expect("lock")
            .insert(session.id.to_string(), session);
    }

    pub fn get(&self, id: &str) -> SsoSession {
        self.items.lock().expect("lock")[id].clone()
    }
}

#[async_trait]
impl SsoSessionRepository for MemorySessions {
    async fn create(&self, mut session: SsoSession) -> RepoResult<SsoSession> {
        self.log
            .record(format!("sessions.create({})", session.account_id))?;
        let mut items = self.items.lock().expect("lock");
        if session.id.is_empty() {
            // Stand-in for the adapter's UUIDv7.
            session.id = SessionId::new(format!("0190a000-0000-7000-8000-{:012}", items.len() + 1));
        }
        items.insert(session.id.to_string(), session.clone());
        Ok(session)
    }

    async fn find_by_id(&self, id: &SessionId) -> RepoResult<SsoSession> {
        self.log.record(format!("sessions.find_by_id({id})"))?;
        self.items
            .lock()
            .expect("lock")
            .get(id.as_str())
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn update(&self, session: SsoSession) -> RepoResult<SsoSession> {
        self.log
            .record(format!("sessions.update({})", session.id))?;
        self.insert(session.clone());
        Ok(session)
    }

    async fn revoke_by_id(&self, id: &SessionId) -> RepoResult<()> {
        self.log.record(format!("sessions.revoke_by_id({id})"))?;
        if let Some(session) = self.items.lock().expect("lock").get_mut(id.as_str()) {
            session.status = SsoSessionStatus::Revoked;
            session.revoked_at = Some(REVOKED_AT);
        }
        Ok(())
    }
}

/// Go `memoryRefreshChainRepo`; `find_by_id` returns `NotFound` like the
/// adapter (Go `port.ErrRefreshTokenChainNotFound`).
pub struct MemoryChains {
    log: Arc<CallLog>,
    pub items: Mutex<BTreeMap<String, RefreshTokenChain>>,
}

impl MemoryChains {
    pub fn insert(&self, chain: RefreshTokenChain) {
        self.items
            .lock()
            .expect("lock")
            .insert(chain.id.to_string(), chain);
    }

    pub fn get(&self, id: &str) -> RefreshTokenChain {
        self.items.lock().expect("lock")[id].clone()
    }
}

#[async_trait]
impl RefreshTokenChainRepository for MemoryChains {
    async fn create(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        self.log.record(format!("chains.create({})", chain.id))?;
        self.insert(chain.clone());
        Ok(chain)
    }

    async fn find_by_id(&self, id: &ChainId) -> RepoResult<RefreshTokenChain> {
        self.log.record(format!("chains.find_by_id({id})"))?;
        self.items
            .lock()
            .expect("lock")
            .get(id.as_str())
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn list_active_ids_by_sso_session_id(
        &self,
        sso_session_id: &SessionId,
    ) -> RepoResult<Vec<ChainId>> {
        self.log.record(format!(
            "chains.list_active_ids_by_sso_session_id({sso_session_id})"
        ))?;
        Ok(self
            .items
            .lock()
            .expect("lock")
            .values()
            .filter(|chain| {
                chain.sso_session_id == *sso_session_id
                    && chain.status == RefreshTokenChainStatus::Active
                    && chain.revoked_at.is_none()
            })
            .map(|chain| chain.id.clone())
            .collect())
    }

    async fn update(&self, chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        self.log.record(format!("chains.update({})", chain.id))?;
        self.insert(chain.clone());
        Ok(chain)
    }

    async fn revoke_by_id(&self, id: &ChainId) -> RepoResult<()> {
        self.log.record(format!("chains.revoke_by_id({id})"))?;
        if let Some(chain) = self.items.lock().expect("lock").get_mut(id.as_str()) {
            chain.status = RefreshTokenChainStatus::Revoked;
            chain.revoked_at = Some(REVOKED_AT);
        }
        Ok(())
    }
}

/// Go `memoryRefreshTokenRepo`.
pub struct MemoryTokens {
    log: Arc<CallLog>,
    pub items: Mutex<BTreeMap<String, RefreshToken>>,
}

impl MemoryTokens {
    pub fn insert(&self, token: RefreshToken) {
        self.items
            .lock()
            .expect("lock")
            .insert(token.id.to_string(), token);
    }

    pub fn get(&self, id: &str) -> RefreshToken {
        self.items.lock().expect("lock")[id].clone()
    }
}

#[async_trait]
impl RefreshTokenRepository for MemoryTokens {
    async fn create(&self, token: RefreshToken) -> RepoResult<RefreshToken> {
        self.log.record(format!("tokens.create({})", token.id))?;
        Ok(token)
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> RepoResult<RefreshToken> {
        self.log
            .record(format!("tokens.find_by_token_hash({token_hash})"))?;
        Err(RepoError::NotFound)
    }

    async fn update(&self, token: RefreshToken) -> RepoResult<RefreshToken> {
        self.log.record(format!("tokens.update({})", token.id))?;
        Ok(token)
    }

    async fn revoke_by_chain_id(&self, chain_id: &ChainId) -> RepoResult<()> {
        self.log
            .record(format!("tokens.revoke_by_chain_id({chain_id})"))?;
        for token in self.items.lock().expect("lock").values_mut() {
            if token.refresh_token_chain_id == *chain_id {
                token.revoked_at = Some(REVOKED_AT);
            }
        }
        Ok(())
    }
}

/// A service wired to fresh fakes, with handles to each fake.
pub struct Harness {
    pub service: FlowService,
    pub log: Arc<CallLog>,
    pub clock: Arc<TestClock>,
    pub random: Arc<TestRandom>,
    pub codes: Arc<MemoryCodes>,
    pub consents: Arc<MemoryConsents>,
    pub sessions: Arc<MemorySessions>,
    pub chains: Arc<MemoryChains>,
    pub tokens: Arc<MemoryTokens>,
}

impl Harness {
    pub fn new() -> Self {
        let log = Arc::new(CallLog::default());
        let clock = Arc::new(TestClock(Mutex::new(NOW)));
        let random = Arc::new(TestRandom::default());
        let codes = Arc::new(MemoryCodes {
            log: log.clone(),
            items: Mutex::default(),
        });
        let consents = Arc::new(MemoryConsents {
            log: log.clone(),
            items: Mutex::default(),
            upserts: Mutex::default(),
        });
        let sessions = Arc::new(MemorySessions {
            log: log.clone(),
            items: Mutex::default(),
        });
        let chains = Arc::new(MemoryChains {
            log: log.clone(),
            items: Mutex::default(),
        });
        let tokens = Arc::new(MemoryTokens {
            log: log.clone(),
            items: Mutex::default(),
        });
        let service = FlowService::new(
            config(),
            FlowPorts {
                clock: clock.clone(),
                id_generator: Arc::new(SequentialIds::default()),
                random: random.clone(),
                authorization_codes: codes.clone(),
                consent_grants: consents.clone(),
                sso_sessions: sessions.clone(),
                refresh_token_chains: chains.clone(),
                refresh_tokens: tokens.clone(),
            },
        );
        Self {
            service,
            log,
            clock,
            random,
            codes,
            consents,
            sessions,
            chains,
            tokens,
        }
    }
}

pub fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}
