//! `IdentityService` ordering rules (Go `internal/application/identity/
//! service.go`) with in-memory fakes and a controllable clock, plus the OTP
//! vectors of `testdata/golden/hashes.json` driven through the service.

mod golden_support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use auth_core::crypto::{RandomOtpCodeGenerator, sha256_b64url};
use auth_core::domain::{
    Account, AccountId, AccountProvider, AccountProviderId, AccountStatus, OtpChallenge,
    OtpChallengeId, SessionId, SsoSession, SsoSessionStatus, ZERO_TIME,
};
use auth_core::flow::FlowError;
use auth_core::identity::{
    FixedOtpCodeGenerator, IdentityConfig, IdentityDeps, IdentityError, IdentityService,
    OtpResendRequest, OtpStartRequest, OtpVerifyRequest, ProviderLoginRequest, SsoSessionStarter,
};
use auth_core::ports::{
    AccountProviderRepository, AccountRepository, Clock, MailError, OtpChallengeRepository,
    OtpCodeGenerator, OtpMailer, RepoError, RepoResult,
};
use golden_support::{ScriptedRandom, cases, load, opt, s};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const T0: OffsetDateTime = datetime!(2026-01-02 03:04:05 UTC);
const CODE: &str = "AbCd-_12";

// ---------------------------------------------------------------- fakes ---

struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    fn set(&self, now: OffsetDateTime) {
        *self.0.lock().expect("lock") = now;
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().expect("lock") += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("lock")
    }
}

#[derive(Default)]
struct MemAccounts {
    rows: Mutex<Vec<Account>>,
    created: Mutex<Vec<Account>>,
}

#[async_trait]
impl AccountRepository for MemAccounts {
    async fn create(&self, mut account: Account) -> RepoResult<Account> {
        let mut rows = self.rows.lock().expect("lock");
        self.created.lock().expect("lock").push(account.clone());
        account.id = AccountId::new(format!("acc-{}", rows.len() + 1));
        rows.push(account.clone());
        Ok(account)
    }

    async fn find_by_id(&self, id: &AccountId) -> RepoResult<Account> {
        let rows = self.rows.lock().expect("lock");
        rows.iter()
            .find(|a| &a.id == id)
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn find_by_primary_verified_email(&self, email: &str) -> RepoResult<Account> {
        let rows = self.rows.lock().expect("lock");
        rows.iter()
            .find(|a| a.primary_verified_email.to_lowercase() == email.to_lowercase())
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn update(&self, account: Account) -> RepoResult<Account> {
        panic!("identity service never updates accounts: {account:?}");
    }
}

#[derive(Default)]
struct MemProviders {
    rows: Mutex<Vec<AccountProvider>>,
    /// Lookups fail with a non-"not found" error (Go still falls through).
    lookup_fails: AtomicBool,
}

#[async_trait]
impl AccountProviderRepository for MemProviders {
    async fn create(&self, mut provider: AccountProvider) -> RepoResult<AccountProvider> {
        let mut rows = self.rows.lock().expect("lock");
        provider.id = AccountProviderId::new(format!("ap-{}", rows.len() + 1));
        rows.push(provider.clone());
        Ok(provider)
    }

    async fn find_by_provider_account_id(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> RepoResult<AccountProvider> {
        if self.lookup_fails.load(Ordering::SeqCst) {
            return Err(RepoError::other("db down"));
        }
        let rows = self.rows.lock().expect("lock");
        rows.iter()
            .find(|p| p.provider == provider && p.provider_account_id == provider_account_id)
            .cloned()
            .ok_or(RepoError::NotFound)
    }

    async fn find_by_account_id_and_provider(
        &self,
        _account_id: &AccountId,
        _provider: &str,
    ) -> RepoResult<AccountProvider> {
        panic!("not used by the identity service");
    }
}

#[derive(Default)]
struct MemOtp {
    rows: Mutex<BTreeMap<String, OtpChallenge>>,
    updates: Mutex<usize>,
    update_fails: AtomicBool,
}

impl MemOtp {
    fn get(&self, id: &OtpChallengeId) -> OtpChallenge {
        self.rows.lock().expect("lock")[id.as_str()].clone()
    }

    fn put(&self, challenge: OtpChallenge) {
        self.rows
            .lock()
            .expect("lock")
            .insert(challenge.id.to_string(), challenge);
    }

    fn update_count(&self) -> usize {
        *self.updates.lock().expect("lock")
    }
}

#[async_trait]
impl OtpChallengeRepository for MemOtp {
    async fn create(&self, mut challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        let mut rows = self.rows.lock().expect("lock");
        challenge.id = OtpChallengeId::new(format!("otp-{}", rows.len() + 1));
        rows.insert(challenge.id.to_string(), challenge.clone());
        Ok(challenge)
    }

    async fn find_active_by_request_and_email(
        &self,
        _request_id: &str,
        _email: &str,
    ) -> RepoResult<OtpChallenge> {
        panic!("not used by the stateless flow");
    }

    async fn find_by_id(&self, id: &OtpChallengeId) -> RepoResult<OtpChallenge> {
        let rows = self.rows.lock().expect("lock");
        rows.get(id.as_str()).cloned().ok_or(RepoError::NotFound)
    }

    async fn update(&self, challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        *self.updates.lock().expect("lock") += 1;
        if self.update_fails.load(Ordering::SeqCst) {
            return Err(RepoError::other("update failed"));
        }
        self.put(challenge.clone());
        Ok(challenge)
    }

    async fn find_latest_active_by_email(&self, _email: &str) -> RepoResult<OtpChallenge> {
        panic!("not used by the identity service");
    }
}

#[derive(Default)]
struct FakeSessions {
    started: Mutex<Vec<(AccountId, String)>>,
}

impl FakeSessions {
    fn started(&self) -> Vec<(String, String)> {
        self.started
            .lock()
            .expect("lock")
            .iter()
            .map(|(a, m)| (a.to_string(), m.clone()))
            .collect()
    }
}

#[async_trait]
impl SsoSessionStarter for FakeSessions {
    async fn start_sso_session(
        &self,
        account_id: &AccountId,
        login_method: &str,
    ) -> Result<SsoSession, FlowError> {
        let mut started = self.started.lock().expect("lock");
        started.push((account_id.clone(), login_method.to_owned()));
        Ok(SsoSession {
            id: SessionId::new(format!("sess-{}", started.len())),
            account_id: account_id.clone(),
            status: SsoSessionStatus::Active,
            login_method: login_method.to_owned(),
            ..SsoSession::default()
        })
    }
}

#[derive(Default)]
struct RecordingMailer {
    sent: Mutex<Vec<(String, String, OffsetDateTime)>>,
    fails: AtomicBool,
}

impl RecordingMailer {
    fn sent(&self) -> Vec<(String, String, OffsetDateTime)> {
        self.sent.lock().expect("lock").clone()
    }
}

#[async_trait]
impl OtpMailer for RecordingMailer {
    async fn send_otp(
        &self,
        to: &str,
        code: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), MailError> {
        self.sent
            .lock()
            .expect("lock")
            .push((to.to_owned(), code.to_owned(), expires_at));
        if self.fails.load(Ordering::SeqCst) {
            return Err(MailError::new("smtp down"));
        }
        Ok(())
    }
}

/// Hands out codes in order.
struct ScriptedCodes(Mutex<Vec<String>>);

impl ScriptedCodes {
    fn new(codes: &[&str]) -> Self {
        Self(Mutex::new(
            codes.iter().rev().map(|c| (*c).to_owned()).collect(),
        ))
    }
}

impl OtpCodeGenerator for ScriptedCodes {
    fn new_code(&self) -> Result<String, auth_core::ports::RandomError> {
        Ok(self.0.lock().expect("lock").pop().expect("code"))
    }
}

struct Harness {
    clock: Arc<TestClock>,
    accounts: Arc<MemAccounts>,
    providers: Arc<MemProviders>,
    otp: Arc<MemOtp>,
    sessions: Arc<FakeSessions>,
    mailer: Arc<RecordingMailer>,
    service: IdentityService,
}

fn config() -> IdentityConfig {
    IdentityConfig {
        otp_challenge_ttl: Duration::minutes(10),
        otp_max_attempts: 6,
        otp_max_resends: 3,
        otp_resend_cooldown: Duration::MINUTE,
    }
}

struct Options {
    config: IdentityConfig,
    generator: Arc<dyn OtpCodeGenerator>,
    with_mailer: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            config: config(),
            generator: Arc::new(FixedOtpCodeGenerator::new(CODE)),
            with_mailer: true,
        }
    }
}

fn harness_with(options: Options) -> Harness {
    let clock = Arc::new(TestClock(Mutex::new(T0)));
    let accounts = Arc::new(MemAccounts::default());
    let providers = Arc::new(MemProviders::default());
    let otp = Arc::new(MemOtp::default());
    let sessions = Arc::new(FakeSessions::default());
    let mailer = Arc::new(RecordingMailer::default());
    let service = IdentityService::new(
        options.config,
        IdentityDeps {
            clock: clock.clone(),
            otp_code_generator: options.generator,
            accounts: accounts.clone(),
            account_providers: providers.clone(),
            otp_challenges: otp.clone(),
            otp_mailer: options
                .with_mailer
                .then(|| mailer.clone() as Arc<dyn OtpMailer>),
            sso_sessions: sessions.clone(),
        },
    );
    Harness {
        clock,
        accounts,
        providers,
        otp,
        sessions,
        mailer,
        service,
    }
}

fn harness() -> Harness {
    harness_with(Options::default())
}

fn err_text<T: std::fmt::Debug>(result: Result<T, IdentityError>) -> String {
    result.expect_err("expected an error").to_string()
}

fn provider_req(email: &str) -> ProviderLoginRequest {
    ProviderLoginRequest {
        provider_name: "google".into(),
        provider_account_id: "g-123".into(),
        email: email.into(),
        email_verified: true,
        display_name: "Alice Doe".into(),
        avatar_url: "https://img.example/a.png".into(),
    }
}

impl Harness {
    async fn start(&self, email: &str) -> OtpChallenge {
        self.service
            .start_otp_challenge(OtpStartRequest {
                email: email.into(),
                purpose: String::new(),
            })
            .await
            .expect("start")
    }

    async fn verify(&self, id: &OtpChallengeId, email: &str, code: &str) -> Result<(), String> {
        self.service
            .verify_otp_challenge(OtpVerifyRequest {
                otp_challenge_id: id.to_string(),
                email: email.into(),
                code: code.into(),
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn resend(&self, id: &OtpChallengeId) -> Result<OtpChallenge, String> {
        self.service
            .resend_otp_challenge(OtpResendRequest {
                otp_challenge_id: id.to_string(),
            })
            .await
            .map_err(|e| e.to_string())
    }

    fn seed_account(&self, email: &str, name: &str) -> Account {
        let account = Account {
            id: AccountId::new(format!("seed-{email}")),
            primary_verified_email: email.into(),
            display_name: name.into(),
            avatar_url: "old.png".into(),
            status: AccountStatus::Active,
            ..Account::default()
        };
        self.accounts
            .rows
            .lock()
            .expect("lock")
            .push(account.clone());
        account
    }
}

// --------------------------------------------------------------- config ---

#[test]
fn limits_default_when_not_positive() {
    let h = harness_with(Options {
        config: IdentityConfig {
            otp_challenge_ttl: Duration::ZERO,
            otp_max_attempts: 0,
            otp_max_resends: 0,
            otp_resend_cooldown: Duration::ZERO,
        },
        ..Options::default()
    });
    assert_eq!(h.service.otp_max_attempts(), 6);
    // OTP_MAX_RESENDS=0 passes config validation but still means 3.
    assert_eq!(h.service.otp_max_resends(), 3);
    assert_eq!(h.service.otp_resend_cooldown(), Duration::seconds(60));

    let h = harness_with(Options {
        config: IdentityConfig {
            otp_challenge_ttl: Duration::minutes(5),
            otp_max_attempts: 2,
            otp_max_resends: 1,
            otp_resend_cooldown: Duration::seconds(5),
        },
        ..Options::default()
    });
    assert_eq!(h.service.otp_max_attempts(), 2);
    assert_eq!(h.service.otp_max_resends(), 1);
    assert_eq!(h.service.otp_resend_cooldown(), Duration::seconds(5));
}

// ------------------------------------------------------- provider login ---

#[tokio::test]
async fn provider_login_requires_verified_non_blank_email() {
    let h = harness();
    for (email, verified) in [("a@x.com", false), ("", true), (" \t ", true)] {
        let mut req = provider_req(email);
        req.email_verified = verified;
        assert_eq!(
            err_text(h.service.handle_provider_login(req).await),
            "provider email verification required"
        );
    }
    assert!(h.accounts.rows.lock().expect("lock").is_empty());
    assert!(h.providers.rows.lock().expect("lock").is_empty());
    assert!(h.sessions.started().is_empty());
}

#[tokio::test]
async fn provider_login_creates_account_and_link() {
    let h = harness();
    let result = h
        .service
        .handle_provider_login(provider_req("Alice@Example.com"))
        .await
        .expect("login");

    let account = &result.account;
    assert_eq!(account.id, "acc-1");
    assert_eq!(account.primary_verified_email, "Alice@Example.com");
    assert_eq!(account.display_name, "Alice Doe");
    assert_eq!(account.avatar_url, "https://img.example/a.png");
    assert_eq!(account.status, AccountStatus::Active);
    assert_eq!(account.created_at, ZERO_TIME, "repository fills timestamps");

    let link = &result.account_provider;
    assert_eq!(link.account_id, "acc-1");
    assert_eq!(link.provider, "google");
    assert_eq!(link.provider_account_id, "g-123");
    assert_eq!(link.provider_email, "Alice@Example.com");
    assert!(link.provider_email_verified);
    assert_eq!(link.profile_name, "Alice Doe");
    assert_eq!(link.profile_avatar_url, "https://img.example/a.png");

    assert_eq!(result.session.login_method, "google");
    assert_eq!(
        h.sessions.started(),
        [("acc-1".to_owned(), "google".to_owned())]
    );
}

#[tokio::test]
async fn provider_login_display_name_falls_back_to_local_part() {
    let h = harness();
    let mut req = provider_req("bob.smith@example.com");
    req.display_name = "   ".into();
    req.avatar_url = String::new();
    let result = h.service.handle_provider_login(req).await.expect("login");
    assert_eq!(result.account.display_name, "bob.smith");
    assert_eq!(result.account.avatar_url, "");
    // The link keeps the raw provider name.
    assert_eq!(result.account_provider.profile_name, "   ");
}

#[tokio::test]
async fn provider_login_links_by_case_insensitive_email() {
    let h = harness();
    let existing = h.seed_account("alice@example.com", "Old Name");

    let result = h
        .service
        .handle_provider_login(provider_req("alice@example.com"))
        .await
        .expect("login");
    assert_eq!(result.account, existing, "profile is not refreshed");
    assert_eq!(result.account_provider.account_id, existing.id);
    assert!(h.accounts.created.lock().expect("lock").is_empty());
    assert_eq!(h.providers.rows.lock().expect("lock").len(), 1);

    // A second verified provider identity can resolve the same email in another case.
    let mut req = provider_req("Alice@example.com");
    req.provider_account_id = "g-999".into();
    let other = h.service.handle_provider_login(req).await.expect("login");
    assert_eq!(other.account, existing);
    assert!(h.accounts.created.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn provider_login_prefers_existing_link_over_email() {
    let h = harness();
    let first = h
        .service
        .handle_provider_login(provider_req("alice@example.com"))
        .await
        .expect("first");

    // Another account owns the new email; the link wins.
    h.seed_account("new@example.com", "Someone");
    let mut req = provider_req("new@example.com");
    req.display_name = "New Name".into();
    req.avatar_url = "new.png".into();
    let second = h.service.handle_provider_login(req).await.expect("second");

    assert_eq!(second.account, first.account, "no profile refresh");
    assert_eq!(second.account_provider, first.account_provider);
    assert_eq!(h.providers.rows.lock().expect("lock").len(), 1);
    assert_eq!(h.accounts.created.lock().expect("lock").len(), 1);
    assert_eq!(h.sessions.started().len(), 2);
}

#[tokio::test]
async fn provider_login_link_lookup_error_falls_through() {
    let h = harness();
    h.service
        .handle_provider_login(provider_req("alice@example.com"))
        .await
        .expect("first");
    h.providers.lookup_fails.store(true, Ordering::SeqCst);
    let again = h
        .service
        .handle_provider_login(provider_req("alice@example.com"))
        .await
        .expect("second");
    // Found by email, and a duplicate link row is inserted, like Go.
    assert_eq!(again.account.id, "acc-1");
    assert_eq!(h.providers.rows.lock().expect("lock").len(), 2);
}

#[tokio::test]
async fn provider_login_missing_linked_account_is_an_error() {
    let h = harness();
    h.providers
        .rows
        .lock()
        .expect("lock")
        .push(AccountProvider {
            account_id: AccountId::new("ghost"),
            provider: "google".into(),
            provider_account_id: "g-123".into(),
            ..AccountProvider::default()
        });
    assert_eq!(
        err_text(
            h.service
                .handle_provider_login(provider_req("alice@example.com"))
                .await
        ),
        "record not found"
    );
}

// ------------------------------------------------------------ otp start ---

#[tokio::test]
async fn otp_start_stores_challenge_and_mails_code() {
    let h = harness();
    let challenge = h
        .service
        .start_otp_challenge(OtpStartRequest {
            email: "  User@Example.COM \n".into(),
            purpose: String::new(),
        })
        .await
        .expect("start");

    assert_eq!(challenge.id, "otp-1");
    assert_eq!(challenge.email, "user@example.com");
    assert_eq!(challenge.purpose, "login");
    assert_eq!(challenge.authorization_request_id, None);
    assert_eq!(challenge.code_hash, sha256_b64url(CODE));
    assert_eq!(challenge.attempt_count, 0);
    assert_eq!(challenge.resend_count, 0);
    assert_eq!(challenge.expires_at, T0 + Duration::minutes(10));
    assert_eq!(challenge.last_sent_at, T0);
    assert_eq!(challenge.created_at, T0);
    assert_eq!(challenge.verified_at, None);

    assert_eq!(
        h.mailer.sent(),
        [(
            "user@example.com".to_owned(),
            CODE.to_owned(),
            T0 + Duration::minutes(10)
        )]
    );
}

#[tokio::test]
async fn otp_start_purpose_is_trimmed() {
    let h = harness();
    let challenge = h
        .service
        .start_otp_challenge(OtpStartRequest {
            email: "a@x.com".into(),
            purpose: " link ".into(),
        })
        .await
        .expect("start");
    assert_eq!(challenge.purpose, "link");
}

#[tokio::test]
async fn otp_start_requires_email() {
    let h = harness();
    for email in ["", "  \t"] {
        let result = h
            .service
            .start_otp_challenge(OtpStartRequest {
                email: email.into(),
                purpose: String::new(),
            })
            .await;
        assert_eq!(err_text(result), "otp email required");
    }
    assert!(h.mailer.sent().is_empty());
}

#[tokio::test]
async fn otp_start_ignores_mail_failure_and_missing_mailer() {
    let h = harness();
    h.mailer.fails.store(true, Ordering::SeqCst);
    h.start("a@x.com").await;
    assert_eq!(h.mailer.sent().len(), 1);

    let h = harness_with(Options {
        with_mailer: false,
        ..Options::default()
    });
    h.start("a@x.com").await;
    assert!(h.mailer.sent().is_empty());
}

#[tokio::test]
async fn otp_start_keeps_older_challenges_valid() {
    let h = harness_with(Options {
        generator: Arc::new(ScriptedCodes::new(&["FIRST111", "SECOND22"])),
        ..Options::default()
    });
    let first = h.start("a@x.com").await;
    h.clock.advance(Duration::seconds(1));
    let second = h.start("a@x.com").await;
    assert_ne!(first.id, second.id);
    assert_eq!(h.otp.get(&first.id), first, "not invalidated");
    assert_eq!(h.verify(&first.id, "a@x.com", "FIRST111").await, Ok(()));
    assert_eq!(h.verify(&second.id, "a@x.com", "SECOND22").await, Ok(()));
}

// ----------------------------------------------------------- otp verify ---

#[tokio::test]
async fn otp_verify_unknown_challenge_is_not_found() {
    let h = harness();
    for id in ["", "   ", "missing"] {
        assert_eq!(
            h.verify(&OtpChallengeId::new(id), "a@x.com", CODE).await,
            Err("otp challenge not found".into())
        );
    }
}

#[tokio::test]
async fn otp_verify_checks_verified_before_email() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    h.verify(&challenge.id, "a@x.com", CODE).await.expect("ok");
    assert_eq!(
        h.verify(&challenge.id, "other@x.com", CODE).await,
        Err("otp challenge invalid".into())
    );
}

#[tokio::test]
async fn otp_verify_email_mismatch_is_not_found() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    assert_eq!(
        h.verify(&challenge.id, "b@x.com", CODE).await,
        Err("otp challenge not found".into())
    );
    assert_eq!(h.otp.get(&challenge.id).attempt_count, 0, "not counted");
    // Case-insensitive and trimmed on both sides.
    assert_eq!(h.verify(&challenge.id, "  A@X.COM ", CODE).await, Ok(()));
}

#[tokio::test]
async fn otp_verify_attempt_limit_precedes_expiry() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    let mut stored = h.otp.get(&challenge.id);
    stored.attempt_count = 6;
    h.otp.put(stored);
    h.clock.advance(Duration::hours(1));
    assert_eq!(
        h.verify(&challenge.id, "a@x.com", CODE).await,
        Err("otp challenge too many attempts".into())
    );
}

#[tokio::test]
async fn otp_verify_expiry_is_strictly_after() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    h.clock.set(challenge.expires_at + Duration::nanoseconds(1));
    assert_eq!(
        h.verify(&challenge.id, "a@x.com", CODE).await,
        Err("otp challenge expired".into())
    );
    assert_eq!(h.otp.get(&challenge.id).attempt_count, 0);

    h.clock.set(challenge.expires_at);
    assert_eq!(h.verify(&challenge.id, "a@x.com", CODE).await, Ok(()));
}

#[tokio::test]
async fn otp_verify_empty_code_is_rejected_without_counting() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    assert_eq!(
        h.verify(&challenge.id, "a@x.com", "").await,
        Err("empty otp code".into())
    );
    assert_eq!(h.otp.get(&challenge.id).attempt_count, 0);
}

#[tokio::test]
async fn otp_verify_wrong_code_counts_until_limit() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    // Comparison is exact: no trimming or case folding of the code.
    for (i, wrong) in ["abcd-_12", " AbCd-_12", "AbCd-_12 ", "x", "y"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            h.verify(&challenge.id, "a@x.com", wrong).await,
            Err("otp challenge invalid".into()),
            "{wrong:?}"
        );
        assert_eq!(
            h.otp.get(&challenge.id).attempt_count,
            i32::try_from(i + 1).expect("i32")
        );
    }
    // The 6th wrong code reaches the limit.
    assert_eq!(
        h.verify(&challenge.id, "a@x.com", "zzz").await,
        Err("otp challenge too many attempts".into())
    );
    assert_eq!(h.otp.get(&challenge.id).attempt_count, 6);
    // Now even the right code fails.
    assert_eq!(
        h.verify(&challenge.id, "a@x.com", CODE).await,
        Err("otp challenge too many attempts".into())
    );
    assert!(h.sessions.started().is_empty());
}

#[tokio::test]
async fn otp_verify_wrong_code_ignores_update_failure() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    h.otp.update_fails.store(true, Ordering::SeqCst);
    assert_eq!(
        h.verify(&challenge.id, "a@x.com", "nope").await,
        Err("otp challenge invalid".into())
    );
    assert_eq!(h.otp.update_count(), 1);
}

#[tokio::test]
async fn otp_verify_success_creates_account_and_session() {
    let h = harness();
    let challenge = h.start("New.User@Example.com").await;
    h.clock.advance(Duration::seconds(30));
    let result = h
        .service
        .verify_otp_challenge(OtpVerifyRequest {
            otp_challenge_id: challenge.id.to_string(),
            email: "new.user@example.com".into(),
            code: CODE.into(),
        })
        .await
        .expect("verify");

    assert_eq!(
        result.account.primary_verified_email,
        "new.user@example.com"
    );
    assert_eq!(result.account.display_name, "new.user");
    assert_eq!(result.account.avatar_url, "");
    assert_eq!(result.account.status, AccountStatus::Active);
    assert_eq!(result.session.login_method, "email_otp");
    assert_eq!(
        h.sessions.started(),
        [(result.account.id.to_string(), "email_otp".to_owned())]
    );

    let stored = h.otp.get(&challenge.id);
    assert_eq!(stored.verified_at, Some(T0 + Duration::seconds(30)));
    assert_eq!(stored.attempt_count, 0);

    assert_eq!(
        h.verify(&challenge.id, "new.user@example.com", CODE).await,
        Err("otp challenge invalid".into()),
        "single use"
    );
}

#[tokio::test]
async fn otp_verify_reuses_account_by_case_insensitive_email() {
    let h = harness();
    let existing = h.seed_account("A@X.COM", "Alice");
    let challenge = h.start("a@x.com").await;
    let result = h
        .service
        .verify_otp_challenge(OtpVerifyRequest {
            otp_challenge_id: challenge.id.to_string(),
            email: "A@x.com".into(),
            code: CODE.into(),
        })
        .await
        .expect("verify");
    assert_eq!(result.account, existing);
    assert!(h.accounts.created.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn otp_verify_success_ignores_update_failure() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    h.otp.update_fails.store(true, Ordering::SeqCst);
    assert_eq!(h.verify(&challenge.id, "a@x.com", CODE).await, Ok(()));
    assert_eq!(h.sessions.started().len(), 1);
}

// ----------------------------------------------------------- otp resend ---

#[tokio::test]
async fn otp_resend_unknown_challenge_is_not_found() {
    let h = harness();
    for id in ["", " ", "missing"] {
        assert_eq!(
            h.resend(&OtpChallengeId::new(id)).await,
            Err("otp challenge not found".into())
        );
    }
}

#[tokio::test]
async fn otp_resend_check_order() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    // Everything is wrong at once: still within the cooldown, resends and
    // attempts used up, already verified.
    let mut stored = h.otp.get(&challenge.id);
    stored.verified_at = Some(T0);
    stored.attempt_count = 6;
    stored.resend_count = 3;
    h.otp.put(stored.clone());
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge invalid".into())
    );

    stored.verified_at = None;
    h.otp.put(stored.clone());
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge too many attempts".into())
    );

    stored.attempt_count = 5;
    h.otp.put(stored.clone());
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge too many resends".into())
    );

    stored.resend_count = 2;
    h.otp.put(stored);
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge throttled".into())
    );
    assert_eq!(h.mailer.sent().len(), 1, "only the start email");
}

#[tokio::test]
async fn otp_resend_cooldown_boundary() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    h.clock
        .set(T0 + Duration::MINUTE - Duration::nanoseconds(1));
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge throttled".into())
    );
    h.clock.set(T0 + Duration::MINUTE);
    assert!(h.resend(&challenge.id).await.is_ok());
}

#[tokio::test]
async fn otp_resend_cooldown_falls_back_to_created_at() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    let mut stored = h.otp.get(&challenge.id);
    stored.last_sent_at = ZERO_TIME;
    stored.created_at = T0 + Duration::seconds(30);
    h.otp.put(stored);
    h.clock.set(T0 + Duration::seconds(60));
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge throttled".into())
    );
    h.clock.set(T0 + Duration::seconds(90));
    assert!(h.resend(&challenge.id).await.is_ok());
}

#[tokio::test]
async fn otp_resend_after_expiry_leaves_challenge_untouched() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    h.clock.set(challenge.expires_at + Duration::nanoseconds(1));
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge expired".into())
    );
    assert_eq!(h.otp.get(&challenge.id), challenge);
    assert_eq!(h.mailer.sent().len(), 1);
}

#[tokio::test]
async fn otp_resend_rotates_code_and_keeps_attempts() {
    let h = harness_with(Options {
        generator: Arc::new(ScriptedCodes::new(&["OLDCODE1", "NEWCODE2"])),
        ..Options::default()
    });
    let challenge = h.start("User@x.com").await;
    assert_eq!(
        h.verify(&challenge.id, "user@x.com", "wrong").await,
        Err("otp challenge invalid".into())
    );

    let later = T0 + Duration::minutes(2);
    h.clock.set(later);
    let updated = h.resend(&challenge.id).await.expect("resend");
    assert_eq!(updated.resend_count, 1);
    assert_eq!(updated.attempt_count, 1, "attempts are not reset");
    assert_eq!(updated.code_hash, sha256_b64url("NEWCODE2"));
    assert_eq!(updated.expires_at, later + Duration::minutes(10));
    assert_eq!(updated.last_sent_at, later);
    assert_eq!(updated.created_at, T0);
    assert_eq!(updated.email, "user@x.com");
    assert_eq!(h.otp.get(&challenge.id), updated);
    assert_eq!(
        h.mailer.sent()[1],
        (
            "user@x.com".to_owned(),
            "NEWCODE2".to_owned(),
            later + Duration::minutes(10)
        )
    );

    assert_eq!(
        h.verify(&challenge.id, "user@x.com", "OLDCODE1").await,
        Err("otp challenge invalid".into())
    );
    assert_eq!(
        h.verify(&challenge.id, "user@x.com", "NEWCODE2").await,
        Ok(())
    );
}

#[tokio::test]
async fn otp_max_resends_zero_still_allows_three() {
    let h = harness_with(Options {
        config: IdentityConfig {
            otp_max_resends: 0,
            ..config()
        },
        ..Options::default()
    });
    let challenge = h.start("a@x.com").await;
    for n in 1..=3 {
        h.clock.advance(Duration::MINUTE);
        let updated = h.resend(&challenge.id).await.expect("resend");
        assert_eq!(updated.resend_count, n);
    }
    h.clock.advance(Duration::MINUTE);
    assert_eq!(
        h.resend(&challenge.id).await,
        Err("otp challenge too many resends".into())
    );
    assert_eq!(h.mailer.sent().len(), 4);
}

#[tokio::test]
async fn otp_resend_propagates_update_failure_and_mail_failure_is_ignored() {
    let h = harness();
    let challenge = h.start("a@x.com").await;
    h.clock.advance(Duration::MINUTE);
    h.otp.update_fails.store(true, Ordering::SeqCst);
    assert_eq!(h.resend(&challenge.id).await, Err("update failed".into()));
    assert_eq!(h.mailer.sent().len(), 1, "no email when the update fails");

    h.otp.update_fails.store(false, Ordering::SeqCst);
    h.mailer.fails.store(true, Ordering::SeqCst);
    assert!(h.resend(&challenge.id).await.is_ok());
}

// ----------------------------------------------- golden: hashes.json OTP ---

#[tokio::test]
async fn golden_otp_code_hash_through_service() {
    let doc = load("hashes.json");
    let cases = cases(&doc, "otp_code_hash");
    assert_eq!(cases.len(), 5);
    for case in cases {
        let input = s(case, "input");
        let h = harness_with(Options {
            generator: Arc::new(FixedOtpCodeGenerator::new(input)),
            ..Options::default()
        });
        let result = h
            .service
            .start_otp_challenge(OtpStartRequest {
                email: "a@x.com".into(),
                purpose: String::new(),
            })
            .await;
        match case.get("hash").and_then(|v| v.as_str()) {
            Some(hash) => {
                let challenge = result.expect("start");
                assert_eq!(challenge.code_hash, hash, "{input:?}");
                // Verify hashes the submitted code the same way.
                assert_eq!(h.verify(&challenge.id, "a@x.com", input).await, Ok(()));
            }
            None => {
                assert_eq!(err_text(result), opt(case, "error"), "{input:?}");
                assert!(h.otp.rows.lock().expect("lock").is_empty());
            }
        }
    }
}

#[tokio::test]
async fn golden_otp_code_random_through_service() {
    let doc = load("hashes.json");
    let cases = cases(&doc, "otp_code_random");
    assert_eq!(cases.len(), 4);
    for case in cases {
        let random = Arc::new(ScriptedRandom::from_hex(s(case, "raw_hex")));
        let h = harness_with(Options {
            generator: Arc::new(RandomOtpCodeGenerator::new(random)),
            ..Options::default()
        });
        let challenge = h.start("a@x.com").await;
        assert_eq!(challenge.code_hash, s(case, "hash"));
        assert_eq!(h.mailer.sent()[0].1, s(case, "code"));
    }
}
