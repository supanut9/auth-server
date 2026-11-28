//! Identity application service (`internal/application/identity/service.go`):
//! provider login and account linking, and the stateless email OTP
//! challenge (start, verify, resend).
//!
//! Check order and error values are observable through the HTTP responses.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use super::IdentityError;
use super::text::{equal_fold, fallback_display_name, normalize_otp_email};
use crate::crypto::{constant_time_eq, hash_opaque};
use crate::domain::{
    Account, AccountId, AccountProvider, AccountStatus, OtpChallenge, OtpChallengeId, SsoSession,
    is_zero_time,
};
use crate::flow::FlowError;
use crate::ports::{
    AccountProviderRepository, AccountRepository, Clock, OtpChallengeRepository, OtpCodeGenerator,
    OtpMailer, RandomError,
};

/// Default `OTP_MAX_ATTEMPTS` when the configured value is not positive.
pub const DEFAULT_OTP_MAX_ATTEMPTS: i64 = 6;
/// Default `OTP_MAX_RESENDS` when the configured value is not positive. So
/// `OTP_MAX_RESENDS=0`, which config accepts, still allows 3 resends.
pub const DEFAULT_OTP_MAX_RESENDS: i64 = 3;
/// Default `OTP_RESEND_COOLDOWN` when the configured value is not positive.
pub const DEFAULT_OTP_RESEND_COOLDOWN: Duration = Duration::MINUTE;
/// Purpose stored when the caller passes a blank one.
pub const DEFAULT_OTP_PURPOSE: &str = "login";
/// `sso_sessions.login_method` for an OTP login.
pub const OTP_LOGIN_METHOD: &str = "email_otp";

/// Starts the SSO session after a successful login (Go
/// `flow.Service.StartSSOSession`). Implemented by the flow service.
#[async_trait]
pub trait SsoSessionStarter: Send + Sync {
    async fn start_sso_session(
        &self,
        account_id: &AccountId,
        login_method: &str,
    ) -> Result<SsoSession, FlowError>;
}

/// `identity.Config`. `AppName` moved to the OTP mailer, which renders the
/// email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityConfig {
    /// `OTP_CHALLENGE_TTL`; used as is (no default here, like Go).
    pub otp_challenge_ttl: Duration,
    /// `OTP_MAX_ATTEMPTS`; not positive means [`DEFAULT_OTP_MAX_ATTEMPTS`].
    pub otp_max_attempts: i64,
    /// `OTP_MAX_RESENDS`; not positive means [`DEFAULT_OTP_MAX_RESENDS`].
    pub otp_max_resends: i64,
    /// `OTP_RESEND_COOLDOWN`; not positive means
    /// [`DEFAULT_OTP_RESEND_COOLDOWN`].
    pub otp_resend_cooldown: Duration,
}

/// Collaborators of [`IdentityService`]. Go also passed an `IDGenerator`,
/// which the service never used (repositories assign IDs).
#[derive(Clone)]
pub struct IdentityDeps {
    pub clock: Arc<dyn Clock>,
    /// [`crate::crypto::RandomOtpCodeGenerator`] in production, or
    /// [`FixedOtpCodeGenerator`] when `FIXED_OTP_CODE` is set.
    pub otp_code_generator: Arc<dyn OtpCodeGenerator>,
    pub accounts: Arc<dyn AccountRepository>,
    pub account_providers: Arc<dyn AccountProviderRepository>,
    pub otp_challenges: Arc<dyn OtpChallengeRepository>,
    /// `None` when SMTP is not configured: codes are silently not delivered.
    pub otp_mailer: Option<Arc<dyn OtpMailer>>,
    pub sso_sessions: Arc<dyn SsoSessionStarter>,
}

/// `fixedOTPCodeGenerator` (`internal/httpserver/server.go`): always returns
/// the `FIXED_OTP_CODE` value. Non-production only.
#[derive(Clone, PartialEq, Eq)]
pub struct FixedOtpCodeGenerator {
    code: String,
}

impl FixedOtpCodeGenerator {
    #[must_use]
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl fmt::Debug for FixedOtpCodeGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedOtpCodeGenerator")
            .finish_non_exhaustive()
    }
}

impl OtpCodeGenerator for FixedOtpCodeGenerator {
    fn new_code(&self) -> Result<String, RandomError> {
        Ok(self.code.clone())
    }
}

/// `ProviderLoginStatelessRequest`: the provider-claimed identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderLoginRequest {
    /// `google`, `github`, ...; also the SSO session login method.
    pub provider_name: String,
    pub provider_account_id: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    pub avatar_url: String,
}

/// `ProviderLoginStatelessResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderLoginResult {
    pub account: Account,
    pub account_provider: AccountProvider,
    pub session: SsoSession,
}

/// `OTPStartStatelessRequest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtpStartRequest {
    pub email: String,
    /// Blank means [`DEFAULT_OTP_PURPOSE`].
    pub purpose: String,
}

/// `OTPVerifyStatelessRequest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtpVerifyRequest {
    pub otp_challenge_id: String,
    pub email: String,
    pub code: String,
}

/// Successful OTP verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpVerifyResult {
    pub account: Account,
    pub session: SsoSession,
}

/// `OTPResendStatelessRequest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtpResendRequest {
    pub otp_challenge_id: String,
}

/// `identity.Service`.
#[derive(Clone)]
pub struct IdentityService {
    deps: IdentityDeps,
    otp_challenge_ttl: Duration,
    otp_max_attempts: i64,
    otp_max_resends: i64,
    otp_resend_cooldown: Duration,
}

impl fmt::Debug for IdentityService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityService")
            .field("otp_challenge_ttl", &self.otp_challenge_ttl)
            .field("otp_max_attempts", &self.otp_max_attempts)
            .field("otp_max_resends", &self.otp_max_resends)
            .field("otp_resend_cooldown", &self.otp_resend_cooldown)
            .field("otp_mailer", &self.deps.otp_mailer.is_some())
            .finish_non_exhaustive()
    }
}

/// Go `positiveIntOrDefault`.
fn positive_or(value: i64, fallback: i64) -> i64 {
    if value <= 0 { fallback } else { value }
}

/// Go `durationOrDefault`.
fn duration_or(value: Duration, fallback: Duration) -> Duration {
    if value <= Duration::ZERO {
        fallback
    } else {
        value
    }
}

/// Go `hashOTPCode`: unsalted `base64url_nopad(SHA-256(code))`.
fn hash_otp_code(code: &str) -> Result<String, IdentityError> {
    hash_opaque(code).ok_or(IdentityError::EmptyOtpCode)
}

impl IdentityService {
    /// `NewService`, including the defaults for non-positive limits.
    #[must_use]
    pub fn new(config: IdentityConfig, deps: IdentityDeps) -> Self {
        Self {
            deps,
            otp_challenge_ttl: config.otp_challenge_ttl,
            otp_max_attempts: positive_or(config.otp_max_attempts, DEFAULT_OTP_MAX_ATTEMPTS),
            otp_max_resends: positive_or(config.otp_max_resends, DEFAULT_OTP_MAX_RESENDS),
            otp_resend_cooldown: duration_or(
                config.otp_resend_cooldown,
                DEFAULT_OTP_RESEND_COOLDOWN,
            ),
        }
    }

    /// Effective attempt limit after defaulting.
    #[must_use]
    pub fn otp_max_attempts(&self) -> i64 {
        self.otp_max_attempts
    }

    /// Effective resend limit after defaulting.
    #[must_use]
    pub fn otp_max_resends(&self) -> i64 {
        self.otp_max_resends
    }

    /// Effective resend cooldown after defaulting.
    #[must_use]
    pub fn otp_resend_cooldown(&self) -> Duration {
        self.otp_resend_cooldown
    }

    fn now(&self) -> OffsetDateTime {
        self.deps.clock.now()
    }

    /// `HandleProviderLoginStateless`.
    ///
    /// The provider email must be verified and not blank. The account is
    /// found by `(provider, provider_account_id)`, then by case-insensitive
    /// `primary_verified_email`, and otherwise created. A new
    /// `account_providers` row is written whenever the first lookup misses.
    /// The account profile is never refreshed on later logins.
    ///
    /// # Errors
    /// [`IdentityError::ProviderEmailVerificationRequired`], or a repository
    /// or session failure.
    pub async fn handle_provider_login(
        &self,
        req: ProviderLoginRequest,
    ) -> Result<ProviderLoginResult, IdentityError> {
        if !req.email_verified || req.email.trim().is_empty() {
            return Err(IdentityError::ProviderEmailVerificationRequired);
        }

        let (account, account_provider) = self.resolve_account_and_provider(&req).await?;

        let session = self
            .deps
            .sso_sessions
            .start_sso_session(&account.id, &req.provider_name)
            .await?;

        Ok(ProviderLoginResult {
            account,
            account_provider,
            session,
        })
    }

    /// Go `resolveAccountAndProvider`. Like Go, any lookup error (not only
    /// "not found") falls through to the next step.
    async fn resolve_account_and_provider(
        &self,
        req: &ProviderLoginRequest,
    ) -> Result<(Account, AccountProvider), IdentityError> {
        if let Ok(existing) = self
            .deps
            .account_providers
            .find_by_provider_account_id(&req.provider_name, &req.provider_account_id)
            .await
        {
            let account = self.deps.accounts.find_by_id(&existing.account_id).await?;
            return Ok((account, existing));
        }

        let account = match self
            .deps
            .accounts
            .find_by_primary_verified_email(&req.email)
            .await
        {
            Ok(existing) => existing,
            Err(_) => {
                self.deps
                    .accounts
                    .create(Account {
                        primary_verified_email: req.email.clone(),
                        display_name: fallback_display_name(&req.display_name, &req.email),
                        avatar_url: req.avatar_url.clone(),
                        status: AccountStatus::Active,
                        ..Account::default()
                    })
                    .await?
            }
        };

        let link = self
            .deps
            .account_providers
            .create(AccountProvider {
                account_id: account.id.clone(),
                provider: req.provider_name.clone(),
                provider_account_id: req.provider_account_id.clone(),
                provider_email: req.email.clone(),
                provider_email_verified: req.email_verified,
                profile_name: req.display_name.clone(),
                profile_avatar_url: req.avatar_url.clone(),
                ..AccountProvider::default()
            })
            .await?;

        Ok((account, link))
    }

    /// `StartOTPChallengeStateless`.
    ///
    /// The email is trimmed and lowercased. Older challenges for the
    /// same email stay valid. The email is sent before returning and a
    /// delivery failure is ignored.
    ///
    /// # Errors
    /// [`IdentityError::OtpEmailRequired`] for a blank email, or a code
    /// generator or repository failure.
    pub async fn start_otp_challenge(
        &self,
        req: OtpStartRequest,
    ) -> Result<OtpChallenge, IdentityError> {
        let email = normalize_otp_email(&req.email);
        if email.is_empty() {
            return Err(IdentityError::OtpEmailRequired);
        }

        let code = self.deps.otp_code_generator.new_code()?;
        let code_hash = hash_otp_code(&code)?;

        let now = self.now();
        let purpose = match req.purpose.trim() {
            "" => DEFAULT_OTP_PURPOSE,
            purpose => purpose,
        };

        let challenge = self
            .deps
            .otp_challenges
            .create(OtpChallenge {
                authorization_request_id: None,
                email: email.clone(),
                purpose: purpose.to_owned(),
                code_hash,
                expires_at: now + self.otp_challenge_ttl,
                last_sent_at: now,
                created_at: now,
                ..OtpChallenge::default()
            })
            .await?;

        self.send_code(&email, &code, challenge.expires_at).await;

        Ok(challenge)
    }

    /// `VerifyOTPChallengeStateless`.
    ///
    /// Order: blank ID or unknown challenge => not found; already verified
    /// => invalid; email mismatch (case-insensitive, trimmed) => not found;
    /// attempts used up => too many attempts; expired; empty code; wrong code
    /// => count the attempt, then too many attempts or invalid. On success
    /// the account is found by case-insensitive email or created, the challenge is
    /// marked verified and an `email_otp` SSO session starts.
    ///
    /// # Errors
    /// The [`IdentityError`] OTP variants above, or a repository or session
    /// failure.
    pub async fn verify_otp_challenge(
        &self,
        req: OtpVerifyRequest,
    ) -> Result<OtpVerifyResult, IdentityError> {
        if req.otp_challenge_id.trim().is_empty() {
            return Err(IdentityError::OtpChallengeNotFound);
        }

        let Ok(mut challenge) = self
            .deps
            .otp_challenges
            .find_by_id(&OtpChallengeId::new(req.otp_challenge_id))
            .await
        else {
            return Err(IdentityError::OtpChallengeNotFound);
        };
        if challenge.verified_at.is_some() {
            return Err(IdentityError::OtpChallengeInvalid);
        }
        let email = normalize_otp_email(&challenge.email);
        if !equal_fold(&email, &normalize_otp_email(&req.email)) {
            return Err(IdentityError::OtpChallengeNotFound);
        }
        if i64::from(challenge.attempt_count) >= self.otp_max_attempts {
            return Err(IdentityError::OtpChallengeTooManyAttempts);
        }
        if self.now() > challenge.expires_at {
            return Err(IdentityError::OtpChallengeExpired);
        }

        let hash = hash_otp_code(&req.code)?;
        if !constant_time_eq(hash.as_bytes(), challenge.code_hash.as_bytes()) {
            challenge.attempt_count += 1;
            let attempts = i64::from(challenge.attempt_count);
            // Go ignores the update error.
            let _ = self.deps.otp_challenges.update(challenge).await;
            if attempts >= self.otp_max_attempts {
                return Err(IdentityError::OtpChallengeTooManyAttempts);
            }
            return Err(IdentityError::OtpChallengeInvalid);
        }

        let account = match self
            .deps
            .accounts
            .find_by_primary_verified_email(&email)
            .await
        {
            Ok(existing) => existing,
            Err(_) => {
                self.deps
                    .accounts
                    .create(Account {
                        display_name: fallback_display_name("", &email),
                        primary_verified_email: email,
                        status: AccountStatus::Active,
                        ..Account::default()
                    })
                    .await?
            }
        };

        challenge.verified_at = Some(self.now());
        // Go ignores the update error.
        let _ = self.deps.otp_challenges.update(challenge).await;

        let session = self
            .deps
            .sso_sessions
            .start_sso_session(&account.id, OTP_LOGIN_METHOD)
            .await?;

        Ok(OtpVerifyResult { account, session })
    }

    /// `ResendOTPChallengeStateless`.
    ///
    /// Order: blank ID or unknown challenge => not found; verified =>
    /// invalid; past expiry => expired; attempts used up => too many
    /// attempts; resends used up => too many resends; within the cooldown
    /// since `last_sent_at` (or `created_at` when unset) => throttled.
    /// On success a new code replaces the old one, the expiry restarts
    /// and the attempt count is kept.
    ///
    /// # Errors
    /// The [`IdentityError`] OTP variants above, or a code generator or
    /// repository failure.
    pub async fn resend_otp_challenge(
        &self,
        req: OtpResendRequest,
    ) -> Result<OtpChallenge, IdentityError> {
        if req.otp_challenge_id.trim().is_empty() {
            return Err(IdentityError::OtpChallengeNotFound);
        }

        let Ok(mut challenge) = self
            .deps
            .otp_challenges
            .find_by_id(&OtpChallengeId::new(req.otp_challenge_id))
            .await
        else {
            return Err(IdentityError::OtpChallengeNotFound);
        };
        if challenge.verified_at.is_some() {
            return Err(IdentityError::OtpChallengeInvalid);
        }
        let now = self.now();
        if now > challenge.expires_at {
            return Err(IdentityError::OtpChallengeExpired);
        }
        if i64::from(challenge.attempt_count) >= self.otp_max_attempts {
            return Err(IdentityError::OtpChallengeTooManyAttempts);
        }
        if i64::from(challenge.resend_count) >= self.otp_max_resends {
            return Err(IdentityError::OtpChallengeTooManyResends);
        }
        let last_sent_at = if is_zero_time(challenge.last_sent_at) {
            challenge.created_at
        } else {
            challenge.last_sent_at
        };
        if now < last_sent_at + self.otp_resend_cooldown {
            return Err(IdentityError::OtpChallengeThrottled);
        }

        let code = self.deps.otp_code_generator.new_code()?;
        let code_hash = hash_otp_code(&code)?;

        challenge.resend_count += 1;
        challenge.code_hash = code_hash;
        challenge.expires_at = now + self.otp_challenge_ttl;
        challenge.last_sent_at = now;
        let email = challenge.email.clone();
        let updated = self.deps.otp_challenges.update(challenge).await?;

        self.send_code(&email, &code, updated.expires_at).await;

        Ok(updated)
    }

    /// Sends the code when a mailer is configured; Go discards the error.
    async fn send_code(&self, to: &str, code: &str, expires_at: OffsetDateTime) {
        if let Some(mailer) = &self.deps.otp_mailer {
            let _ = mailer.send_otp(to, code, expires_at).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_default_like_go() {
        assert_eq!(positive_or(0, 3), 3);
        assert_eq!(positive_or(-1, 6), 6);
        assert_eq!(positive_or(1, 3), 1);
        assert_eq!(
            duration_or(Duration::ZERO, Duration::MINUTE),
            Duration::MINUTE
        );
        assert_eq!(
            duration_or(Duration::seconds(-5), Duration::MINUTE),
            Duration::MINUTE
        );
        assert_eq!(
            duration_or(Duration::seconds(5), Duration::MINUTE),
            Duration::seconds(5)
        );
    }

    #[test]
    fn fixed_generator_returns_code_and_hides_it() {
        let generator = FixedOtpCodeGenerator::new("12345678");
        assert_eq!(generator.new_code().ok().as_deref(), Some("12345678"));
        assert!(!format!("{generator:?}").contains("1234"));
    }
}
