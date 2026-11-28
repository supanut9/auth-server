//! Ports used by the application layer (`internal/port`).
//!
//! Async traits use `async-trait` so they stay object safe (`Arc<dyn Trait>`).

mod envelope;
mod error;
mod jwt;
mod mail;
mod provider;
mod rate_limit;
mod repositories;
mod support;
mod system;

pub use envelope::{JtiStore, JtiStoreError, RepositoryJtiStore};
pub use error::{BoxError, JwtError, MailError, ProviderError, RandomError, RepoError, RepoResult};
pub use jwt::{JwksProvider, JwtClaims, JwtSigner, JwtVerifier, SignedJwt};
pub use mail::{MailMessage, MailSender};
pub use provider::{IdentityProvider, ProviderProfile};
pub use rate_limit::OtpRateLimiter;
pub use repositories::{
    AccessTokenRepository, AccountProviderRepository, AccountRepository,
    AuthorizationCodeRepository, ConsentGrantRepository, OAuthClientRepository,
    OtpChallengeRepository, RefreshTokenChainRepository, RefreshTokenRepository,
    SignedStateJtiRepository, SsoSessionRepository,
};
pub use support::{
    CleanupCounts, CleanupRepository, ReadinessProbe, SupportAccountSummary, SupportRepository,
};
pub use system::{Clock, IdGenerator, OtpCodeGenerator, RandomSource};

#[cfg(test)]
mod tests;

mod otp_mailer;
pub use otp_mailer::OtpMailer;
