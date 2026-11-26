use async_trait::async_trait;
use time::OffsetDateTime;

use super::MailError;

/// Delivers an OTP code by email.
///
/// Go's identity service rendered `mail.RenderOTPEmail` itself and handed the
/// result to `port.MailSender`. `auth-core` cannot depend on the template in
/// `auth-adapters`, so rendering moves behind this port. Production wraps the
/// SMTP sender in `auth_adapters::mail::TemplateOtpMailer`.
#[async_trait]
pub trait OtpMailer: Send + Sync {
    /// Sends `code` to `to`; the body says how long until `expires_at`.
    async fn send_otp(
        &self,
        to: &str,
        code: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), MailError>;
}
