//! [`OtpMailer`] over any [`MailSender`]: the rendering half of Go's
//! identity service (`mail.RenderOTPEmail` + `MailSender.Send`).

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use auth_core::ports::{Clock, MailError, MailMessage, MailSender, OtpMailer};
use time::OffsetDateTime;

use super::otp_template::{app_name_or_default, render_otp_email};

/// Renders the OTP email template and sends it.
///
/// The minutes shown are `expires_at - clock.now()` at send time, truncated:
/// with the system clock a 10m TTL shows "9 minute(s)", as in Go, because a
/// little time passes between issuing the challenge and rendering.
#[derive(Clone)]
pub struct TemplateOtpMailer {
    sender: Arc<dyn MailSender>,
    app_name: String,
    clock: Arc<dyn Clock>,
}

impl TemplateOtpMailer {
    /// `app_name` is `APP_NAME`; blank falls back to `auth-server`.
    #[must_use]
    pub fn new(sender: Arc<dyn MailSender>, app_name: &str, clock: Arc<dyn Clock>) -> Self {
        Self {
            sender,
            app_name: app_name_or_default(app_name).to_owned(),
            clock,
        }
    }

    /// The app name used in the subject and header.
    #[must_use]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }
}

impl fmt::Debug for TemplateOtpMailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemplateOtpMailer")
            .field("app_name", &self.app_name)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl OtpMailer for TemplateOtpMailer {
    async fn send_otp(
        &self,
        to: &str,
        code: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), MailError> {
        let email = render_otp_email(code, &self.app_name, expires_at, self.clock.now());
        self.sender
            .send(MailMessage {
                to: to.to_owned(),
                subject: email.subject,
                text: email.text,
                html: email.html,
            })
            .await
    }
}
