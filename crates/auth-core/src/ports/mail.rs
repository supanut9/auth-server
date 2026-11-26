use async_trait::async_trait;

use super::MailError;

/// `port.MailMessage`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
    /// Optional HTML body. When non-empty the message is sent as
    /// multipart/alternative; otherwise plain text only.
    pub html: String,
}

/// `port.MailSender`.
#[async_trait]
pub trait MailSender: Send + Sync {
    async fn send(&self, message: MailMessage) -> Result<(), MailError>;
}
