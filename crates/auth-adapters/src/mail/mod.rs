//! Email delivery adapters (`internal/adapter/out/mail`).

mod mime;
mod otp_template;
mod smtp;

pub use mime::{MIME_BOUNDARY, build_message, smtp_data_encoding};
pub use otp_template::{
    DEFAULT_APP_NAME, OtpEmail, app_name_or_default, otp_minutes_left, render_otp_email,
    render_otp_email_with_remaining,
};
pub use smtp::{SmtpSender, SmtpSenderConfig};

mod otp_mailer;
pub use otp_mailer::TemplateOtpMailer;
