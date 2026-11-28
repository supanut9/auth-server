//! `TemplateOtpMailer` through the `OtpMailer` port: the message handed to
//! the `MailSender` matches the frozen fixture with rounded expiry minutes.

mod golden_support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use auth_adapters::mail::{TemplateOtpMailer, build_message};
use auth_core::ports::{Clock, MailError, MailMessage, MailSender, OtpMailer};
use golden_support::otp_rendered_field;
use serde_json::Value;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn golden(file: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/golden")
        .join(file);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_slice(&bytes).expect("golden json")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string {key}"))
}

#[derive(Default)]
struct CapturingSender {
    sent: Mutex<Vec<MailMessage>>,
    fail: bool,
}

#[async_trait]
impl MailSender for CapturingSender {
    async fn send(&self, message: MailMessage) -> Result<(), MailError> {
        self.sent.lock().expect("lock").push(message);
        if self.fail {
            return Err(MailError::new("smtp down"));
        }
        Ok(())
    }
}

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

const NOW: OffsetDateTime = datetime!(2026-03-04 05:06:07.123456789 UTC);

#[tokio::test]
async fn golden_render_cases_through_port() {
    let golden = golden("otp_email.json");
    let cases = golden["render"]["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 7, "every recorded case is checked");
    for case in cases {
        let name = text(case, "name");
        let remaining =
            Duration::milliseconds(case["remaining_ms_at_render"].as_i64().expect("remaining"));
        let sender = Arc::new(CapturingSender::default());
        let mailer = TemplateOtpMailer::new(
            sender.clone(),
            text(case, "app_name"),
            Arc::new(FixedClock(NOW)),
        );
        let port: &dyn OtpMailer = &mailer;
        port.send_otp(text(case, "to"), text(case, "code"), NOW + remaining)
            .await
            .expect("send");

        let sent = sender.sent.lock().expect("lock").clone();
        assert_eq!(sent.len(), 1, "{name}");
        let message = &sent[0];
        assert_eq!(message.to, text(case, "to"), "{name}: to");
        assert_eq!(message.subject, text(case, "subject"), "{name}: subject");
        assert_eq!(
            message.text,
            otp_rendered_field(case, "text"),
            "{name}: text"
        );
        assert_eq!(
            message.html,
            otp_rendered_field(case, "html"),
            "{name}: html"
        );
        assert_eq!(
            build_message(text(case, "from"), message).as_bytes(),
            otp_rendered_field(case, "mime_message").as_bytes(),
            "{name}: mime"
        );
    }
}

#[tokio::test]
async fn blank_app_name_defaults_and_errors_surface() {
    let sender = Arc::new(CapturingSender {
        fail: true,
        ..CapturingSender::default()
    });
    let mailer = TemplateOtpMailer::new(sender.clone(), "  ", Arc::new(FixedClock(NOW)));
    assert_eq!(mailer.app_name(), "auth-server");
    // The port reports the failure; the identity service is what ignores it.
    let error = mailer
        .send_otp("u@x.com", "AbCd-_12", NOW + Duration::minutes(10))
        .await
        .expect_err("sender failure");
    assert_eq!(error.to_string(), "smtp down");
    let sent = sender.sent.lock().expect("lock").clone();
    assert_eq!(sent[0].subject, "Your auth-server verification code");
    // The template displays the remaining TTL in whole minutes.
    assert!(sent[0].text.contains("expires in 10 minute(s)"));
}
