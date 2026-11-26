//! OTP template and MIME builder against `testdata/golden/otp_email.json`.

use std::path::PathBuf;

use auth_adapters::mail::{build_message, otp_minutes_left, render_otp_email_with_remaining};
use auth_core::ports::MailMessage;
use serde_json::Value;
use time::Duration;

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

#[test]
fn render_cases_match_go_byte_for_byte() {
    let golden = golden("otp_email.json");
    let cases = golden["render"]["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 7, "every recorded case is checked");
    for case in cases {
        let name = text(case, "name");
        let remaining =
            Duration::milliseconds(case["remaining_ms_at_render"].as_i64().expect("remaining"));
        assert_eq!(
            Some(otp_minutes_left(remaining)),
            case["minutes_shown"].as_i64(),
            "{name}: minutes"
        );

        let email =
            render_otp_email_with_remaining(text(case, "code"), text(case, "app_name"), remaining);
        assert_eq!(email.subject, text(case, "subject"), "{name}: subject");
        assert_eq!(email.text, text(case, "text"), "{name}: text");
        assert_eq!(email.html, text(case, "html"), "{name}: html");

        let mime = build_message(
            text(case, "from"),
            &MailMessage {
                to: text(case, "to").to_owned(),
                subject: email.subject,
                text: email.text,
                html: email.html,
            },
        );
        assert_eq!(
            mime.as_bytes(),
            text(case, "mime_message").as_bytes(),
            "{name}: mime"
        );
    }
}

#[test]
fn text_only_mime_matches_go() {
    let golden = golden("otp_email.json");
    let section = &golden["mime_text_only"];
    let mime = build_message(
        text(section, "from"),
        &MailMessage {
            to: text(section, "to").to_owned(),
            subject: text(section, "subject").to_owned(),
            text: text(section, "text").to_owned(),
            html: String::new(),
        },
    );
    assert_eq!(mime.as_bytes(), text(section, "mime").as_bytes());
}
