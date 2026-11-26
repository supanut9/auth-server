//! OTP email template (`internal/adapter/out/mail/otp_template.go`).

use std::fmt::Write as _;

use time::{Duration, OffsetDateTime};

/// `identity.Service` falls back to this when `APP_NAME` is blank.
pub const DEFAULT_APP_NAME: &str = "auth-server";

/// Rendered OTP email (`RenderOTPEmail`'s `(subject, text, html)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpEmail {
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// `strings.TrimSpace(cfg.AppName)`, falling back to [`DEFAULT_APP_NAME`].
#[must_use]
pub fn app_name_or_default(app_name: &str) -> &str {
    let trimmed = app_name.trim();
    if trimmed.is_empty() {
        DEFAULT_APP_NAME
    } else {
        trimmed
    }
}

/// `max(1, int(remaining.Minutes()))`: whole minutes, truncated, at least 1.
#[must_use]
pub fn otp_minutes_left(remaining: Duration) -> i64 {
    remaining.whole_minutes().max(1)
}

/// Renders the OTP email. Go read the wall clock (`time.Until(expiresAt)`) at
/// render time; here the caller passes `now`. The identity service sets
/// `expires_at = now + OTP_CHALLENGE_TTL` and renders a moment later, so the
/// default 10m TTL shows "9 minute(s)".
#[must_use]
pub fn render_otp_email(
    code: &str,
    app_name: &str,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> OtpEmail {
    render_otp_email_with_remaining(code, app_name, expires_at - now)
}

/// [`render_otp_email`] with the time left until expiry given directly.
/// `app_name` goes through [`app_name_or_default`].
#[must_use]
pub fn render_otp_email_with_remaining(
    code: &str,
    app_name: &str,
    remaining: Duration,
) -> OtpEmail {
    let app_name = app_name_or_default(app_name);
    let minutes_left = otp_minutes_left(remaining);

    let subject = format!("Your {app_name} verification code");

    let mut text = String::new();
    let _ = write!(text, "Your {app_name} verification code\n\n");
    let _ = write!(text, "    {code}\n\n");
    let _ = write!(text, "This code expires in {minutes_left} minute(s).\n\n");
    text.push_str("If you did not request this code you can safely ignore this email.\n");
    text.push_str("Do not share this code with anyone.\n");

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>");
    html.push_str(r#"<html lang="en"><head><meta charset="UTF-8">"#);
    html.push_str(r#"<meta name="viewport" content="width=device-width,initial-scale=1">"#);
    html.push_str("<title>Verification code</title></head>");
    html.push_str(r#"<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">"#);
    html.push_str(r#"<table width="100%" cellpadding="0" cellspacing="0" role="presentation">"#);
    html.push_str(r#"<tr><td align="center" style="padding:40px 16px;">"#);
    html.push_str(r#"<table width="560" cellpadding="0" cellspacing="0" role="presentation" style="max-width:560px;width:100%;background:#ffffff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">"#);
    html.push_str(r#"<tr><td style="padding:32px 40px 24px;border-bottom:1px solid #f0f0f0;">"#);
    let _ = write!(
        html,
        r#"<p style="margin:0;font-size:18px;font-weight:700;color:#1a1a1a;">{}</p>"#,
        escape_html(app_name)
    );
    html.push_str("</td></tr>");
    html.push_str(r#"<tr><td style="padding:32px 40px 24px;">"#);
    html.push_str(
        r#"<p style="margin:0 0 16px;font-size:15px;color:#444;">Your verification code is:</p>"#,
    );
    let _ = write!(
        html,
        r#"<div style="display:inline-block;padding:18px 32px;background:#f8f4ff;border-radius:10px;font-size:36px;font-weight:700;letter-spacing:8px;color:#2d1b6e;font-family:'Courier New',Courier,monospace;">{}</div>"#,
        escape_html(code)
    );
    let _ = write!(
        html,
        r#"<p style="margin:20px 0 0;font-size:13px;color:#888;">This code expires in <strong>{minutes_left} minute(s)</strong>.</p>"#
    );
    html.push_str("</td></tr>");
    html.push_str(r#"<tr><td style="padding:0 40px 32px;">"#);
    html.push_str(r#"<p style="margin:0;font-size:12px;color:#aaa;border-top:1px solid #f0f0f0;padding-top:20px;">"#);
    html.push_str("If you did not request this code, you can safely ignore this email. ");
    html.push_str("Do not share this code with anyone.");
    html.push_str("</p></td></tr>");
    html.push_str("</table></td></tr></table>");
    html.push_str("</body></html>");

    OtpEmail {
        subject,
        text,
        html,
    }
}

/// Go's `escapeHTML`: `&`, `<`, `>`, `"` only (`'` is left as is).
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minutes_truncate_and_clamp() {
        assert_eq!(otp_minutes_left(Duration::milliseconds(599_999)), 9);
        assert_eq!(otp_minutes_left(Duration::minutes(10)), 10);
        assert_eq!(otp_minutes_left(Duration::seconds(30)), 1);
        assert_eq!(otp_minutes_left(Duration::minutes(-5)), 1);
    }

    #[test]
    fn app_name_falls_back() {
        assert_eq!(app_name_or_default("  "), "auth-server");
        assert_eq!(app_name_or_default(" Web "), "Web");
    }

    #[test]
    fn escapes_like_go() {
        assert_eq!(
            escape_html(r#"A&B <"x"> 'y'"#),
            "A&amp;B &lt;&#34;x&#34;&gt; 'y'"
        );
    }

    #[test]
    fn render_uses_clock_difference() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let email = render_otp_email("123", "", now + Duration::minutes(10), now);
        assert_eq!(email.subject, "Your auth-server verification code");
        assert!(email.text.contains("expires in 10 minute(s)"));
    }
}
