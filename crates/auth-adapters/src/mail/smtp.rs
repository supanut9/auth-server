//! SMTP sender (`internal/adapter/out/mail/smtp.go`).
//!
//! Mirrors Go's `net/smtp` session on top of lettre's low-level connection:
//! plain TCP to `host:port` (no implicit TLS), `EHLO localhost`, `STARTTLS`
//! when advertised (TLS 1.2+), `AUTH PLAIN` only when a username is set and the
//! server advertises AUTH, then `MAIL`/`RCPT`/`DATA` with the message bytes
//! built by [`build_message`](super::build_message). lettre's message builder
//! is not used, so no header is added or rewritten.

use std::time::Duration;

use async_trait::async_trait;
use auth_core::ports::{MailError, MailMessage, MailSender};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lettre::transport::smtp::authentication::Mechanism;
use lettre::transport::smtp::client::{AsyncSmtpConnection, TlsParameters, TlsVersion};
use lettre::transport::smtp::extension::{ClientId, Extension};
use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpStream;

use super::mime::{build_message, smtp_data_encoding};
use crate::config::Config;

/// Bounds the TCP connect. Go's dialer had none (only the request context).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// `SMTPSenderConfig`.
#[derive(Debug, Clone)]
pub struct SmtpSenderConfig {
    pub host: String,
    pub port: String,
    pub username: String,
    pub password: SecretString,
    pub from: String,
}

/// `SMTPSender`: one connection per message, like Go.
#[derive(Debug, Clone)]
pub struct SmtpSender {
    host: String,
    port: String,
    from: String,
    /// `smtp.PlainAuth("", username, password, host)` when a username is set.
    credentials: Option<(String, SecretString)>,
}

impl SmtpSender {
    /// `NewSMTPSender`.
    ///
    /// # Errors
    /// `smtp host is required`, `smtp port is required` or `smtp from is
    /// required` when the value is blank.
    pub fn new(config: SmtpSenderConfig) -> Result<Self, MailError> {
        if config.host.trim().is_empty() {
            return Err(MailError::new("smtp host is required"));
        }
        if config.port.trim().is_empty() {
            return Err(MailError::new("smtp port is required"));
        }
        if config.from.trim().is_empty() {
            return Err(MailError::new("smtp from is required"));
        }
        let credentials =
            (!config.username.trim().is_empty()).then_some((config.username, config.password));
        Ok(Self {
            host: config.host,
            port: config.port,
            from: config.from,
            credentials,
        })
    }

    /// Built only when `SMTP_HOST` and `SMTP_FROM` are set (`httpserver/server.go`).
    #[must_use]
    pub fn from_config(config: &Config) -> Option<Result<Self, MailError>> {
        (!config.smtp_host.is_empty() && !config.smtp_from.is_empty()).then(|| {
            Self::new(SmtpSenderConfig {
                host: config.smtp_host.clone(),
                port: config.smtp_port.clone(),
                username: config.smtp_username.clone(),
                password: config.smtp_password.clone(),
                from: config.smtp_from.clone(),
            })
        })
    }

    async fn deliver(&self, message: &MailMessage) -> Result<(), MailError> {
        let address = join_host_port(&self.host, &self.port);
        let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&address)).await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                return Err(MailError::new(format!(
                    "dial smtp server: dial tcp {address}: {error}"
                )));
            }
            Err(_) => {
                return Err(MailError::new(format!(
                    "dial smtp server: dial tcp {address}: i/o timeout"
                )));
            }
        };

        // Go's net/smtp greets with "EHLO localhost".
        let hello = ClientId::Domain("localhost".to_owned());
        let mut conn = AsyncSmtpConnection::connect_with_transport(Box::new(stream), &hello)
            .await
            .map_err(|error| wrap("create smtp client", &error))?;

        let result = self.session(&mut conn, &hello, message).await;
        if result.is_err() {
            conn.abort().await;
        }
        result
    }

    async fn session(
        &self,
        conn: &mut AsyncSmtpConnection,
        hello: &ClientId,
        message: &MailMessage,
    ) -> Result<(), MailError> {
        if conn.server_info().supports_feature(Extension::StartTls) {
            let tls = TlsParameters::builder(self.host.clone())
                .set_min_tls_version(TlsVersion::Tlsv12)
                .build_rustls()
                .map_err(|error| wrap("start tls", &error))?;
            conn.starttls(tls, hello)
                .await
                .map_err(|error| wrap("start tls", &error))?;
        }

        if let Some((username, password)) = &self.credentials
            && advertises_auth(conn)
        {
            if !plain_auth_allowed(conn.is_encrypted(), &self.host) {
                return Err(MailError::new("smtp auth: unencrypted connection"));
            }
            let response = format!(
                "\0{username}\0{password}",
                password = password.expose_secret()
            );
            let reply = conn
                .command(format!("AUTH PLAIN {}\r\n", STANDARD.encode(response)))
                .await
                .map_err(|error| wrap("smtp auth", &error))?;
            if !reply.has_code(235) {
                // PlainAuth.Next rejects any server challenge.
                return Err(MailError::new("smtp auth: unexpected server challenge"));
            }
        }

        // client.Mail: BODY=8BITMIME / SMTPUTF8 when the server offers them.
        validate_line(&self.from).map_err(|error| MailError::new(format!("smtp from: {error}")))?;
        let mut mail = format!("MAIL FROM:<{}>", self.from);
        if conn.server_info().supports_feature(Extension::EightBitMime) {
            mail.push_str(" BODY=8BITMIME");
        }
        if conn.server_info().supports_feature(Extension::SmtpUtfEight) {
            mail.push_str(" SMTPUTF8");
        }
        mail.push_str("\r\n");
        conn.command(mail)
            .await
            .map_err(|error| wrap("smtp from", &error))?;

        validate_line(&message.to)
            .map_err(|error| MailError::new(format!("smtp rcpt: {error}")))?;
        conn.command(format!("RCPT TO:<{}>\r\n", message.to))
            .await
            .map_err(|error| wrap("smtp rcpt", &error))?;

        let reply = conn
            .command("DATA\r\n")
            .await
            .map_err(|error| wrap("smtp data", &error))?;
        if !reply.has_code(354) {
            return Err(MailError::new(format!(
                "smtp data: {} {}",
                reply.code(),
                reply.message().collect::<Vec<_>>().join("\n")
            )));
        }

        let payload = smtp_data_encoding(&build_message(&self.from, message));
        conn.command(payload)
            .await
            .map_err(|error| wrap("close message writer", &error))?;

        conn.quit()
            .await
            .map_err(|error| wrap("smtp quit", &error))?;
        Ok(())
    }
}

#[async_trait]
impl MailSender for SmtpSender {
    async fn send(&self, message: MailMessage) -> Result<(), MailError> {
        self.deliver(&message).await
    }
}

/// `net.JoinHostPort`: brackets a host that contains a colon (IPv6).
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `client.Extension("AUTH")`. lettre only records the mechanisms it knows, so
/// a server offering only unknown mechanisms counts as not advertising AUTH.
fn advertises_auth(conn: &AsyncSmtpConnection) -> bool {
    [Mechanism::Plain, Mechanism::Login, Mechanism::Xoauth2]
        .into_iter()
        .any(|mechanism| conn.server_info().supports_auth_mechanism(mechanism))
}

/// `smtp.PlainAuth.Start`: credentials go only over TLS or to localhost.
fn plain_auth_allowed(encrypted: bool, host: &str) -> bool {
    encrypted || matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// `net/smtp` `validateLine`.
fn validate_line(line: &str) -> Result<(), &'static str> {
    if line.contains(['\r', '\n']) {
        return Err("smtp: A line must not contain CR or LF");
    }
    Ok(())
}

/// `fmt.Errorf("<context>: %w", err)`. A server rejection reads like Go's
/// `textproto.Error` (`"550 5.1.1 message"`).
fn wrap(context: &str, error: &lettre::transport::smtp::Error) -> MailError {
    let detail = match (error.status(), std::error::Error::source(error)) {
        (Some(code), Some(message)) => format!("{code} {message}"),
        _ => error.to_string(),
    };
    MailError::new(format!("{context}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_validates_like_go() {
        let config = |host: &str, port: &str, from: &str| SmtpSenderConfig {
            host: host.to_owned(),
            port: port.to_owned(),
            username: String::new(),
            password: SecretString::from(String::new()),
            from: from.to_owned(),
        };
        let error = |config| SmtpSender::new(config).err().map(|error| error.to_string());
        assert_eq!(
            error(config(" ", "25", "a@b")),
            Some("smtp host is required".to_owned())
        );
        assert_eq!(
            error(config("h", "", "a@b")),
            Some("smtp port is required".to_owned())
        );
        assert_eq!(
            error(config("h", "25", " ")),
            Some("smtp from is required".to_owned())
        );
        assert!(SmtpSender::new(config("h", "25", "a@b")).is_ok_and(|s| s.credentials.is_none()));
    }

    #[test]
    fn plain_auth_needs_tls_or_localhost() {
        assert!(plain_auth_allowed(true, "smtp.gmail.com"));
        assert!(plain_auth_allowed(false, "localhost"));
        assert!(plain_auth_allowed(false, "127.0.0.1"));
        assert!(!plain_auth_allowed(false, "smtp.gmail.com"));
    }

    #[test]
    fn host_port_join() {
        assert_eq!(
            join_host_port("smtp.gmail.com", "587"),
            "smtp.gmail.com:587"
        );
        assert_eq!(join_host_port("::1", "25"), "[::1]:25");
    }

    #[test]
    fn line_validation() {
        assert!(validate_line("a@b").is_ok());
        assert!(validate_line("a@b\r\nRCPT TO:<x>").is_err());
    }
}
