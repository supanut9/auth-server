//! SMTP sender against a local fake ESMTP server (no network beyond 127.0.0.1).

use std::path::PathBuf;

use auth_adapters::mail::{
    SmtpSender, SmtpSenderConfig, build_message, render_otp_email_with_remaining,
    smtp_data_encoding,
};
use auth_core::ports::{MailMessage, MailSender};
use base64::Engine as _;
use secrecy::SecretString;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const FROM: &str = "no-reply@auth.example.com";

/// What the fake server advertises and how it answers.
#[derive(Clone)]
struct Script {
    ehlo: &'static str,
    starttls_reply: &'static str,
    rcpt_reply: &'static str,
}

const FULL_EHLO: &str =
    "250-fake.local\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250 AUTH PLAIN LOGIN\r\n";
const MINIMAL_EHLO: &str = "250 fake.local\r\n";

impl Default for Script {
    fn default() -> Self {
        Self {
            ehlo: FULL_EHLO,
            starttls_reply: "454 4.7.0 TLS not available\r\n",
            rcpt_reply: "250 2.1.5 ok\r\n",
        }
    }
}

/// Commands received (without CRLF) and the raw bytes sent after `DATA`.
#[derive(Debug, Default)]
struct Transcript {
    commands: Vec<String>,
    data: Vec<u8>,
}

async fn fake_server(script: Script) -> (u16, JoinHandle<Transcript>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let (read, mut write) = socket.into_split();
        let mut reader = BufReader::new(read);
        let mut transcript = Transcript::default();
        write
            .write_all(b"220 fake.local ESMTP\r\n")
            .await
            .expect("greet");
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.expect("read") == 0 {
                break;
            }
            let command = line.trim_end_matches("\r\n").to_owned();
            transcript.commands.push(command.clone());
            let verb = command
                .split(' ')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            let reply: &str = match verb.as_str() {
                "EHLO" => script.ehlo,
                "STARTTLS" => script.starttls_reply,
                "AUTH" => "235 2.7.0 Authentication successful\r\n",
                "MAIL" => "250 2.1.0 ok\r\n",
                "RCPT" => script.rcpt_reply,
                "DATA" => {
                    write.write_all(b"354 go ahead\r\n").await.expect("354");
                    let mut data = Vec::new();
                    while !data.ends_with(b"\r\n.\r\n") {
                        let mut byte = [0_u8; 1];
                        reader.read_exact(&mut byte).await.expect("data");
                        data.push(byte[0]);
                    }
                    transcript.data = data;
                    "250 2.0.0 queued\r\n"
                }
                "QUIT" => {
                    write.write_all(b"221 2.0.0 bye\r\n").await.expect("221");
                    break;
                }
                _ => "500 5.5.1 unknown\r\n",
            };
            write.write_all(reply.as_bytes()).await.expect("reply");
        }
        transcript
    });
    (port, handle)
}

fn sender(port: u16, username: &str) -> SmtpSender {
    SmtpSender::new(SmtpSenderConfig {
        host: "127.0.0.1".to_owned(),
        port: port.to_string(),
        username: username.to_owned(),
        password: SecretString::from("app-password".to_owned()),
        from: FROM.to_owned(),
    })
    .expect("sender")
}

fn otp_message(to: &str) -> MailMessage {
    let email =
        render_otp_email_with_remaining("AbCd-_12", "auth-server", time::Duration::minutes(10));
    MailMessage {
        to: to.to_owned(),
        subject: email.subject,
        text: email.text,
        html: email.html,
    }
}

#[tokio::test]
async fn sends_go_session_with_auth_and_exact_data() {
    let (port, server) = fake_server(Script::default()).await;
    let message = otp_message("user@example.com");

    sender(port, "mailer@example.com")
        .send(message.clone())
        .await
        .expect("send");
    let transcript = server.await.expect("server");

    let plain =
        base64::engine::general_purpose::STANDARD.encode("\0mailer@example.com\0app-password");
    assert_eq!(
        transcript.commands,
        vec![
            "EHLO localhost".to_owned(),
            format!("AUTH PLAIN {plain}"),
            format!("MAIL FROM:<{FROM}> BODY=8BITMIME SMTPUTF8"),
            "RCPT TO:<user@example.com>".to_owned(),
            "DATA".to_owned(),
            "QUIT".to_owned(),
        ]
    );
    let mime = build_message(FROM, &message);
    assert_eq!(transcript.data, smtp_data_encoding(&mime).into_bytes());
    // Go's DotWriter turns the text part's bare LFs into CRLF on the wire; nothing else changes.
    let expected_wire = format!("{}.\r\n", mime.replace("\r\n", "\n").replace('\n', "\r\n"));
    assert_eq!(transcript.data, expected_wire.into_bytes());
}

#[tokio::test]
async fn golden_mime_goes_on_the_wire_unchanged_apart_from_line_endings() {
    let golden_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/golden/otp_email.json");
    let golden: Value =
        serde_json::from_slice(&std::fs::read(golden_path).expect("golden")).expect("json");
    let case = &golden["render"]["cases"][0];
    let field = |key: &str| case[key].as_str().expect(key).to_owned();

    let (port, server) = fake_server(Script::default()).await;
    let message = MailMessage {
        to: field("to"),
        subject: field("subject"),
        text: field("text"),
        html: field("html"),
    };
    let sender = SmtpSender::new(SmtpSenderConfig {
        host: "127.0.0.1".to_owned(),
        port: port.to_string(),
        username: String::new(),
        password: SecretString::from(String::new()),
        from: field("from"),
    })
    .expect("sender");
    sender.send(message).await.expect("send");
    let transcript = server.await.expect("server");

    let golden_mime = field("mime_message");
    assert_eq!(
        transcript.data,
        format!(
            "{}.\r\n",
            golden_mime.replace("\r\n", "\n").replace('\n', "\r\n")
        )
        .into_bytes()
    );
}

#[tokio::test]
async fn data_bytes_equal_built_mime_when_already_crlf() {
    let (port, server) = fake_server(Script::default()).await;
    let message = MailMessage {
        to: "user@example.com".to_owned(),
        subject: "Plain only".to_owned(),
        text: "single line".to_owned(),
        html: String::new(),
    };
    sender(port, "").send(message.clone()).await.expect("send");
    let transcript = server.await.expect("server");

    let mut expected = build_message(FROM, &message).into_bytes();
    expected.extend_from_slice(b".\r\n");
    assert_eq!(transcript.data, expected);
    assert!(
        !transcript
            .commands
            .iter()
            .any(|command| command.starts_with("AUTH"))
    );
}

#[tokio::test]
async fn skips_auth_when_not_advertised_and_omits_mail_params() {
    let (port, server) = fake_server(Script {
        ehlo: MINIMAL_EHLO,
        ..Script::default()
    })
    .await;
    sender(port, "mailer@example.com")
        .send(otp_message("user@example.com"))
        .await
        .expect("send");
    let transcript = server.await.expect("server");
    assert_eq!(
        transcript.commands,
        vec![
            "EHLO localhost".to_owned(),
            format!("MAIL FROM:<{FROM}>"),
            "RCPT TO:<user@example.com>".to_owned(),
            "DATA".to_owned(),
            "QUIT".to_owned(),
        ]
    );
}

#[tokio::test]
async fn attempts_starttls_when_advertised() {
    let (port, server) = fake_server(Script {
        ehlo: "250-fake.local\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
        ..Script::default()
    })
    .await;
    let error = sender(port, "mailer@example.com")
        .send(otp_message("user@example.com"))
        .await
        .expect_err("starttls refused");
    assert_eq!(error.to_string(), "start tls: 454 4.7.0 TLS not available");
    let transcript = server.await.expect("server");
    assert_eq!(transcript.commands[..2], ["EHLO localhost", "STARTTLS"]);
    assert!(
        !transcript
            .commands
            .iter()
            .any(|command| command.starts_with("AUTH"))
    );
}

#[tokio::test]
async fn recipient_rejection_reads_like_go() {
    let (port, server) = fake_server(Script {
        rcpt_reply: "550 5.1.1 no such user\r\n",
        ..Script::default()
    })
    .await;
    let error = sender(port, "")
        .send(otp_message("nobody@example.com"))
        .await
        .expect_err("550");
    assert_eq!(error.to_string(), "smtp rcpt: 550 5.1.1 no such user");
    let transcript = server.await.expect("server");
    assert!(!transcript.commands.iter().any(|command| command == "DATA"));
}

#[tokio::test]
async fn rejects_crlf_in_recipient_before_rcpt() {
    let (port, server) = fake_server(Script::default()).await;
    let error = sender(port, "")
        .send(otp_message("a@example.com\r\nRCPT TO:<b@example.com>"))
        .await
        .expect_err("crlf");
    assert_eq!(
        error.to_string(),
        "smtp rcpt: smtp: A line must not contain CR or LF"
    );
    let transcript = server.await.expect("server");
    assert!(
        !transcript
            .commands
            .iter()
            .any(|command| command.starts_with("RCPT"))
    );
}

#[tokio::test]
async fn dial_failure_is_wrapped() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let error = sender(port, "")
        .send(otp_message("user@example.com"))
        .await
        .expect_err("refused");
    assert!(
        error
            .to_string()
            .starts_with(&format!("dial smtp server: dial tcp 127.0.0.1:{port}: ")),
        "{error}"
    );
}
