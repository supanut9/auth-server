//! Raw MIME message (`internal/adapter/out/mail/smtp.go` `buildMessage`).

use auth_core::ports::MailMessage;

/// Fixed multipart boundary used by Go.
pub const MIME_BOUNDARY: &str = "----=_Part_MimeBoundary_AuthServer";

/// Builds the message exactly like Go: only `From`, `To`, `Subject` and
/// `MIME-Version` headers, CRLF header lines, no RFC 2047 encoding of the
/// subject, bodies inserted verbatim (LF line endings kept), each part followed
/// by CRLF. With an HTML body it is `multipart/alternative` (text, then HTML);
/// otherwise a single `text/plain` body.
#[must_use]
pub fn build_message(from: &str, message: &MailMessage) -> String {
    let mut out = String::new();
    out.push_str("From: ");
    out.push_str(from);
    out.push_str("\r\nTo: ");
    out.push_str(&message.to);
    out.push_str("\r\nSubject: ");
    out.push_str(&message.subject);
    out.push_str("\r\nMIME-Version: 1.0\r\n");

    if message.html.is_empty() {
        out.push_str("Content-Type: text/plain; charset=UTF-8\r\n\r\n");
        out.push_str(&message.text);
        out.push_str("\r\n");
    } else {
        out.push_str("Content-Type: multipart/alternative; boundary=\"");
        out.push_str(MIME_BOUNDARY);
        out.push_str("\"\r\n\r\n");

        out.push_str("--");
        out.push_str(MIME_BOUNDARY);
        out.push_str("\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n");
        out.push_str(&message.text);
        out.push_str("\r\n");

        out.push_str("--");
        out.push_str(MIME_BOUNDARY);
        out.push_str("\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
        out.push_str(&message.html);
        out.push_str("\r\n");

        out.push_str("--");
        out.push_str(MIME_BOUNDARY);
        out.push_str("--\r\n");
    }
    out
}

/// What Go's `textproto` `DotWriter` puts on the wire for `DATA`: a bare `\n`
/// becomes `\r\n`, a line starting with `.` gets another `.`, and the data ends
/// with `.\r\n` (after a CRLF if the message is empty or did not end with one).
#[must_use]
pub fn smtp_data_encoding(message: &str) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Begin,
        BeginLine,
        Data,
        Cr,
    }

    let mut out = String::with_capacity(message.len() + message.len() / 32 + 5);
    let mut state = State::Begin;
    for ch in message.chars() {
        match state {
            State::Begin | State::BeginLine | State::Data => {
                if state != State::Data && ch == '.' {
                    out.push('.');
                }
                state = State::Data;
                if ch == '\r' {
                    state = State::Cr;
                }
                if ch == '\n' {
                    out.push('\r');
                    state = State::BeginLine;
                }
            }
            State::Cr => {
                state = if ch == '\n' {
                    State::BeginLine
                } else {
                    State::Data
                };
            }
        }
        out.push(ch);
    }
    match state {
        State::Cr => out.push_str("\n.\r\n"),
        State::Begin | State::Data => out.push_str("\r\n.\r\n"),
        State::BeginLine => out.push_str(".\r\n"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_encoding_matches_go_dot_writer() {
        assert_eq!(smtp_data_encoding("a\r\n"), "a\r\n.\r\n");
        assert_eq!(smtp_data_encoding("a\nb"), "a\r\nb\r\n.\r\n");
        assert_eq!(smtp_data_encoding(".x\r\n..y\n"), "..x\r\n...y\r\n.\r\n");
        assert_eq!(smtp_data_encoding("a\r"), "a\r\n.\r\n");
        assert_eq!(smtp_data_encoding("a\r.b\r\n"), "a\r.b\r\n.\r\n");
        assert_eq!(smtp_data_encoding(""), "\r\n.\r\n");
    }
}
