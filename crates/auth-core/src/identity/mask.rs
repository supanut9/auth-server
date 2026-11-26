//! OTP response email masking (Go `router.go maskEmail`).
//!
//! Go's function lives in the HTTP adapter; it is pure, so it lives here and
//! the Rust HTTP layer reuses it.
//!
//! The masking is byte-based: a multi-byte first or last character of the
//! local part is cut mid-rune, so the result can be invalid UTF-8.
//! [`mask_email_bytes`] returns those exact bytes. Gin's `c.JSON` then writes
//! every invalid byte as the escape `\ufffd`:
//!
//! - [`mask_email_json`] is that exact JSON string token (quotes included,
//!   Go HTML escaping). Splice it in when the response bytes must match Go.
//! - [`mask_email`] is the decoded value (one U+FFFD per invalid byte). A
//!   generic JSON encoder writes the replacement character as raw UTF-8
//!   instead of `\ufffd`: the same JSON value, different bytes.
//!
//! Only the cut bytes can be invalid, and each is followed by `*` or `@`, so
//! one U+FFFD per invalid byte is also what `String::from_utf8_lossy` yields
//! for any `&str` input.

use crate::crypto::gojson;

/// Go `maskEmail`, as bytes.
///
/// Split on every `@`; unless there are exactly two parts with a non-empty
/// local part the input is returned unchanged. A local part of at most two
/// bytes becomes `local[0] + "*"`; a longer one keeps its first and last byte
/// and replaces the `len - 2` bytes between with `*`.
#[must_use]
pub fn mask_email_bytes(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut parts = bytes.split(|&b| b == b'@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return bytes.to_vec();
    };
    if local.is_empty() {
        return bytes.to_vec();
    }

    let mut out = Vec::with_capacity(bytes.len());
    out.push(local[0]);
    if local.len() <= 2 {
        out.push(b'*');
    } else {
        out.resize(local.len() - 1, b'*');
        out.push(local[local.len() - 1]);
    }
    out.push(b'@');
    out.extend_from_slice(domain);
    out
}

/// [`mask_email_bytes`] decoded the way Go's JSON encoder sees it: each
/// invalid byte becomes U+FFFD.
#[must_use]
pub fn mask_email(value: &str) -> String {
    let bytes = mask_email_bytes(value);
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}

/// The JSON string token Gin writes for [`mask_email_bytes`]: Go
/// `encoding/json` escaping, with `\ufffd` for each invalid byte.
#[must_use]
pub fn mask_email_json(value: &str) -> String {
    let bytes = mask_email_bytes(value);
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        if !valid.is_empty() {
            let mut quoted = String::with_capacity(valid.len() + 2);
            gojson::write_string(&mut quoted, valid);
            out.push_str(&quoted[1..quoted.len() - 1]);
        }
        for _ in chunk.invalid() {
            out.push_str("\\ufffd");
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_like_go() {
        assert_eq!(mask_email("alice@example.com"), "a***e@example.com");
        assert_eq!(mask_email("ab@x"), "a*@x");
        assert_eq!(mask_email("a@b@c"), "a@b@c");
        assert_eq!(mask_email_bytes("é@x"), b"\xc3*@x");
        assert_eq!(mask_email("é@x"), "\u{fffd}*@x");
        // Go HTML-escapes `<`, `>` and `&`.
        let bs = '\\';
        assert_eq!(
            mask_email_json("<a>@x&y"),
            format!("\"{bs}u003c*{bs}u003e@x{bs}u0026y\"")
        );
    }
}
