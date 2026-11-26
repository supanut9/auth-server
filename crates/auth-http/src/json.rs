//! JSON responses serialised like gin's `c.JSON` (Go `encoding/json`).
//!
//! `serde_json::Map` is a `BTreeMap` in this workspace (no `preserve_order`),
//! so object keys come out sorted, as Go sorts `gin.H` map keys. Struct fields
//! keep declaration order, as Go does. Strings are escaped like Go:
//! `<`, `>`, `&`, U+2028 and U+2029 become `<`, `>`, `&`,
//! ` `, ` `. No trailing newline.

use std::io;

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::ser::Formatter;

/// gin's `MIMEJSON` render content type.
pub const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// A `serde_json` formatter that escapes strings like Go `encoding/json`.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoFormatter;

impl Formatter for GoFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let escaped: &[u8] = match c {
                '<' => b"\\u003c",
                '>' => b"\\u003e",
                '&' => b"\\u0026",
                '\u{2028}' => b"\\u2028",
                '\u{2029}' => b"\\u2029",
                _ => continue,
            };
            writer.write_all(&fragment.as_bytes()[start..i])?;
            writer.write_all(escaped)?;
            start = i + c.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
    // Everything else (control-character escapes `\b \f \n \r \t \u00XX` in
    // lowercase hex, compact separators, integers) already matches Go.
}

/// Serialises `value` with [`GoFormatter`].
pub fn to_go_json<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, GoFormatter);
    value.serialize(&mut serializer)?;
    Ok(out)
}

/// gin `c.JSON(status, value)`.
///
/// A serialisation failure yields 500 with an empty body; gin would panic
/// into its recovery middleware, which writes the same response.
pub fn json_response<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    match to_go_json(value) {
        Ok(body) => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(JSON_CONTENT_TYPE),
            );
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `IntoResponse` wrapper for [`json_response`] with status 200. Combine with
/// a status as `(StatusCode::BAD_REQUEST, GoJson(body))`.
#[derive(Debug, Clone)]
pub struct GoJson<T>(pub T);

impl<T: Serialize> IntoResponse for GoJson<T> {
    fn into_response(self) -> Response {
        json_response(StatusCode::OK, &self.0)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn escapes_like_go_encoding_json() {
        let value = json!({"b": "<a href=\"x\">&\u{2028}\u{2029}</a>", "a": "\n\t\u{1}\u{8}\u{c}\u{7f}é\\/"});
        assert_eq!(
            String::from_utf8(to_go_json(&value).unwrap()).unwrap(),
            r#"{"a":"\n\t\u0001\b\f"#.to_owned()
                + "\u{7f}é\\\\/\",\"b\":\"\\u003ca href=\\\"x\\\"\\u003e\\u0026\\u2028\\u2029\\u003c/a\\u003e\"}"
        );
    }

    #[test]
    fn sorts_map_keys_like_gin_h() {
        let value = json!({"status": "ok", "app_name": "auth-server", "request_id": "r"});
        assert_eq!(
            to_go_json(&value).unwrap(),
            br#"{"app_name":"auth-server","request_id":"r","status":"ok"}"#
        );
    }
}
