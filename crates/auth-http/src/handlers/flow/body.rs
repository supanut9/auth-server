//! gin `ShouldBindJSON` for the flow request bodies: Go `encoding/json`
//! decoding into a struct of string fields, then `binding:"required"`.
//!
//! Decoding follows Go where it changes the outcome:
//!
//! - only the first JSON value is read (`json.Decoder.Decode`); trailing
//!   bytes are ignored, an empty body fails (Go `EOF`);
//! - object keys match a field exactly, else case-insensitively
//!   (`strings.EqualFold`); unknown keys are ignored whatever their type;
//!   a repeated key overwrites the earlier one;
//! - `null` (top level or as a field value) leaves the field unchanged;
//! - a field holding a non-string value, or a top-level value that is not
//!   an object, fails the bind.
//!
//! Accepted deviation (`docs/rust-port-deviations.md`): the error text is
//! `invalid JSON body` or `<field> is required` (the first missing field in
//! struct order) instead of gin's validator text. serde_json also rejects
//! invalid UTF-8 and lone surrogate escapes, which Go replaces with U+FFFD.

use std::fmt;

use auth_core::{identity::equal_fold, oauth::AuthorizeRequest};
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};

/// The bind failure; its text is the `error_description` of the 400.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindError(String);

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl BindError {
    fn invalid_json() -> Self {
        Self("invalid JSON body".to_owned())
    }
}

/// Decodes `body` into one string per entry of `fields` (same order), then
/// checks that every field named in `required` is non-empty.
///
/// # Errors
/// [`BindError`] as described in the module docs.
pub fn bind(
    body: &[u8],
    fields: &[&'static str],
    required: &[&'static str],
) -> Result<Vec<String>, BindError> {
    let mut values = vec![String::new(); fields.len()];
    let mut stream = serde_json::Deserializer::from_slice(body).into_iter::<IgnoredAny>();
    // The stream is only used to locate the first value; decode it with the
    // field-aware seed.
    let Some(first) = stream.next() else {
        return Err(BindError::invalid_json());
    };
    first.map_err(|_| BindError::invalid_json())?;
    let end = stream.byte_offset();
    let mut deserializer = serde_json::Deserializer::from_slice(&body[..end]);
    let typed = Fields {
        names: fields,
        values: &mut values,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| BindError::invalid_json())?;
    if !typed {
        return Err(BindError::invalid_json());
    }
    for (name, value) in fields.iter().zip(&values) {
        if required.contains(name) && value.is_empty() {
            return Err(BindError(format!("{name} is required")));
        }
    }
    Ok(values)
}

/// Seed that writes matching string fields into `values`. Yields `false`
/// when a known field held a non-string value (Go `UnmarshalTypeError`,
/// which does not stop decoding but fails the bind).
struct Fields<'a> {
    names: &'a [&'static str],
    values: &'a mut [String],
}

impl<'de> DeserializeSeed<'de> for Fields<'_> {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Fields<'_> {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_unit<E: de::Error>(self) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_none<E: de::Error>(self) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut typed = true;
        while let Some(key) = map.next_key::<String>()? {
            let index = self
                .names
                .iter()
                .position(|name| *name == key)
                .or_else(|| self.names.iter().position(|name| equal_fold(name, &key)));
            let Some(index) = index else {
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            match map.next_value::<FieldValue>()? {
                FieldValue::String(value) => self.values[index] = value,
                FieldValue::Null => {}
                FieldValue::Other => typed = false,
            }
        }
        Ok(typed)
    }

    // Any other top-level JSON type is a Go `UnmarshalTypeError`.
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<bool, E> {
        Ok(false)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(false)
    }
}

/// A known field's JSON value, as far as a Go `string` field cares.
enum FieldValue {
    String(String),
    Null,
    Other,
}

impl<'de> de::Deserialize<'de> for FieldValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(FieldValueVisitor)
    }
}

struct FieldValueVisitor;

impl<'de> Visitor<'de> for FieldValueVisitor {
    type Value = FieldValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<FieldValue, E> {
        Ok(FieldValue::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<FieldValue, E> {
        Ok(FieldValue::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<FieldValue, E> {
        Ok(FieldValue::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<FieldValue, E> {
        Ok(FieldValue::Null)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<FieldValue, E> {
        Ok(FieldValue::Other)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<FieldValue, E> {
        Ok(FieldValue::Other)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<FieldValue, E> {
        Ok(FieldValue::Other)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<FieldValue, E> {
        Ok(FieldValue::Other)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<FieldValue, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(FieldValue::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<FieldValue, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(FieldValue::Other)
    }
}

/// The nine OAuth fields of Go `authorizeRequestBody`, in struct order.
pub const AUTHORIZE_FIELDS: [&str; 9] = [
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "response_type",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "prompt",
];

/// `binding:"required"` fields of `authorizeRequestBody`.
pub const AUTHORIZE_REQUIRED: [&str; 4] = ["client_id", "redirect_uri", "scope", "state"];

/// Go `authorizeRequestBody`: the OAuth params as sent by auth-ui.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizeBody(AuthorizeRequest);

impl AuthorizeBody {
    /// Takes the first nine `values` (bound with [`AUTHORIZE_FIELDS`] first).
    fn from_values(values: &mut std::vec::IntoIter<String>) -> Self {
        let mut next = || values.next().unwrap_or_default();
        let client_id = next();
        let redirect_uri = next();
        let scope = next();
        let state = next();
        Self(AuthorizeRequest {
            client_id,
            redirect_uri,
            scope,
            state,
            response_type: next(),
            nonce: next(),
            code_challenge: next(),
            code_challenge_method: next(),
            prompt: next(),
        })
    }

    /// The params exactly as sent (`toQuery` source).
    #[must_use]
    pub fn raw(&self) -> &AuthorizeRequest {
        &self.0
    }

    /// Go `toOAuthRequest`: `response_type` defaults to `code`.
    #[must_use]
    pub fn to_oauth_request(&self) -> AuthorizeRequest {
        let mut request = self.0.clone();
        if request.response_type.is_empty() {
            request.response_type = "code".to_owned();
        }
        request
    }
}

/// Binds an [`AuthorizeBody`] followed by `extra` fields (Go struct
/// embedding: the embedded fields come first in validation order). Every
/// `extra` field is required, as in each Go body type.
///
/// # Errors
/// [`BindError`].
pub fn bind_authorize_with(
    body: &[u8],
    extra: &[&'static str],
) -> Result<(AuthorizeBody, Vec<String>), BindError> {
    let fields: Vec<&'static str> = AUTHORIZE_FIELDS.iter().chain(extra).copied().collect();
    let required: Vec<&'static str> = AUTHORIZE_REQUIRED.iter().chain(extra).copied().collect();
    let mut values = bind(body, &fields, &required)?.into_iter();
    let authorize = AuthorizeBody::from_values(&mut values);
    Ok((authorize, values.collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELDS: [&str; 2] = ["client_id", "code"];

    fn run(body: &str) -> Result<Vec<String>, BindError> {
        bind(body.as_bytes(), &FIELDS, &["client_id"])
    }

    #[test]
    fn decodes_like_go_encoding_json() {
        assert_eq!(run(r#"{"client_id":"a","code":"b"}"#).unwrap(), ["a", "b"]);
        // Case-insensitive match, last key wins, null keeps the value,
        // unknown keys of any type are ignored, trailing bytes ignored.
        assert_eq!(
            run(r#" {"CLIENT_ID":"x","client_id":"a","code":"b","code":null,"n":1e999,"o":{"a":[1]}} trailing"#)
                .unwrap(),
            ["a", "b"]
        );
    }

    #[test]
    fn rejects_like_gin() {
        for body in [
            "",
            "  ",
            "{",
            "[]",
            "\"s\"",
            "1",
            r#"{"client_id":1}"#,
            r#"{"client_id":"a","code":{}}"#,
        ] {
            assert_eq!(
                run(body).unwrap_err().to_string(),
                "invalid JSON body",
                "{body:?}"
            );
        }
        for body in ["null", "{}", r#"{"client_id":""}"#, r#"{"client_id":null}"#] {
            assert_eq!(
                run(body).unwrap_err().to_string(),
                "client_id is required",
                "{body:?}"
            );
        }
    }

    #[test]
    fn authorize_body_defaults_response_type() {
        let (body, extra) = bind_authorize_with(
            br#"{"client_id":"c","redirect_uri":"r","scope":"s","state":"t","email":"e"}"#,
            &["email"],
        )
        .unwrap();
        assert_eq!(body.raw().response_type, "");
        assert_eq!(body.to_oauth_request().response_type, "code");
        assert_eq!(extra, ["e"]);
        let error = bind_authorize_with(
            br#"{"client_id":"c","redirect_uri":"r","scope":"s"}"#,
            &["email"],
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "state is required");
    }
}
