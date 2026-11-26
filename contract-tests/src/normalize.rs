//! Normalize volatile response values for comparisons across server runs.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

pub fn json(value: &Value) -> Value {
    field("", value)
}

pub fn request_id(_: &str) -> &str {
    "<request-id>"
}

pub fn location(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return value.into();
    };
    if url.query().is_none() {
        return value.into();
    }

    let pairs: Vec<_> = url
        .query_pairs()
        .map(|(name, value)| {
            let normalized = string(&name, &value).unwrap_or_else(|| value.into_owned());
            (name.into_owned(), normalized)
        })
        .collect();
    url.query_pairs_mut().clear().extend_pairs(pairs);
    url.into()
}

fn field(key: &str, value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, value)| (name.clone(), field(name, value)))
                .collect(),
        ),
        Value::Array(list) => Value::Array(list.iter().map(|value| field(key, value)).collect()),
        Value::Number(_) if matches!(key, "iat" | "exp" | "auth_time" | "nbf") => {
            Value::String("<timestamp>".into())
        }
        Value::String(value) => {
            string(key, value).map_or_else(|| Value::String(value.clone()), Value::String)
        }
        _ => value.clone(),
    }
}

fn string(key: &str, value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let replacement = match key {
        "request_id" => request_id(value),
        "redirect_to" | "location" => return Some(location(value)),
        "csrf_token" => "<csrf-token>",
        "refresh_token" => "<refresh-token>",
        "code" | "otp_code" if matches!(value.len(), 8 | 43) && is_base64url(value) => "<code>",
        _ if Uuid::parse_str(value).is_ok() => "<uuid>",
        _ if is_jwt(value) => "<jwt>",
        _ if key.ends_with("_at") && value.contains('T') => "<timestamp>",
        _ => return None,
    };
    Some(replacement.into())
}

fn is_base64url(value: &str) -> bool {
    !value.is_empty() && URL_SAFE_NO_PAD.decode(value).is_ok()
}

fn is_jwt(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    if let [header, payload, signature] = parts.as_slice() {
        URL_SAFE_NO_PAD
            .decode(header)
            .is_ok_and(|bytes| serde_json::from_slice::<Value>(&bytes).is_ok_and(|v| v.is_object()))
            && is_base64url(payload)
            && is_base64url(signature)
    } else {
        false
    }
}

/// Consistent aliasing for differential runs. Each distinct volatile value
/// (UUID, opaque token, JWT, flow envelope) becomes `<kind#n>`, numbered in
/// order of first appearance within one server's run. Equal values keep equal
/// aliases, so a deterministic script yields identical aliases on both servers
/// only if the relationships between values (sub = account id, sid = cookie,
/// rotated token != original, ...) also match. JWTs and envelopes are
/// expanded so their claims compare field by field.
#[derive(Default)]
pub struct Normalizer {
    aliases: std::collections::HashMap<String, String>,
    counters: std::collections::HashMap<String, usize>,
    /// The `X-Request-Id` the current request sent, if any.
    pub sent_request_id: Option<String>,
}

impl Normalizer {
    pub fn alias(&mut self, kind: &str, raw: &str) -> String {
        if let Some(alias) = self.aliases.get(raw) {
            return alias.clone();
        }
        let counter = self.counters.entry(kind.into()).or_default();
        *counter += 1;
        let alias = format!("<{kind}#{counter}>");
        self.aliases.insert(raw.into(), alias.clone());
        alias
    }

    pub fn json(&mut self, value: &Value) -> Value {
        self.value("", value, true)
    }

    fn value(&mut self, key: &str, value: &Value, expand: bool) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(name, value)| (name.clone(), self.value(name, value, expand)))
                    .collect(),
            ),
            Value::Array(list) => Value::Array(
                list.iter()
                    .map(|value| self.value(key, value, expand))
                    .collect(),
            ),
            Value::Number(_) if matches!(key, "iat" | "exp" | "auth_time" | "nbf") => {
                Value::String("<timestamp>".into())
            }
            Value::String(text) => self.string(key, text, expand),
            _ => value.clone(),
        }
    }

    /// Classify a request ID: echoed from the request, a generated UUID v4,
    /// or (unexpectedly) anything else verbatim.
    pub fn request_id(&self, value: &str) -> String {
        if self.sent_request_id.as_deref() == Some(value) {
            "<echoed-request-id>".into()
        } else if Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4) {
            "<generated-uuid-v4>".into()
        } else {
            value.into()
        }
    }

    pub fn string(&mut self, key: &str, text: &str, expand: bool) -> Value {
        if text.is_empty() {
            return Value::String(String::new());
        }
        if key == "request_id" {
            return Value::String(self.request_id(text));
        }
        if is_jwt(text) {
            // RS256 is deterministic and `iat` has one-second granularity, so
            // two tokens with identical claims may or may not be byte-equal
            // depending on timing. JWTs are therefore not numbered; their
            // claims are compared instead.
            if !expand {
                return Value::String("<jwt>".into());
            }
            return self.expand_jwt("<jwt>".into(), text);
        }
        if let Some(payload) = envelope_payload(text) {
            let alias = self.alias("envelope", text);
            if !expand {
                return Value::String(alias);
            }
            return self.expand_envelope(alias, &payload);
        }
        if let Ok(id) = Uuid::parse_str(text) {
            let kind = format!("uuid-v{}", id.get_version_num());
            return Value::String(self.alias(&kind, text));
        }
        if text.len() == 43 && URL_SAFE_NO_PAD.decode(text).is_ok_and(|b| b.len() == 32) {
            return Value::String(self.alias("opaque", text));
        }
        if (text.starts_with("http://") || text.starts_with("https://")) && text.contains('?') {
            return Value::String(self.url(text));
        }
        if let Some(class) = timestamp_class(text) {
            return Value::String(class.into());
        }
        Value::String(text.into())
    }

    fn expand_jwt(&mut self, alias: String, raw: &str) -> Value {
        let mut parts = raw.split('.');
        let decode = |part: Option<&str>| {
            part.and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .unwrap_or(Value::Null)
        };
        let header = decode(parts.next());
        let claims = decode(parts.next());
        let lifetime = match (claims["exp"].as_i64(), claims["iat"].as_i64()) {
            (Some(exp), Some(iat)) => Value::from(exp - iat),
            _ => Value::Null,
        };
        let auth_time_le_iat = match (claims["auth_time"].as_i64(), claims["iat"].as_i64()) {
            (Some(auth), Some(iat)) => Value::Bool(auth <= iat),
            _ => Value::Null,
        };
        serde_json::json!({
            "jwt": alias,
            "header": self.value("", &header, false),
            "claims": self.value("", &claims, false),
            "derived": {"exp_minus_iat": lifetime, "auth_time_le_iat": auth_time_le_iat},
        })
    }

    /// Envelopes carry their exact JSON bytes (field order is part of the
    /// contract), so keep the payload text with only `jti`/`exp` replaced.
    fn expand_envelope(&mut self, alias: String, payload: &str) -> Value {
        let parsed: Value = serde_json::from_str(payload).unwrap_or(Value::Null);
        let mut text = payload.to_owned();
        if let Some(jti) = parsed["jti"].as_str() {
            text = text.replace(jti, &format!("<jti len={}>", jti.len()));
        }
        if let Some(exp) = parsed["exp"].as_i64() {
            text = text.replace(&exp.to_string(), "<exp>");
        }
        serde_json::json!({"envelope": alias, "payload": text})
    }

    /// Keep the raw query (order and encoding are contract) and replace only
    /// volatile values with their aliases.
    pub fn url(&mut self, raw: &str) -> String {
        let (before, fragment) = match raw.split_once('#') {
            Some((before, fragment)) => (before, Some(fragment)),
            None => (raw, None),
        };
        let Some((base, query)) = before.split_once('?') else {
            return raw.into();
        };
        let segments: Vec<String> = query
            .split('&')
            .map(|segment| {
                let Some((name, decoded)) = url::form_urlencoded::parse(segment.as_bytes()).next()
                else {
                    return segment.into();
                };
                match self.string(&name, &decoded, false) {
                    Value::String(value) if value != decoded => {
                        format!("{}={value}", segment.split('=').next().unwrap_or_default())
                    }
                    _ => segment.into(),
                }
            })
            .collect();
        let mut out = format!("{base}?{}", segments.join("&"));
        if let Some(fragment) = fragment {
            out.push('#');
            out.push_str(fragment);
        }
        out
    }
}

fn envelope_payload(value: &str) -> Option<String> {
    let (payload, signature) = value.split_once('.')?;
    if signature.contains('.') || !is_base64url(signature) {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    serde_json::from_str::<Value>(&text)
        .ok()
        .filter(|parsed| parsed.get("jti").is_some())
        .map(|_| text)
}

fn timestamp_class(value: &str) -> Option<&'static str> {
    let bytes = value.as_bytes();
    let shaped = bytes.len() >= 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':';
    if !shaped {
        None
    } else if value.ends_with('Z') {
        Some("<timestamp-utc>")
    } else {
        Some("<timestamp-offset>")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn normalizes_volatile_fields_and_retains_contract_values() {
        let id = "01900000-0000-7000-8000-000000000123";
        let code = "A".repeat(43);
        let input = json!({
            "request_id": "req.one",
            "access_token": "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
            "redirect_to": format!("http://example.test/callback?code={code}&state=a+b#keep"),
            "data": [{"id": id, "exp": 1770000000, "expires_at": "2026-11-25T01:00:00Z"}],
            "expires_in": 600,
            "error_description": "otp challenge invalid",
            "revoked_at": null,
        });
        assert_eq!(
            json(&input),
            json!({
                "request_id": "<request-id>",
                "access_token": "<jwt>",
                "redirect_to": "http://example.test/callback?code=%3Ccode%3E&state=a+b#keep",
                "data": [{"id": "<uuid>", "exp": "<timestamp>", "expires_at": "<timestamp>"}],
                "expires_in": 600,
                "error_description": "otp challenge invalid",
                "revoked_at": null,
            })
        );
    }
}
