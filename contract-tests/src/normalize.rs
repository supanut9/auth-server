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
