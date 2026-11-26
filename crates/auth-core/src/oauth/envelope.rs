//! Signed provider-state envelope (Go `internal/application/oauth/envelope.go`).
//!
//! The envelope is the `state` handed to Google/GitHub: a snapshot of the
//! OAuth request, `b64url(json) + "." + b64url(HMAC-SHA256(secret, b64url(json)))`.
//! Tokens signed by the Go service must verify here and vice versa, so the
//! JSON bytes, the MAC input and every verify error string match Go.

use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac as _};
use secrecy::{ExposeSecret as _, SecretSlice};
use sha2::Sha256;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use super::EnvelopeError;
use crate::crypto::gojson::{self, FlatDocument, FlatValue};
use crate::crypto::{b64url_encode, constant_time_eq, decode_b64url_go, new_jti};
use crate::ports::{Clock, JtiStore, RandomSource};

/// Minimum HMAC key length.
pub const MIN_SECRET_LEN: usize = 32;
/// TTL used when the configured one is zero or negative.
pub const DEFAULT_TTL: Duration = Duration::minutes(10);

/// The OAuth request snapshot (Go `oauth.Envelope`). Optional fields are
/// omitted from the payload when empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Envelope {
    pub provider: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub prompt: String,
}

/// Signs and verifies envelopes (Go `oauth.EnvelopeSigner`).
pub struct EnvelopeSigner {
    secret: SecretSlice<u8>,
    ttl: Duration,
    jti_store: Arc<dyn JtiStore>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn RandomSource>,
}

impl fmt::Debug for EnvelopeSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeSigner")
            .field("secret", &"[redacted]")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

type HmacSha256 = Hmac<Sha256>;

impl EnvelopeSigner {
    /// Go `NewEnvelopeSigner`: the secret must be at least 32 bytes; a TTL of
    /// zero or less becomes 10 minutes.
    ///
    /// # Errors
    /// [`EnvelopeError::SecretTooShort`] with the actual length.
    pub fn new(
        secret: impl Into<Vec<u8>>,
        ttl: Duration,
        jti_store: Arc<dyn JtiStore>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn RandomSource>,
    ) -> Result<Self, EnvelopeError> {
        let secret: Vec<u8> = secret.into();
        if secret.len() < MIN_SECRET_LEN {
            return Err(EnvelopeError::SecretTooShort(secret.len()));
        }
        let ttl = if ttl <= Duration::ZERO {
            DEFAULT_TTL
        } else {
            ttl
        };
        Ok(Self {
            secret: secret.into(),
            ttl,
            jti_store,
            clock,
            random,
        })
    }

    /// The effective TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    fn mac(&self, encoded: &str) -> String {
        // HMAC accepts keys of any length; the constructor guarantees >= 32 bytes.
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(self.secret.expose_secret())
            .unwrap_or_else(|_| unreachable!("HMAC takes keys of any length"));
        mac.update(encoded.as_bytes());
        b64url_encode(mac.finalize().into_bytes())
    }

    /// Go `Sign`: `iat` = now, `exp` = now + ttl, fresh 16-byte `jti`.
    ///
    /// # Errors
    /// Fails only when the random source fails.
    pub fn sign(&self, envelope: &Envelope) -> Result<String, EnvelopeError> {
        let jti = new_jti(self.random.as_ref())?;
        let now = self.clock.now();
        let iat = now.unix_timestamp();
        let exp = (now + self.ttl).unix_timestamp();
        let payload = payload_json(envelope, iat, exp, &jti);
        let encoded = b64url_encode(payload);
        let signature = self.mac(&encoded);
        Ok(format!("{encoded}.{signature}"))
    }

    /// Go `Verify`, in Go's order: split on the first `.`, constant-time MAC
    /// check over the base64 text, base64 decode, JSON decode, `now > exp`,
    /// non-empty `jti`, then the single-use JTI insert.
    ///
    /// # Errors
    /// Every failure carries Go's exact error text.
    pub async fn verify(&self, token: &str) -> Result<Envelope, EnvelopeError> {
        let Some((encoded, signature)) = token.split_once('.') else {
            return Err(EnvelopeError::MalformedToken);
        };
        let expected = self.mac(encoded);
        if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            return Err(EnvelopeError::SignatureMismatch);
        }
        let payload = decode_b64url_go(encoded.as_bytes())
            .map_err(|error| EnvelopeError::DecodePayload(error.to_string()))?;
        let claims = decode_claims(&payload).map_err(EnvelopeError::ParseClaims)?;

        if self.clock.now().unix_timestamp() > claims.exp {
            return Err(EnvelopeError::Expired);
        }
        if claims.jti.is_empty() {
            return Err(EnvelopeError::MissingJti);
        }
        self.jti_store
            .insert(&claims.jti, unix_to_datetime(claims.exp))
            .await?;
        Ok(claims.envelope)
    }
}

/// `time.Unix(exp, 0)`, saturated to the range `time` can represent.
fn unix_to_datetime(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(seconds).unwrap_or_else(|_| {
        if seconds > 0 {
            PrimitiveDateTime::MAX.assume_utc()
        } else {
            PrimitiveDateTime::MIN.assume_utc()
        }
    })
}

/// `json.Marshal(envelopeClaims)`: fixed field order, optional fields omitted
/// when empty, Go HTML escaping.
fn payload_json(envelope: &Envelope, iat: i64, exp: i64, jti: &str) -> String {
    let mut out = String::with_capacity(256);
    let required = [
        ("provider", &envelope.provider),
        ("client_id", &envelope.client_id),
        ("redirect_uri", &envelope.redirect_uri),
        ("scope", &envelope.scope),
        ("state", &envelope.state),
    ];
    let optional = [
        ("nonce", &envelope.nonce),
        ("code_challenge", &envelope.code_challenge),
        ("code_challenge_method", &envelope.code_challenge_method),
        ("prompt", &envelope.prompt),
    ];
    out.push('{');
    for (i, (name, value)) in required.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_field(&mut out, name, value);
    }
    for (name, value) in optional {
        if !value.is_empty() {
            out.push(',');
            push_field(&mut out, name, value);
        }
    }
    out.push_str(&format!(",\"iat\":{iat},\"exp\":{exp},\"jti\":"));
    gojson::write_string(&mut out, jti);
    out.push('}');
    out
}

fn push_field(out: &mut String, name: &str, value: &str) {
    out.push('"');
    out.push_str(name);
    out.push_str("\":");
    gojson::write_string(out, value);
}

#[derive(Debug, Default)]
struct Claims {
    envelope: Envelope,
    exp: i64,
    jti: String,
}

#[derive(Clone, Copy)]
enum Field {
    Text(TextField),
    Int(IntField),
}

#[derive(Clone, Copy)]
enum TextField {
    Provider,
    ClientId,
    RedirectUri,
    Scope,
    State,
    Nonce,
    CodeChallenge,
    CodeChallengeMethod,
    Prompt,
    Jti,
}

#[derive(Clone, Copy)]
enum IntField {
    Iat,
    Exp,
}

/// JSON name, Go error path (`envelopeClaims.<path>`), field.
const FIELDS: [(&str, &str, Field); 12] = [
    (
        "provider",
        "Envelope.provider",
        Field::Text(TextField::Provider),
    ),
    (
        "client_id",
        "Envelope.client_id",
        Field::Text(TextField::ClientId),
    ),
    (
        "redirect_uri",
        "Envelope.redirect_uri",
        Field::Text(TextField::RedirectUri),
    ),
    ("scope", "Envelope.scope", Field::Text(TextField::Scope)),
    ("state", "Envelope.state", Field::Text(TextField::State)),
    ("nonce", "Envelope.nonce", Field::Text(TextField::Nonce)),
    (
        "code_challenge",
        "Envelope.code_challenge",
        Field::Text(TextField::CodeChallenge),
    ),
    (
        "code_challenge_method",
        "Envelope.code_challenge_method",
        Field::Text(TextField::CodeChallengeMethod),
    ),
    ("prompt", "Envelope.prompt", Field::Text(TextField::Prompt)),
    ("iat", "iat", Field::Int(IntField::Iat)),
    ("exp", "exp", Field::Int(IntField::Exp)),
    ("jti", "jti", Field::Text(TextField::Jti)),
];

fn find_field(key: &str) -> Option<(&'static str, Field)> {
    FIELDS
        .iter()
        .find(|(name, _, _)| *name == key)
        .or_else(|| {
            let folded = gojson::fold_name(key);
            FIELDS
                .iter()
                .find(|(name, _, _)| gojson::fold_name(name) == folded)
        })
        .map(|&(_, path, field)| (path, field))
}

/// `json.Unmarshal(payload, &envelopeClaims)` with Go semantics: syntax
/// errors first, unknown fields ignored, case-insensitive field match, `null`
/// leaves a field unchanged, the first type error wins after decoding the rest.
fn decode_claims(payload: &[u8]) -> Result<Claims, String> {
    let document = gojson::parse_flat_object(payload).map_err(|error| error.to_string())?;
    let members = match document {
        FlatDocument::Object(members) => members,
        FlatDocument::Other(FlatValue::Null) => Vec::new(),
        FlatDocument::Other(other) => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type oauth.envelopeClaims",
                other.go_kind()
            ));
        }
    };
    let mut claims = Claims::default();
    let mut first_error: Option<String> = None;
    for (key, value) in members {
        let Some((path, field)) = find_field(&key) else {
            continue;
        };
        let mismatch = match (field, value) {
            (_, FlatValue::Null) => None,
            (Field::Text(text), FlatValue::String(s)) => {
                *text_slot(&mut claims, text) = s;
                None
            }
            (Field::Text(_), other) => Some((other.go_kind().to_owned(), "string")),
            (Field::Int(int), FlatValue::Number(n)) => match n.parse::<i64>() {
                Ok(parsed) => {
                    if matches!(int, IntField::Exp) {
                        claims.exp = parsed;
                    }
                    None
                }
                Err(_) => Some((format!("number {n}"), "int64")),
            },
            (Field::Int(_), other) => Some((other.go_kind().to_owned(), "int64")),
        };
        if let Some((value, go_type)) = mismatch {
            first_error.get_or_insert_with(|| {
                format!(
                    "json: cannot unmarshal {value} into Go struct field envelopeClaims.{path} of type {go_type}"
                )
            });
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(claims),
    }
}

fn text_slot(claims: &mut Claims, field: TextField) -> &mut String {
    let envelope = &mut claims.envelope;
    match field {
        TextField::Provider => &mut envelope.provider,
        TextField::ClientId => &mut envelope.client_id,
        TextField::RedirectUri => &mut envelope.redirect_uri,
        TextField::Scope => &mut envelope.scope,
        TextField::State => &mut envelope.state,
        TextField::Nonce => &mut envelope.nonce,
        TextField::CodeChallenge => &mut envelope.code_challenge,
        TextField::CodeChallengeMethod => &mut envelope.code_challenge_method,
        TextField::Prompt => &mut envelope.prompt,
        TextField::Jti => &mut claims.jti,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(json: &str) -> Result<Claims, String> {
        decode_claims(json.as_bytes())
    }

    #[test]
    fn payload_omits_empty_optionals() {
        let envelope = Envelope {
            provider: "google".into(),
            prompt: "login".into(),
            ..Envelope::default()
        };
        assert_eq!(
            payload_json(&envelope, 1, 2, "j"),
            r#"{"provider":"google","client_id":"","redirect_uri":"","scope":"","state":"","prompt":"login","iat":1,"exp":2,"jti":"j"}"#
        );
    }

    #[test]
    fn decode_follows_go_struct_rules() {
        let claims =
            decode(r#"{"PROVIDER":"g","ſtate":"s","exp":5,"jti":"a","jti":"b","scope":null}"#)
                .expect("decode");
        assert_eq!(claims.envelope.provider, "g");
        assert_eq!(claims.envelope.state, "s");
        assert_eq!(claims.exp, 5);
        assert_eq!(claims.jti, "b");

        let null = decode("null").expect("null decodes to zero value");
        assert_eq!(null.exp, 0);

        let cases = [
            (
                "[1]",
                "json: cannot unmarshal array into Go value of type oauth.envelopeClaims",
            ),
            (
                "\"x\"",
                "json: cannot unmarshal string into Go value of type oauth.envelopeClaims",
            ),
            (
                r#"{"exp":"1","provider":1}"#,
                "json: cannot unmarshal string into Go struct field envelopeClaims.exp of type int64",
            ),
            (
                r#"{"provider":true}"#,
                "json: cannot unmarshal bool into Go struct field envelopeClaims.Envelope.provider of type string",
            ),
            (
                r#"{"exp":1.5}"#,
                "json: cannot unmarshal number 1.5 into Go struct field envelopeClaims.exp of type int64",
            ),
            (
                r#"{"iat":99999999999999999999}"#,
                "json: cannot unmarshal number 99999999999999999999 into Go struct field envelopeClaims.iat of type int64",
            ),
            (
                r#"{"jti":{}}"#,
                "json: cannot unmarshal object into Go struct field envelopeClaims.jti of type string",
            ),
            ("{", "unexpected end of JSON input"),
        ];
        for (input, want) in cases {
            assert_eq!(decode(input).expect_err(input), want, "{input}");
        }
    }

    #[test]
    fn saturating_jti_expiry() {
        assert_eq!(unix_to_datetime(0), OffsetDateTime::UNIX_EPOCH);
        assert_eq!(
            unix_to_datetime(i64::MAX),
            PrimitiveDateTime::MAX.assume_utc()
        );
        assert_eq!(
            unix_to_datetime(i64::MIN),
            PrimitiveDateTime::MIN.assume_utc()
        );
    }
}
