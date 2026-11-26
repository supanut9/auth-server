//! Signing keys and JSON Web Key Set publication
//! (Go `internal/adapter/out/jwks/manager.go`).
//!
//! - Keys load from PEM strings (or files): private PKCS#1 then PKCS#8 (RSA
//!   only), public PKIX then an X.509 certificate. Only the first PEM block
//!   counts; text before it is ignored; `\n` escapes are not unescaped.
//! - New vs Go: the public key must be the private key's public half,
//!   otherwise loading fails with [`KeyError::KeyPairMismatch`].
//! - `kid` = `base64url_nopad(SHA-256(SPKI DER))`.
//! - Signing is RS256 only (RSASSA-PKCS1-v1_5, deterministic). Header and
//!   claims serialize like Go maps (sorted keys, HTML escaping), so tokens
//!   match the Go service byte for byte.
//! - Verification follows golang-jwt v5 defaults: the header `alg` must equal
//!   the configured alg, `exp`/`nbf` are checked with no leeway when present,
//!   `iat`/`iss`/`aud` are not checked.

mod cert;
mod pem;

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use auth_core::crypto::gojson;
use auth_core::crypto::{b64url_encode, decode_b64url_go};
use auth_core::ports::{
    Clock, JwksProvider, JwtClaims, JwtError, JwtSigner, JwtVerifier, SignedJwt,
};
use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs8::{EncodePublicKey as _, PrivateKeyInfoRef, SubjectPublicKeyInfoRef};
use rsa::sha2::{Digest as _, Sha256};
use rsa::traits::PublicKeyParts as _;
use rsa::{Pkcs1v15Sign, PrivateKey, PublicKey};
use serde_json::Value;
use time::OffsetDateTime;

/// The only signing algorithm Go supports (`JWT_SIGNING_ALG`).
pub const RS256: &str = "RS256";

/// Key loading failure. Display strings match Go where Go has its own text;
/// the wrapped parser detail differs (Go prints `x509`/`asn1` errors).
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("read private key: {0}")]
    ReadPrivateKey(std::io::Error),
    #[error("read public key: {0}")]
    ReadPublicKey(std::io::Error),
    #[error("decode private key PEM: no PEM block found")]
    PrivateKeyPemNotFound,
    #[error("decode public key PEM: no PEM block found")]
    PublicKeyPemNotFound,
    #[error("parse private key: {0}")]
    ParsePrivateKey(String),
    #[error("parse private key: expected RSA private key")]
    PrivateKeyNotRsa,
    #[error("parse public key: {0}")]
    ParsePublicKey(String),
    #[error("parse public key: expected RSA public key")]
    PublicKeyNotRsa,
    #[error("parse public key: expected RSA public key in certificate")]
    CertificateKeyNotRsa,
    #[error("marshal public key: {0}")]
    MarshalPublicKey(String),
    /// New vs Go, which never checked the pair.
    #[error("jwt key pair mismatch: the public key does not belong to the private key")]
    KeyPairMismatch,
}

/// Wall clock used for `exp`/`nbf` checks unless one is injected.
#[derive(Debug, Clone, Copy)]
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Signs and verifies access/ID tokens and serves the JWKS (Go `jwks.Manager`).
#[derive(Clone)]
pub struct JwksManager {
    alg: String,
    key_id: String,
    private_key: PrivateKey,
    public_key: PublicKey,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for JwksManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwksManager")
            .field("alg", &self.alg)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl JwksManager {
    /// Go `NewManagerWithSources`: a non-empty PEM value wins over its path.
    /// The config loader already trims the PEM values.
    ///
    /// # Errors
    /// See [`KeyError`].
    pub fn from_sources(
        alg: &str,
        private_key_path: &str,
        public_key_path: &str,
        private_key_pem: &str,
        public_key_pem: &str,
    ) -> Result<Self, KeyError> {
        let private_raw = if private_key_pem.is_empty() {
            std::fs::read(Path::new(private_key_path)).map_err(KeyError::ReadPrivateKey)?
        } else {
            private_key_pem.as_bytes().to_vec()
        };
        let public_raw = if public_key_pem.is_empty() {
            std::fs::read(Path::new(public_key_path)).map_err(KeyError::ReadPublicKey)?
        } else {
            public_key_pem.as_bytes().to_vec()
        };
        Self::from_pem(alg, &private_raw, &public_raw)
    }

    /// Loads both keys from PEM bytes.
    ///
    /// # Errors
    /// See [`KeyError`].
    pub fn from_pem(alg: &str, private_pem: &[u8], public_pem: &[u8]) -> Result<Self, KeyError> {
        let private_key = parse_private_key(private_pem)?;
        let public_key = parse_public_key(public_pem)?;
        let key_id = compute_key_id(&public_key)?;
        if private_key.to_public_key() != public_key {
            return Err(KeyError::KeyPairMismatch);
        }
        Ok(Self {
            alg: alg.to_owned(),
            key_id,
            private_key,
            public_key,
            clock: Arc::new(SystemClock),
        })
    }

    /// Replaces the clock used for `exp`/`nbf` checks.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn alg(&self) -> &str {
        &self.alg
    }

    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The header JSON for a signed token: `{"alg","kid","typ"}` sorted.
    fn header_json(&self) -> String {
        let mut out = String::from("{\"alg\":");
        gojson::write_string(&mut out, &self.alg);
        out.push_str(",\"kid\":");
        gojson::write_string(&mut out, &self.key_id);
        out.push_str(",\"typ\":\"JWT\"}");
        out
    }

    fn sign_compact(&self, claims: &JwtClaims) -> Result<String, JwtError> {
        if self.alg != RS256 {
            return Err(JwtError::new(format!(
                "unsupported signing alg: {}",
                self.alg
            )));
        }
        let mut claims_json = String::new();
        gojson::write_object(&mut claims_json, claims.iter());
        let signing_input = format!(
            "{}.{}",
            b64url_encode(self.header_json()),
            b64url_encode(claims_json)
        );
        let digest = Sha256::digest(signing_input.as_bytes());
        let signature = self
            .private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(JwtError::new)?;
        Ok(format!("{signing_input}.{}", b64url_encode(signature)))
    }

    fn verify_compact(&self, token: &str) -> Result<JwtClaims, String> {
        let parts: Vec<&str> = token.split('.').collect();
        let [header_b64, claims_b64, signature_b64] = parts[..] else {
            return Err("token is malformed: token contains an invalid number of segments".into());
        };
        let header_bytes = decode_b64url_go(header_b64.as_bytes())
            .map_err(|e| format!("token is malformed: could not base64 decode header: {e}"))?;
        let header: serde_json::Map<String, Value> = serde_json::from_slice(&header_bytes)
            .map_err(|e| format!("token is malformed: could not JSON decode header: {e}"))?;
        let claims_bytes = decode_b64url_go(claims_b64.as_bytes())
            .map_err(|e| format!("token is malformed: could not base64 decode claim: {e}"))?;
        // Like Go's json.Decoder: the first value counts, trailing data is ignored.
        let claims: JwtClaims = serde_json::Deserializer::from_slice(&claims_bytes)
            .into_iter::<JwtClaims>()
            .next()
            .ok_or_else(|| "EOF".to_owned())
            .and_then(|parsed| parsed.map_err(|e| e.to_string()))
            .map_err(|e| format!("token is malformed: could not JSON decode claim: {e}"))?;

        let Some(alg) = header.get("alg").and_then(Value::as_str) else {
            return Err("token is unverifiable: signing method (alg) is unspecified".into());
        };
        if !is_registered_alg(alg) {
            return Err("token is unverifiable: signing method (alg) is unavailable".into());
        }
        let signature = decode_b64url_go(signature_b64.as_bytes())
            .map_err(|e| format!("token is malformed: could not base64 decode signature: {e}"))?;
        if alg != self.alg {
            return Err(format!(
                "token is unverifiable: error while executing keyfunc: unexpected signing alg: {alg}"
            ));
        }
        if alg != RS256 {
            return Err("token signature is invalid: key is of invalid type".into());
        }
        let digest = Sha256::digest(format!("{header_b64}.{claims_b64}").as_bytes());
        self.public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .map_err(|_| "token signature is invalid: crypto/rsa: verification error".to_owned())?;

        validate_time_claims(&claims, self.clock.now())
            .map_err(|e| format!("token has invalid claims: {e}"))?;
        Ok(claims)
    }
}

/// Signing methods golang-jwt v5 registers.
fn is_registered_alg(alg: &str) -> bool {
    matches!(
        alg,
        "HS256"
            | "HS384"
            | "HS512"
            | "RS256"
            | "RS384"
            | "RS512"
            | "PS256"
            | "PS384"
            | "PS512"
            | "ES256"
            | "ES384"
            | "ES512"
            | "EdDSA"
            | "none"
    )
}

/// golang-jwt `parseNumericDate`: seconds, truncated to whole seconds
/// (floor), as Unix nanoseconds.
fn numeric_date(claims: &JwtClaims, key: &str) -> Result<Option<i128>, String> {
    match claims.get(key) {
        None => Ok(None),
        Some(Value::Number(number)) => {
            let seconds = number
                .as_i64()
                .map(i128::from)
                .or_else(|| number.as_u64().map(i128::from))
                .or_else(|| {
                    #[allow(clippy::cast_possible_truncation)]
                    number.as_f64().map(|f| f.floor() as i128)
                })
                .unwrap_or_default();
            Ok(Some(seconds.saturating_mul(1_000_000_000)))
        }
        Some(_) => Err(format!("invalid type for claim: {key} is invalid")),
    }
}

/// golang-jwt v5 `Validator.Validate` with default options.
fn validate_time_claims(claims: &JwtClaims, now: OffsetDateTime) -> Result<(), String> {
    let now = now.unix_timestamp_nanos();
    let mut errors = Vec::new();
    match numeric_date(claims, "exp") {
        Ok(Some(exp)) if now >= exp => errors.push("token is expired".to_owned()),
        Ok(_) => {}
        Err(error) => errors.push(error),
    }
    match numeric_date(claims, "nbf") {
        Ok(Some(nbf)) if now < nbf => errors.push("token is not valid yet".to_owned()),
        Ok(_) => {}
        Err(error) => errors.push(error),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(", "))
    }
}

impl JwtSigner for JwksManager {
    fn sign(&self, claims: &JwtClaims) -> Result<SignedJwt, JwtError> {
        Ok(SignedJwt {
            token: self.sign_compact(claims)?,
            key_id: self.key_id.clone(),
            alg: self.alg.clone(),
        })
    }
}

impl JwtVerifier for JwksManager {
    fn verify(&self, token: &str) -> Result<JwtClaims, JwtError> {
        self.verify_compact(token).map_err(JwtError::new)
    }
}

impl JwksProvider for JwksManager {
    fn public_jwks(&self) -> Result<Vec<u8>, JwtError> {
        let e_bytes = self.public_key.e_bytes();
        let e = match i64::try_from(be_to_u64(&e_bytes)) {
            Ok(value) if e_bytes.len() <= 8 => encode_int(value),
            _ => b64url_encode(&e_bytes),
        };
        let mut out = String::from("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":");
        gojson::write_string(&mut out, &self.alg);
        out.push_str(",\"kid\":");
        gojson::write_string(&mut out, &self.key_id);
        out.push_str(",\"n\":");
        gojson::write_string(&mut out, &b64url_encode(self.public_key.n_bytes()));
        out.push_str(",\"e\":");
        gojson::write_string(&mut out, &e);
        out.push_str("}]}");
        Ok(out.into_bytes())
    }
}

fn be_to_u64(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0_u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// Go `encodeInt`: minimal big-endian bytes, base64url without padding;
/// zero (and negatives) encode to `""`.
#[must_use]
pub fn encode_int(value: i64) -> String {
    if value <= 0 {
        return String::new();
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    b64url_encode(&bytes[first..])
}

/// SPKI (PKIX) DER of an RSA public key, as Go `x509.MarshalPKIXPublicKey`.
///
/// # Errors
/// Fails only if the key cannot be encoded.
pub fn spki_der(public_key: &PublicKey) -> Result<Vec<u8>, KeyError> {
    public_key
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|e| KeyError::MarshalPublicKey(e.to_string()))
}

/// Go `computeKeyID`: `base64url_nopad(SHA-256(SPKI DER))`.
///
/// # Errors
/// Fails only if the key cannot be encoded.
pub fn compute_key_id(public_key: &PublicKey) -> Result<String, KeyError> {
    Ok(b64url_encode(Sha256::digest(spki_der(public_key)?)))
}

/// Go `parsePrivateKey`: first PEM block, PKCS#1 then PKCS#8 (RSA only).
///
/// # Errors
/// See [`KeyError`].
pub fn parse_private_key(raw: &[u8]) -> Result<PrivateKey, KeyError> {
    let block = pem::decode(raw).ok_or(KeyError::PrivateKeyPemNotFound)?;
    if let Ok(key) = PrivateKey::from_pkcs1_der(&block.bytes) {
        return Ok(key);
    }
    let info = PrivateKeyInfoRef::try_from(block.bytes.as_slice())
        .map_err(|e| KeyError::ParsePrivateKey(e.to_string()))?;
    if info.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
        return Err(KeyError::PrivateKeyNotRsa);
    }
    PrivateKey::try_from(info).map_err(|e| KeyError::ParsePrivateKey(e.to_string()))
}

/// Go `parsePublicKey`: first PEM block, PKIX then an X.509 certificate. A
/// failure reports the PKIX error, as Go does.
///
/// # Errors
/// See [`KeyError`].
pub fn parse_public_key(raw: &[u8]) -> Result<PublicKey, KeyError> {
    let block = pem::decode(raw).ok_or(KeyError::PublicKeyPemNotFound)?;
    let pkix_error = match SubjectPublicKeyInfoRef::try_from(block.bytes.as_slice()) {
        Ok(spki) => {
            if spki.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
                return Err(KeyError::PublicKeyNotRsa);
            }
            return PublicKey::try_from(spki).map_err(|e| KeyError::ParsePublicKey(e.to_string()));
        }
        Err(error) => error,
    };
    let spki = cert::subject_public_key_info(&block.bytes)
        .and_then(|der| SubjectPublicKeyInfoRef::try_from(der).ok())
        .ok_or_else(|| KeyError::ParsePublicKey(pkix_error.to_string()))?;
    if spki.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
        return Err(KeyError::CertificateKeyNotRsa);
    }
    PublicKey::try_from(spki).map_err(|e| KeyError::ParsePublicKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn encode_int_matches_go() {
        for (value, want) in [(65537, "AQAB"), (3, "Aw"), (0, ""), (-1, ""), (256, "AQA")] {
            assert_eq!(encode_int(value), want);
        }
    }

    #[test]
    fn time_claims_follow_golang_jwt() {
        let now = OffsetDateTime::from_unix_timestamp(100).expect("time");
        let claims = |value: Value| value.as_object().expect("object").clone();
        assert_eq!(validate_time_claims(&claims(json!({})), now), Ok(()));
        assert_eq!(
            validate_time_claims(&claims(json!({"exp": 101})), now),
            Ok(())
        );
        // Valid strictly before exp: now == exp is expired.
        assert_eq!(
            validate_time_claims(&claims(json!({"exp": 100})), now),
            Err("token is expired".into())
        );
        assert_eq!(
            validate_time_claims(&claims(json!({"exp": 100.9})), now),
            Err("token is expired".into())
        );
        assert_eq!(
            validate_time_claims(&claims(json!({"nbf": 100})), now),
            Ok(())
        );
        assert_eq!(
            validate_time_claims(&claims(json!({"nbf": 101, "exp": 1})), now),
            Err("token is expired, token is not valid yet".into())
        );
        assert_eq!(
            validate_time_claims(&claims(json!({"exp": "x"})), now),
            Err("invalid type for claim: exp is invalid".into())
        );
        // iat is not checked by default.
        assert_eq!(
            validate_time_claims(&claims(json!({"iat": 999})), now),
            Ok(())
        );
    }
}
