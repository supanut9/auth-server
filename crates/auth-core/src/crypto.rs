//! Hashing, random token encoding and constant-time helpers.
//!
//! Every stored secret digest in the Go service is
//! `base64url_nopad(SHA-256(value))`, unsalted: authorization `code_hash`,
//! refresh `token_hash`, OTP `code_hash` and the digest part of a
//! `sha256:`-prefixed client secret. Random values are raw bytes from a
//! [`RandomSource`] encoded as base64url without padding.

pub mod gojson;

use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::ports::{OtpCodeGenerator, RandomError, RandomSource};

/// Bytes behind an authorization code or refresh token (43 encoded chars).
pub const OPAQUE_TOKEN_BYTES: usize = 32;
/// Bytes behind an envelope `jti` (22 encoded chars).
pub const JTI_BYTES: usize = 16;
/// Bytes behind an OTP code (8 encoded chars from `[A-Za-z0-9_-]`).
pub const OTP_CODE_BYTES: usize = 6;
/// Prefix of a hashed client secret in `oauth_clients.client_secret_hash`.
pub const CLIENT_SECRET_HASH_PREFIX: &str = "sha256:";

/// `base64.RawURLEncoding.EncodeToString`.
#[must_use]
pub fn b64url_encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `base64url_nopad(SHA-256(value))`.
#[must_use]
pub fn sha256_b64url(value: impl AsRef<[u8]>) -> String {
    b64url_encode(Sha256::digest(value.as_ref()))
}

/// Digest of a non-empty opaque value (code, refresh token, OTP code).
///
/// Returns `None` for an empty value. Each Go service rejects that with its
/// own error (`FlowError::AuthorizationCodeExpired`,
/// `TokenError::EmptyToken`, `IdentityError::EmptyOtpCode`, or the HTTP
/// layer's `empty token`), so the caller maps `None`.
#[must_use]
pub fn hash_opaque(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| sha256_b64url(value))
}

/// `len` random bytes from `random`, base64url-encoded without padding.
///
/// # Errors
/// Fails when the random source fails.
pub fn random_b64url(random: &dyn RandomSource, len: usize) -> Result<String, RandomError> {
    let mut raw = vec![0_u8; len];
    random.fill_bytes(&mut raw)?;
    Ok(b64url_encode(raw))
}

/// A freshly generated opaque secret and its stored digest.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueSecret {
    /// The value handed to the client (43 chars).
    pub value: String,
    /// `sha256_b64url(value)`, the only form that is stored.
    pub hash: String,
}

impl fmt::Debug for OpaqueSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueSecret")
            .field("value", &"[redacted]")
            .field("hash", &self.hash)
            .finish()
    }
}

/// Authorization code or refresh token: 32 random bytes plus their digest
/// (Go `newOpaqueSecret` / `newOpaqueToken`).
///
/// # Errors
/// Fails when the random source fails.
pub fn new_opaque_secret(random: &dyn RandomSource) -> Result<OpaqueSecret, RandomError> {
    let value = random_b64url(random, OPAQUE_TOKEN_BYTES)?;
    let hash = sha256_b64url(&value);
    Ok(OpaqueSecret { value, hash })
}

/// Envelope `jti`: 16 random bytes (Go `randomJTI`).
///
/// # Errors
/// Fails when the random source fails.
pub fn new_jti(random: &dyn RandomSource) -> Result<String, RandomError> {
    random_b64url(random, JTI_BYTES)
}

/// OTP code: 6 random bytes as 8 base64url characters (Go
/// `randomOTPCodeGenerator`). Not digits only.
///
/// # Errors
/// Fails when the random source fails.
pub fn new_otp_code(random: &dyn RandomSource) -> Result<String, RandomError> {
    random_b64url(random, OTP_CODE_BYTES)
}

/// Production [`OtpCodeGenerator`] backed by a [`RandomSource`].
#[derive(Clone)]
pub struct RandomOtpCodeGenerator {
    random: Arc<dyn RandomSource>,
}

impl RandomOtpCodeGenerator {
    #[must_use]
    pub fn new(random: Arc<dyn RandomSource>) -> Self {
        Self { random }
    }
}

impl fmt::Debug for RandomOtpCodeGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RandomOtpCodeGenerator")
            .finish_non_exhaustive()
    }
}

impl OtpCodeGenerator for RandomOtpCodeGenerator {
    fn new_code(&self) -> Result<String, RandomError> {
        new_otp_code(self.random.as_ref())
    }
}

/// Operating-system CSPRNG (Go `crypto/rand`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        use rand::TryRng as _;
        rand::rngs::SysRng
            .try_fill_bytes(dest)
            .map_err(RandomError::new)
    }
}

/// Constant-time byte equality (Go `subtle.ConstantTimeCompare(a, b) == 1`
/// and `hmac.Equal`). Different lengths compare unequal.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// Stored form of a client secret, as written by Go `cmd/devseed`:
/// `"sha256:" + base64url_nopad(SHA-256(secret))`.
#[must_use]
pub fn client_secret_storage(secret: &str) -> String {
    format!("{CLIENT_SECRET_HASH_PREFIX}{}", sha256_b64url(secret))
}

/// Confidential-client secret check (Go `router.go matchSecret`).
///
/// Empty stored or provided value never matches. A stored value with the
/// case-sensitive `sha256:` prefix is compared, in constant time, against the
/// digest text of `provided`; anything else is a constant-time plaintext
/// comparison.
#[must_use]
pub fn match_client_secret(stored: &str, provided: &str) -> bool {
    if stored.is_empty() || provided.is_empty() {
        return false;
    }
    match stored.strip_prefix(CLIENT_SECRET_HASH_PREFIX) {
        Some(digest) => constant_time_eq(digest.as_bytes(), sha256_b64url(provided).as_bytes()),
        None => constant_time_eq(stored.as_bytes(), provided.as_bytes()),
    }
}

/// Go `base64.CorruptInputError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("illegal base64 data at input byte {offset}")]
pub struct Base64Error {
    /// Byte offset Go reports.
    pub offset: usize,
}

const INVALID: u8 = 0xff;

const URL_DECODE_MAP: [u8; 256] = {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut map = [INVALID; 256];
    let mut i = 0;
    while i < alphabet.len() {
        map[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    map
};

/// `base64.RawURLEncoding.DecodeString`, including Go's quirks: `\r` and
/// `\n` are skipped anywhere, non-zero trailing bits are accepted, and the
/// error offset is the one Go reports.
///
/// # Errors
/// Returns the offset of the first byte Go rejects.
pub fn decode_b64url_go(input: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut si = 0;
    loop {
        // One Go `decodeQuantum`.
        let mut quantum = [0_u8; 4];
        let mut filled = 0;
        while filled < 4 {
            if si == input.len() {
                if filled == 0 {
                    return Ok(out);
                }
                if filled == 1 {
                    return Err(Base64Error { offset: si - 1 });
                }
                break;
            }
            let byte = input[si];
            si += 1;
            let value = URL_DECODE_MAP[usize::from(byte)];
            if value != INVALID {
                quantum[filled] = value;
                filled += 1;
                continue;
            }
            if byte == b'\n' || byte == b'\r' {
                continue;
            }
            return Err(Base64Error { offset: si - 1 });
        }
        let val = (u32::from(quantum[0]) << 18)
            | (u32::from(quantum[1]) << 12)
            | (u32::from(quantum[2]) << 6)
            | u32::from(quantum[3]);
        let bytes = val.to_be_bytes();
        out.extend_from_slice(&bytes[1..filled]);
        if filled < 4 {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct Fixed(Mutex<Vec<u8>>);

    impl RandomSource for Fixed {
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError> {
            let mut bytes = self.0.lock().expect("lock");
            let taken: Vec<u8> = bytes.drain(..dest.len()).collect();
            dest.copy_from_slice(&taken);
            Ok(())
        }
    }

    #[test]
    fn random_lengths() {
        let random = Fixed(Mutex::new(vec![0xab; 64]));
        assert_eq!(new_opaque_secret(&random).expect("secret").value.len(), 43);
        assert_eq!(new_jti(&random).expect("jti").len(), 22);
        assert_eq!(new_otp_code(&random).expect("otp").len(), 8);
        assert_eq!(
            SystemRandom
                .fill_bytes(&mut [0; 8])
                .map_err(|e| e.to_string()),
            Ok(())
        );
    }

    #[test]
    fn opaque_secret_debug_redacts_value() {
        let secret = OpaqueSecret {
            value: "top".into(),
            hash: "h".into(),
        };
        assert!(!format!("{secret:?}").contains("top"));
    }

    #[test]
    fn go_base64_decoder() {
        let ok: &[(&str, &[u8])] = &[
            ("", b""),
            ("QQ", b"A"),
            ("QUI", b"AB"),
            ("QUJD", b"ABC"),
            ("QUJDRA", b"ABCD"),
            ("QU\r\nJD", b"ABC"),
            ("QUJD\n", b"ABC"),
            // Trailing bits are not checked (non-strict).
            ("QR", b"A"),
            ("_-8", &[0xff, 0xef]),
        ];
        for (input, want) in ok {
            assert_eq!(
                decode_b64url_go(input.as_bytes()).as_deref(),
                Ok(*want),
                "{input:?}"
            );
        }
        let bad: &[(&str, usize)] = &[
            ("@@@", 0),
            ("Q", 0),
            ("QUJDR", 4),
            ("QUJD=", 4),
            ("QQ==", 2),
            ("QUJD+", 4),
            ("QU/D", 2),
        ];
        for (input, offset) in bad {
            assert_eq!(
                decode_b64url_go(input.as_bytes()),
                Err(Base64Error { offset: *offset }),
                "{input:?}"
            );
        }
        assert_eq!(
            Base64Error { offset: 3 }.to_string(),
            "illegal base64 data at input byte 3"
        );
    }

    #[test]
    fn constant_time_eq_lengths() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
