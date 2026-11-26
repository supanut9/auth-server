use time::OffsetDateTime;

use super::RandomError;

/// Wall clock (`port.Clock`). Implementations return UTC.
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

/// Entity ID source (`port.IDGenerator`). Production yields UUIDv7 strings.
///
/// Infallible, unlike Go: Rust UUIDv7 generation cannot fail.
pub trait IdGenerator: Send + Sync {
    fn new_id(&self) -> String;
}

/// Cryptographically secure random bytes for codes, opaque tokens and JTIs.
pub trait RandomSource: Send + Sync {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RandomError>;
}

/// OTP code source (`port.OTPCodeGenerator`). Production: 6 random bytes as
/// 8 base64url characters.
pub trait OtpCodeGenerator: Send + Sync {
    fn new_code(&self) -> Result<String, RandomError>;
}
