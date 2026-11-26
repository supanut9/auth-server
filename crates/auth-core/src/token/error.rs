//! Token service errors (`internal/application/token/errors.go`).

use crate::ports::{JwtError, RandomError, RepoError};

/// Display strings match the Go sentinels verbatim.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("refresh token expired")]
    RefreshTokenExpired,
    #[error("refresh token revoked")]
    RefreshTokenRevoked,
    #[error("refresh token reuse detected")]
    RefreshTokenReuseDetected,
    #[error("refresh token client mismatch")]
    RefreshTokenClientMismatch,
    #[error("refresh token chain inactive")]
    RefreshTokenChainInactive,
    /// The chain's SSO session is revoked, inactive or expired (AUTH-019).
    #[error("refresh token session inactive")]
    RefreshTokenSessionInactive,
    #[error("hash opaque token: empty token")]
    EmptyToken,
    #[error("generate opaque token: {0}")]
    GenerateOpaqueToken(RandomError),
    #[error(transparent)]
    Signing(#[from] JwtError),
    #[error(transparent)]
    Repo(#[from] RepoError),
}

#[cfg(test)]
mod tests {
    use super::TokenError as E;
    use crate::ports::RandomError;

    #[test]
    fn messages_match_go() {
        let cases = [
            (E::RefreshTokenExpired, "refresh token expired"),
            (E::RefreshTokenRevoked, "refresh token revoked"),
            (E::RefreshTokenReuseDetected, "refresh token reuse detected"),
            (
                E::RefreshTokenClientMismatch,
                "refresh token client mismatch",
            ),
            (E::RefreshTokenChainInactive, "refresh token chain inactive"),
            (
                E::RefreshTokenSessionInactive,
                "refresh token session inactive",
            ),
            (E::EmptyToken, "hash opaque token: empty token"),
            (
                E::GenerateOpaqueToken(RandomError::new("entropy unavailable")),
                "generate opaque token: entropy unavailable",
            ),
        ];
        for (error, want) in cases {
            assert_eq!(error.to_string(), want);
        }
    }
}
