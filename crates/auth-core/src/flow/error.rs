//! Flow service errors (`internal/application/flow/errors.go`).

use crate::ports::{RandomError, RepoError};

/// Flow error messages, including Go-compatible sentinels.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("authorization request expired")]
    AuthorizationRequestExpired,
    #[error("authorization request invalid stage")]
    AuthorizationRequestInvalidStage,
    #[error("consent required")]
    ConsentRequired,
    /// Also returned for an empty code value (Go `hashSecret`).
    #[error("authorization code expired")]
    AuthorizationCodeExpired,
    #[error("authorization code already consumed")]
    AuthorizationCodeAlreadyConsumed,
    #[error("authorization code client mismatch")]
    AuthorizationCodeClientMismatch,
    #[error("authorization code redirect uri mismatch")]
    AuthorizationCodeRedirectMismatch,
    #[error("pkce validation failed")]
    PkceValidationFailed,
    #[error(transparent)]
    Repo(#[from] RepoError),
    #[error(transparent)]
    Random(#[from] RandomError),
}

#[cfg(test)]
mod tests {
    use super::FlowError as E;

    #[test]
    fn messages_match_go() {
        let cases = [
            (
                E::AuthorizationRequestExpired,
                "authorization request expired",
            ),
            (
                E::AuthorizationRequestInvalidStage,
                "authorization request invalid stage",
            ),
            (E::ConsentRequired, "consent required"),
            (E::AuthorizationCodeExpired, "authorization code expired"),
            (
                E::AuthorizationCodeAlreadyConsumed,
                "authorization code already consumed",
            ),
            (
                E::AuthorizationCodeClientMismatch,
                "authorization code client mismatch",
            ),
            (
                E::AuthorizationCodeRedirectMismatch,
                "authorization code redirect uri mismatch",
            ),
            (
                E::Repo(crate::ports::RepoError::NotFound),
                "record not found",
            ),
        ];
        for (error, want) in cases {
            assert_eq!(error.to_string(), want);
        }
    }
}
