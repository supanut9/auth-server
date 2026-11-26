//! Identity and OTP errors (`internal/application/identity/errors.go`).
//!
//! OTP verify failures reach auth-ui as `error_description`, so the Display
//! strings must stay identical to Go.

use crate::flow::FlowError;
use crate::ports::{RandomError, RepoError};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("provider email verification required")]
    ProviderEmailVerificationRequired,
    #[error("provider login invalid stage")]
    ProviderLoginInvalidStage,
    #[error("otp challenge expired")]
    OtpChallengeExpired,
    #[error("otp challenge invalid")]
    OtpChallengeInvalid,
    #[error("otp challenge not found")]
    OtpChallengeNotFound,
    #[error("otp challenge invalid stage")]
    OtpChallengeInvalidStage,
    #[error("otp challenge throttled")]
    OtpChallengeThrottled,
    #[error("otp challenge too many attempts")]
    OtpChallengeTooManyAttempts,
    #[error("otp challenge too many resends")]
    OtpChallengeTooManyResends,
    /// OTP start with a blank email.
    #[error("otp email required")]
    OtpEmailRequired,
    /// OTP verify with an empty code (Go `hashOTPCode`).
    #[error("empty otp code")]
    EmptyOtpCode,
    #[error(transparent)]
    Flow(#[from] FlowError),
    #[error(transparent)]
    Repo(#[from] RepoError),
    #[error(transparent)]
    Random(#[from] RandomError),
}

#[cfg(test)]
mod tests {
    use super::IdentityError as E;

    #[test]
    fn messages_match_go() {
        let cases = [
            (
                E::ProviderEmailVerificationRequired,
                "provider email verification required",
            ),
            (E::ProviderLoginInvalidStage, "provider login invalid stage"),
            (E::OtpChallengeExpired, "otp challenge expired"),
            (E::OtpChallengeInvalid, "otp challenge invalid"),
            (E::OtpChallengeNotFound, "otp challenge not found"),
            (E::OtpChallengeInvalidStage, "otp challenge invalid stage"),
            (E::OtpChallengeThrottled, "otp challenge throttled"),
            (
                E::OtpChallengeTooManyAttempts,
                "otp challenge too many attempts",
            ),
            (
                E::OtpChallengeTooManyResends,
                "otp challenge too many resends",
            ),
            (E::OtpEmailRequired, "otp email required"),
            (E::EmptyOtpCode, "empty otp code"),
        ];
        for (error, want) in cases {
            assert_eq!(error.to_string(), want);
        }
    }
}
