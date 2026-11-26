use time::OffsetDateTime;

use super::{OtpChallengeId, ZERO_TIME};

/// `otp_challenges` row. Only the hash of the code is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpChallenge {
    pub id: OtpChallengeId,
    pub authorization_request_id: Option<String>,
    pub email: String,
    /// `login` unless the caller supplied another purpose.
    pub purpose: String,
    pub code_hash: String,
    pub attempt_count: i32,
    pub resend_count: i32,
    pub expires_at: OffsetDateTime,
    pub verified_at: Option<OffsetDateTime>,
    pub last_sent_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

impl Default for OtpChallenge {
    fn default() -> Self {
        Self {
            id: OtpChallengeId::default(),
            authorization_request_id: None,
            email: String::new(),
            purpose: String::new(),
            code_hash: String::new(),
            attempt_count: 0,
            resend_count: 0,
            expires_at: ZERO_TIME,
            verified_at: None,
            last_sent_at: ZERO_TIME,
            created_at: ZERO_TIME,
        }
    }
}
