use async_trait::async_trait;

use super::RepoResult;

/// Shared sliding-window request budget for OTP actions.
#[async_trait]
pub trait OtpRateLimiter: Send + Sync {
    /// Records the request if admitted. On rejection, returns the truncated
    /// number of seconds until the next slot, with a minimum of one second.
    async fn check_and_record(&self, key: &str) -> RepoResult<Option<i64>>;
}
