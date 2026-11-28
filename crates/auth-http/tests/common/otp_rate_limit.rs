use std::{collections::HashMap, sync::Mutex};

use auth_core::ports::{OtpRateLimiter, RepoResult};

/// Request budget for the short HTTP unit tests.
#[derive(Default)]
pub struct TestOtpRateLimiter(Mutex<HashMap<String, u8>>);

#[async_trait::async_trait]
impl OtpRateLimiter for TestOtpRateLimiter {
    async fn check_and_record(&self, key: &str) -> RepoResult<Option<i64>> {
        let mut hits = self.0.lock().unwrap();
        let count = hits.entry(key.to_owned()).or_default();
        if *count >= 20 {
            return Ok(Some(60));
        }
        *count += 1;
        Ok(None)
    }
}
