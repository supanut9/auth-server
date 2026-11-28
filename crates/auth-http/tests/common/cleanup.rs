use auth_core::ports::{CleanupCounts, CleanupRepository, RepoResult};
use time::OffsetDateTime;

pub struct TestCleanup;

#[async_trait::async_trait]
impl CleanupRepository for TestCleanup {
    async fn delete_expired(&self, _now: OffsetDateTime) -> RepoResult<CleanupCounts> {
        Ok(CleanupCounts::default())
    }
}
