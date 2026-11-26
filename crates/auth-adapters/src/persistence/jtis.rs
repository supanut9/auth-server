//! `signed_state_jtis` repository (Go `persistence.SignedStateJTIRepository`).
//!
//! One row per consumed provider-state envelope; the primary key is the JTI,
//! so a replay is an insert that changes nothing.

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::ports::{Clock, RepoError, RepoResult, SignedStateJtiRepository};
use sqlx::PgPool;
use time::{OffsetDateTime, UtcOffset};

use super::common::map_err;

/// Postgres-backed [`SignedStateJtiRepository`].
///
/// Takes no ID generator: the JTI is the key (Go's constructor took only the
/// DB and a clock).
pub struct PgSignedStateJtiRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
}

impl PgSignedStateJtiRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>) -> Self {
        Self { pool, clock }
    }
}

#[async_trait]
impl SignedStateJtiRepository for PgSignedStateJtiRepository {
    /// `INSERT ... ON CONFLICT DO NOTHING`; zero rows affected is a replay
    /// ([`RepoError::Conflict`], Go `oauth.ErrJTIExists`). An empty JTI is
    /// rejected before touching the database, with Go's message.
    async fn insert(&self, jti: &str, expires_at: OffsetDateTime) -> RepoResult<()> {
        if jti.is_empty() {
            return Err(RepoError::other("signed_state_jti: jti is required"));
        }
        let now = self.clock.now().to_offset(UtcOffset::UTC);
        let result = sqlx::query!(
            r#"INSERT INTO signed_state_jtis (jti, expires_at, created_at)
               VALUES ($1, $2, $3)
               ON CONFLICT DO NOTHING"#,
            jti,
            expires_at.to_offset(UtcOffset::UTC),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if result.rows_affected() == 0 {
            return Err(RepoError::Conflict);
        }
        Ok(())
    }

    async fn prune_expired(&self, now: OffsetDateTime) -> RepoResult<()> {
        sqlx::query!(
            "DELETE FROM signed_state_jtis WHERE expires_at < $1",
            now.to_offset(UtcOffset::UTC),
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-05-16 12:00:00.123456 UTC);

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            NOW
        }
    }

    fn repo(pool: PgPool) -> PgSignedStateJtiRepository {
        PgSignedStateJtiRepository::new(pool, Arc::new(FixedClock))
    }

    async fn stored(pool: &PgPool) -> Vec<(String, OffsetDateTime, OffsetDateTime)> {
        sqlx::query_as("SELECT jti, expires_at, created_at FROM signed_state_jtis ORDER BY jti")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn insert_records_jti_with_clock_created_at(pool: PgPool) {
        let repo = repo(pool);
        let expires = datetime!(2026-05-16 21:10:00 +09:00);
        repo.insert("jti-1", expires).await.unwrap();
        assert_eq!(
            stored(&repo.pool).await,
            [("jti-1".to_owned(), expires, NOW)]
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn replay_is_conflict(pool: PgPool) {
        let repo = repo(pool);
        let expires = datetime!(2026-05-16 12:10:00 UTC);
        repo.insert("jti-1", expires).await.unwrap();
        let err = repo.insert("jti-1", expires).await.unwrap_err();
        assert!(err.is_conflict(), "{err:?}");
        assert_eq!(stored(&repo.pool).await.len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn empty_jti_is_rejected(pool: PgPool) {
        let err = repo(pool).insert("", NOW).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)));
        assert_eq!(err.to_string(), "signed_state_jti: jti is required");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn prune_deletes_only_strictly_expired(pool: PgPool) {
        let repo = repo(pool);
        repo.insert("past", datetime!(2026-05-16 11:00:00 UTC))
            .await
            .unwrap();
        repo.insert("edge", NOW).await.unwrap();
        repo.insert("future", datetime!(2026-05-16 13:00:00 UTC))
            .await
            .unwrap();

        repo.prune_expired(NOW).await.unwrap();
        let left: Vec<String> = stored(&repo.pool)
            .await
            .into_iter()
            .map(|row| row.0)
            .collect();
        assert_eq!(left, ["edge", "future"]);

        // Idempotent.
        repo.prune_expired(NOW).await.unwrap();
        assert_eq!(stored(&repo.pool).await.len(), 2);
        // A pruned JTI can be recorded again.
        repo.insert("past", datetime!(2026-05-16 11:00:00 UTC))
            .await
            .unwrap();
    }
}
