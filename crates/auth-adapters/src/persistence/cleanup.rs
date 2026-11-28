//! PostgreSQL retention cleanup for short-lived authentication records.

use async_trait::async_trait;
use auth_core::ports::{CleanupCounts, CleanupRepository, RepoResult};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use super::common::map_err;

pub struct PgCleanupRepository {
    pool: PgPool,
}

impl PgCleanupRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CleanupRepository for PgCleanupRepository {
    async fn delete_expired(&self, now: OffsetDateTime) -> RepoResult<CleanupCounts> {
        sqlx::query_as!(
            CleanupCounts,
            r#"WITH jtis AS (
                 DELETE FROM signed_state_jtis WHERE expires_at < $1 RETURNING 1
               ), codes AS (
                 DELETE FROM authorization_codes WHERE expires_at < $2 RETURNING 1
               ), challenges AS (
                 DELETE FROM otp_challenges WHERE expires_at < $2 RETURNING 1
               ), hits AS (
                 DELETE FROM otp_rate_limit_hits WHERE hit_at < $3 RETURNING 1
               )
               SELECT (SELECT count(*) FROM jtis) AS "signed_state_jtis!",
                      (SELECT count(*) FROM codes) AS "authorization_codes!",
                      (SELECT count(*) FROM challenges) AS "otp_challenges!",
                      (SELECT count(*) FROM hits) AS "otp_rate_limit_hits!""#,
            now,
            now - Duration::DAY,
            now - Duration::HOUR,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)
    }
}

#[cfg(test)]
mod tests {
    use crate::persistence::chains::test_support::{T0, insert_account, insert_client, uid};

    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn deletes_only_rows_past_retention_cutoffs(pool: PgPool) {
        let account = uid(1);
        insert_account(&pool, &account, "cleanup@example.test").await;
        insert_client(&pool, &uid(2), "cleanup-web", "Cleanup").await;

        for (id, offset) in [
            (10, -Duration::SECOND),
            (11, Duration::ZERO),
            (12, Duration::SECOND),
        ] {
            let row_id = uid(id);
            let jti_expiry = T0 + offset;
            let code_expiry = T0 - Duration::DAY + offset;
            let hit_at = T0 - Duration::HOUR + offset;
            sqlx::query(
                "INSERT INTO signed_state_jtis (jti, expires_at, created_at) VALUES ($1, $2, $3)",
            )
            .bind(&row_id)
            .bind(jti_expiry)
            .bind(T0 - Duration::HOUR)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO authorization_codes
                 (id, code_hash, account_id, client_id, redirect_uri, granted_scopes, auth_time, expires_at, created_at)
                 VALUES ($1::uuid, $2, $3::uuid, 'cleanup-web', 'https://example.test/cb', 'openid', $4, $5, $4)",
            )
            .bind(&row_id)
            .bind(&row_id)
            .bind(&account)
            .bind(T0 - Duration::days(2))
            .bind(code_expiry)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO otp_challenges (id, email, purpose, code_hash, expires_at, created_at, last_sent_at)
                 VALUES ($1::uuid, 'cleanup@example.test', 'login', 'code-hash', $2, $3, $3)",
            )
            .bind(&row_id)
            .bind(code_expiry)
            .bind(T0 - Duration::days(2))
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("INSERT INTO otp_rate_limit_hits (key, hit_at) VALUES ($1, $2)")
                .bind(&row_id)
                .bind(hit_at)
                .execute(&pool)
                .await
                .unwrap();
        }

        let repo = PgCleanupRepository::new(pool);
        assert_eq!(
            repo.delete_expired(T0).await.unwrap(),
            CleanupCounts {
                signed_state_jtis: 1,
                authorization_codes: 1,
                otp_challenges: 1,
                otp_rate_limit_hits: 1,
            }
        );
        assert_eq!(
            repo.delete_expired(T0).await.unwrap(),
            CleanupCounts::default()
        );
        assert_eq!(
            repo.delete_expired(T0 + Duration::seconds(2))
                .await
                .unwrap(),
            CleanupCounts {
                signed_state_jtis: 2,
                authorization_codes: 2,
                otp_challenges: 2,
                otp_rate_limit_hits: 2,
            }
        );
    }
}
