//! Shared 20-hit, 60-second sliding window for OTP actions.

use async_trait::async_trait;
use auth_core::ports::{OtpRateLimiter, RepoResult};
use sqlx::PgPool;

use super::common::map_err;

pub struct PgOtpRateLimiter {
    pool: PgPool,
}

impl PgOtpRateLimiter {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OtpRateLimiter for PgOtpRateLimiter {
    async fn check_and_record(&self, key: &str) -> RepoResult<Option<i64>> {
        let mut tx = self
            .pool
            .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await
            .map_err(map_err)?;
        // Serialize a key across instances. The next statement takes a fresh
        // snapshot and uses the database clock after the lock wait.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;

        let retry_after = sqlx::query_scalar!(
            r#"WITH active AS (
                 SELECT count(*) AS hits, min(hit_at) AS oldest
                 FROM otp_rate_limit_hits
                 WHERE key = $1 AND hit_at >= statement_timestamp() - interval '60 seconds'
               ), recorded AS (
                 INSERT INTO otp_rate_limit_hits (key, hit_at)
                 SELECT $1, statement_timestamp() FROM active WHERE hits < 20
                 RETURNING 1
               )
               SELECT greatest(1, floor(extract(epoch FROM
                   (oldest + interval '60 seconds' - statement_timestamp())))::bigint) AS "retry_after!"
               FROM active
               WHERE NOT EXISTS (SELECT 1 FROM recorded)"#,
            key,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(retry_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn concurrent_requests_share_the_budget(pool: PgPool) {
        let key = "otp:/v1/auth/otp/start:192.0.2.1";
        let requests: Vec<_> = (0..24)
            .map(|_| {
                let limiter = PgOtpRateLimiter::new(pool.clone());
                tokio::spawn(async move { limiter.check_and_record(key).await.unwrap() })
            })
            .collect();
        let mut allowed = 0;
        for request in requests {
            match request.await.unwrap() {
                None => allowed += 1,
                Some(seconds) => assert!((1..=60).contains(&seconds)),
            }
        }
        assert_eq!(allowed, 20);
        let hits: i64 = sqlx::query_scalar("SELECT count(*) FROM otp_rate_limit_hits")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(hits, 20);

        let limiter = PgOtpRateLimiter::new(pool.clone());
        assert_eq!(
            limiter
                .check_and_record("otp:/v1/auth/otp/start:192.0.2.2")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            limiter
                .check_and_record("otp:/v1/auth/otp/verify:192.0.2.1")
                .await
                .unwrap(),
            None
        );

        sqlx::query(
            "UPDATE otp_rate_limit_hits SET hit_at = now() - interval '61 seconds' WHERE key = $1",
        )
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(limiter.check_and_record(key).await.unwrap(), None);
    }
}
