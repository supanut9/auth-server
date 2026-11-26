//! `otp_challenges` repository
//! (`internal/adapter/out/persistence/otp_challenge_repository.go`).
//!
//! Go's `FindLatestByRequestAndEmail` (an alias of the active finder) and
//! `RevokeByRequestID` are not on the Rust port and were never called.

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{OtpChallenge, OtpChallengeId, is_zero_time};
use auth_core::ports::{Clock, IdGenerator, OtpChallengeRepository, RepoResult};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::common::map_err;
use super::common::{now_utc, parse_uuid};

/// Postgres-backed [`OtpChallengeRepository`].
#[derive(Clone)]
pub struct PgOtpChallengeRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgOtpChallengeRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

struct OtpChallengeRow {
    id: Uuid,
    authorization_request_id: Option<Uuid>,
    email: String,
    purpose: String,
    code_hash: String,
    attempt_count: i32,
    resend_count: i32,
    expires_at: OffsetDateTime,
    verified_at: Option<OffsetDateTime>,
    last_sent_at: OffsetDateTime,
    created_at: OffsetDateTime,
}

impl From<OtpChallengeRow> for OtpChallenge {
    fn from(row: OtpChallengeRow) -> Self {
        Self {
            id: OtpChallengeId::new(row.id.to_string()),
            authorization_request_id: row.authorization_request_id.map(|id| id.to_string()),
            email: row.email,
            purpose: row.purpose,
            code_hash: row.code_hash,
            attempt_count: row.attempt_count,
            resend_count: row.resend_count,
            expires_at: row.expires_at,
            verified_at: row.verified_at,
            last_sent_at: row.last_sent_at,
            created_at: row.created_at,
        }
    }
}

fn parse_request_id(challenge: &OtpChallenge) -> RepoResult<Option<Uuid>> {
    challenge
        .authorization_request_id
        .as_deref()
        .map(parse_uuid)
        .transpose()
}

#[async_trait]
impl OtpChallengeRepository for PgOtpChallengeRepository {
    /// Zero `created_at`/`last_sent_at` default to now. `purpose` is stored
    /// as given (Go's repository did not default it either).
    async fn create(&self, mut challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        let now = now_utc(&*self.clock);
        if challenge.id.is_empty() {
            challenge.id = OtpChallengeId::new(self.ids.new_id());
        }
        if is_zero_time(challenge.created_at) {
            challenge.created_at = now;
        }
        if is_zero_time(challenge.last_sent_at) {
            challenge.last_sent_at = now;
        }

        let id = parse_uuid(challenge.id.as_str())?;
        let request_id = parse_request_id(&challenge)?;
        sqlx::query!(
            r#"INSERT INTO otp_challenges
                (id, authorization_request_id, email, purpose, code_hash, attempt_count,
                 resend_count, expires_at, verified_at, last_sent_at, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
            id,
            request_id,
            challenge.email,
            challenge.purpose,
            challenge.code_hash,
            challenge.attempt_count,
            challenge.resend_count,
            challenge.expires_at,
            challenge.verified_at,
            challenge.last_sent_at,
            challenge.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(challenge)
    }

    /// Newest unverified challenge for the request and email, expired or not
    /// (`ORDER BY created_at DESC` plus GORM `First`'s `id` tiebreak).
    async fn find_active_by_request_and_email(
        &self,
        request_id: &str,
        email: &str,
    ) -> RepoResult<OtpChallenge> {
        let request_id = parse_uuid(request_id)?;
        sqlx::query_as!(
            OtpChallengeRow,
            r#"SELECT id, authorization_request_id, email, purpose, code_hash, attempt_count,
                      resend_count, expires_at, verified_at, last_sent_at, created_at
               FROM otp_challenges
               WHERE authorization_request_id = $1 AND email = $2 AND verified_at IS NULL
               ORDER BY created_at DESC, id LIMIT 1"#,
            request_id,
            email,
        )
        .fetch_one(&self.pool)
        .await
        .map(OtpChallenge::from)
        .map_err(map_err)
    }

    async fn find_by_id(&self, id: &OtpChallengeId) -> RepoResult<OtpChallenge> {
        let id = parse_uuid(id.as_str())?;
        sqlx::query_as!(
            OtpChallengeRow,
            r#"SELECT id, authorization_request_id, email, purpose, code_hash, attempt_count,
                      resend_count, expires_at, verified_at, last_sent_at, created_at
               FROM otp_challenges WHERE id = $1 ORDER BY id LIMIT 1"#,
            id,
        )
        .fetch_one(&self.pool)
        .await
        .map(OtpChallenge::from)
        .map_err(map_err)
    }

    /// GORM `Save`: update every column by ID; when no row matched, insert it
    /// with `ON CONFLICT (id) DO UPDATE` and a zero `created_at` set to now.
    async fn update(&self, mut challenge: OtpChallenge) -> RepoResult<OtpChallenge> {
        let id = parse_uuid(challenge.id.as_str())?;
        let request_id = parse_request_id(&challenge)?;
        let updated = sqlx::query!(
            r#"UPDATE otp_challenges
               SET authorization_request_id = $2, email = $3, purpose = $4, code_hash = $5,
                   attempt_count = $6, resend_count = $7, expires_at = $8, verified_at = $9,
                   last_sent_at = $10, created_at = $11
               WHERE id = $1"#,
            id,
            request_id,
            challenge.email,
            challenge.purpose,
            challenge.code_hash,
            challenge.attempt_count,
            challenge.resend_count,
            challenge.expires_at,
            challenge.verified_at,
            challenge.last_sent_at,
            challenge.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if updated.rows_affected() > 0 {
            return Ok(challenge);
        }

        if is_zero_time(challenge.created_at) {
            challenge.created_at = now_utc(&*self.clock);
        }
        sqlx::query!(
            r#"INSERT INTO otp_challenges
                (id, authorization_request_id, email, purpose, code_hash, attempt_count,
                 resend_count, expires_at, verified_at, last_sent_at, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               ON CONFLICT (id) DO UPDATE SET
                   authorization_request_id = EXCLUDED.authorization_request_id,
                   email = EXCLUDED.email,
                   purpose = EXCLUDED.purpose,
                   code_hash = EXCLUDED.code_hash,
                   attempt_count = EXCLUDED.attempt_count,
                   resend_count = EXCLUDED.resend_count,
                   expires_at = EXCLUDED.expires_at,
                   verified_at = EXCLUDED.verified_at,
                   last_sent_at = EXCLUDED.last_sent_at"#,
            id,
            request_id,
            challenge.email,
            challenge.purpose,
            challenge.code_hash,
            challenge.attempt_count,
            challenge.resend_count,
            challenge.expires_at,
            challenge.verified_at,
            challenge.last_sent_at,
            challenge.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(challenge)
    }

    /// `email = ? AND verified_at IS NULL AND expires_at > now`, newest first.
    async fn find_latest_active_by_email(&self, email: &str) -> RepoResult<OtpChallenge> {
        let now = now_utc(&*self.clock);
        sqlx::query_as!(
            OtpChallengeRow,
            r#"SELECT id, authorization_request_id, email, purpose, code_hash, attempt_count,
                      resend_count, expires_at, verified_at, last_sent_at, created_at
               FROM otp_challenges
               WHERE email = $1 AND verified_at IS NULL AND expires_at > $2
               ORDER BY created_at DESC, id LIMIT 1"#,
            email,
            now,
        )
        .fetch_one(&self.pool)
        .await
        .map(OtpChallenge::from)
        .map_err(map_err)
    }
}

#[cfg(test)]
mod tests {
    use auth_core::domain::ZERO_TIME;
    use auth_core::ports::RepoError;
    use time::Duration;

    use super::super::accounts::test_support::{T0, TestClock, TestIds};
    use super::*;

    const REQUEST: &str = "0190cccc-0000-7000-8000-000000000001";

    fn repo(pool: PgPool) -> (PgOtpChallengeRepository, Arc<TestClock>) {
        let clock = TestClock::new();
        (
            PgOtpChallengeRepository::new(pool, clock.clone(), TestIds::new()),
            clock,
        )
    }

    fn challenge(email: &str) -> OtpChallenge {
        OtpChallenge {
            authorization_request_id: Some(REQUEST.into()),
            email: email.into(),
            purpose: "login".into(),
            code_hash: "hash".into(),
            expires_at: T0 + Duration::minutes(10),
            ..OtpChallenge::default()
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_defaults_zero_timestamps_only(pool: PgPool) {
        let (repo, _) = repo(pool);
        let created = repo.create(challenge("ada@example.com")).await.unwrap();
        assert_eq!(created.id, "01900000-0000-7000-8000-000000000001");
        assert_eq!(created.created_at, T0);
        assert_eq!(created.last_sent_at, T0);
        assert_eq!(created.purpose, "login");
        assert_eq!(repo.find_by_id(&created.id).await.unwrap(), created);

        let earlier = T0 - Duration::hours(1);
        let given = repo
            .create(OtpChallenge {
                purpose: String::new(),
                authorization_request_id: None,
                created_at: earlier,
                last_sent_at: earlier,
                ..challenge("ada@example.com")
            })
            .await
            .unwrap();
        assert_eq!(given.created_at, earlier);
        assert_eq!(given.last_sent_at, earlier);
        assert_eq!(given.purpose, "", "purpose is not defaulted");
        assert_eq!(repo.find_by_id(&given.id).await.unwrap(), given);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_id_not_found_and_malformed(pool: PgPool) {
        let (repo, _) = repo(pool);
        let missing = repo
            .find_by_id(&OtpChallengeId::new(REQUEST))
            .await
            .unwrap_err();
        assert!(missing.is_not_found());
        let malformed = repo.find_by_id(&OtpChallengeId::new("")).await.unwrap_err();
        assert!(matches!(malformed, RepoError::Other(_)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_active_returns_newest_unverified(pool: PgPool) {
        let (repo, clock) = repo(pool);
        let older = repo.create(challenge("ada@example.com")).await.unwrap();
        clock.advance(Duration::seconds(30));
        let newer = repo.create(challenge("ada@example.com")).await.unwrap();
        clock.advance(Duration::seconds(30));
        // Newest overall, but verified: skipped.
        repo.create(OtpChallenge {
            verified_at: Some(T0),
            ..challenge("ada@example.com")
        })
        .await
        .unwrap();

        let found = repo
            .find_active_by_request_and_email(REQUEST, "ada@example.com")
            .await
            .unwrap();
        assert_eq!(found, newer);
        assert_ne!(found, older);

        // Expiry is not part of this finder.
        clock.advance(Duration::hours(1));
        assert_eq!(
            repo.find_active_by_request_and_email(REQUEST, "ada@example.com")
                .await
                .unwrap(),
            newer
        );

        for (request, email) in [
            (REQUEST, "Ada@example.com"),
            ("0190cccc-0000-7000-8000-000000000002", "ada@example.com"),
        ] {
            let err = repo
                .find_active_by_request_and_email(request, email)
                .await
                .unwrap_err();
            assert!(err.is_not_found(), "{request}/{email}");
        }
        let malformed = repo
            .find_active_by_request_and_email("", "ada@example.com")
            .await
            .unwrap_err();
        assert!(matches!(malformed, RepoError::Other(_)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn created_at_ties_break_on_id(pool: PgPool) {
        let (repo, _) = repo(pool);
        let first = repo.create(challenge("ada@example.com")).await.unwrap();
        repo.create(challenge("ada@example.com")).await.unwrap();
        assert_eq!(
            repo.find_active_by_request_and_email(REQUEST, "ada@example.com")
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            repo.find_latest_active_by_email("ada@example.com")
                .await
                .unwrap(),
            first
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_latest_active_by_email_filters_expired_and_verified(pool: PgPool) {
        let (repo, clock) = repo(pool);
        let long_lived = repo
            .create(OtpChallenge {
                authorization_request_id: None,
                expires_at: T0 + Duration::hours(2),
                ..challenge("ada@example.com")
            })
            .await
            .unwrap();
        clock.advance(Duration::seconds(1));
        let short_lived = repo.create(challenge("ada@example.com")).await.unwrap();
        clock.advance(Duration::seconds(1));
        repo.create(OtpChallenge {
            verified_at: Some(T0),
            expires_at: T0 + Duration::hours(2),
            ..challenge("ada@example.com")
        })
        .await
        .unwrap();

        assert_eq!(
            repo.find_latest_active_by_email("ada@example.com")
                .await
                .unwrap(),
            short_lived
        );
        // expires_at > now is strict: at exactly T0 + 10m the short one is out.
        clock.advance(Duration::minutes(10) - Duration::seconds(2));
        assert_eq!(
            repo.find_latest_active_by_email("ada@example.com")
                .await
                .unwrap(),
            long_lived
        );
        clock.advance(Duration::hours(3));
        assert!(
            repo.find_latest_active_by_email("ada@example.com")
                .await
                .unwrap_err()
                .is_not_found()
        );
        assert!(
            repo.find_latest_active_by_email("ADA@example.com")
                .await
                .unwrap_err()
                .is_not_found()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_writes_all_columns(pool: PgPool) {
        let (repo, clock) = repo(pool);
        let mut current = repo.create(challenge("ada@example.com")).await.unwrap();
        clock.advance(Duration::minutes(1));
        current.attempt_count = 3;
        current.resend_count = 1;
        current.code_hash = "hash-2".into();
        current.last_sent_at = T0 + Duration::minutes(1);
        current.verified_at = Some(T0 + Duration::minutes(1));
        current.authorization_request_id = None;
        let updated = repo.update(current.clone()).await.unwrap();
        assert_eq!(updated, current, "OTP rows carry no updated_at");
        assert_eq!(repo.find_by_id(&current.id).await.unwrap(), current);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_missing_row_inserts_like_gorm_save(pool: PgPool) {
        let (repo, _) = repo(pool);
        let input = OtpChallenge {
            id: OtpChallengeId::new("0190dddd-0000-7000-8000-000000000001"),
            created_at: ZERO_TIME,
            last_sent_at: T0,
            ..challenge("ada@example.com")
        };
        let saved = repo.update(input).await.unwrap();
        assert_eq!(saved.created_at, T0);
        assert_eq!(repo.find_by_id(&saved.id).await.unwrap(), saved);

        let err = repo.update(challenge("ada@example.com")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "empty id");
    }
}
