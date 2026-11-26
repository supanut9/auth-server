//! `sso_sessions` repository (`internal/adapter/out/persistence/sso_session_repository.go`).

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{AccountId, SessionId, SsoSession, SsoSessionStatus, is_zero_time};
use auth_core::ports::{Clock, IdGenerator, RepoResult, SsoSessionRepository};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::accounts::{now_utc, parse_uuid};
use super::common::map_err;

/// Postgres-backed [`SsoSessionRepository`].
#[derive(Clone)]
pub struct PgSsoSessionRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgSsoSessionRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

struct SsoSessionRow {
    id: Uuid,
    account_id: Uuid,
    status: String,
    login_method: String,
    authenticated_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<SsoSessionRow> for SsoSession {
    fn from(row: SsoSessionRow) -> Self {
        Self {
            id: SessionId::new(row.id.to_string()),
            account_id: AccountId::new(row.account_id.to_string()),
            status: SsoSessionStatus::from(row.status),
            login_method: row.login_method,
            authenticated_at: row.authenticated_at,
            last_seen_at: row.last_seen_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl SsoSessionRepository for PgSsoSessionRepository {
    /// Empty status defaults to `active`; zero `created_at`/`updated_at`
    /// default to now. Other timestamps are stored as given.
    async fn create(&self, mut session: SsoSession) -> RepoResult<SsoSession> {
        let now = now_utc(&*self.clock);
        if session.id.is_empty() {
            session.id = SessionId::new(self.ids.new_id());
        }
        if session.status.is_empty() {
            session.status = SsoSessionStatus::Active;
        }
        if is_zero_time(session.created_at) {
            session.created_at = now;
        }
        if is_zero_time(session.updated_at) {
            session.updated_at = now;
        }

        let id = parse_uuid(session.id.as_str())?;
        let account_id = parse_uuid(session.account_id.as_str())?;
        sqlx::query!(
            r#"INSERT INTO sso_sessions
                (id, account_id, status, login_method, authenticated_at, last_seen_at,
                 expires_at, revoked_at, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
            id,
            account_id,
            session.status.as_str(),
            session.login_method,
            session.authenticated_at,
            session.last_seen_at,
            session.expires_at,
            session.revoked_at,
            session.created_at,
            session.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(session)
    }

    async fn find_by_id(&self, id: &SessionId) -> RepoResult<SsoSession> {
        let id = parse_uuid(id.as_str())?;
        sqlx::query_as!(
            SsoSessionRow,
            r#"SELECT id, account_id, status, login_method, authenticated_at, last_seen_at,
                      expires_at, revoked_at, created_at, updated_at
               FROM sso_sessions WHERE id = $1 ORDER BY id LIMIT 1"#,
            id,
        )
        .fetch_one(&self.pool)
        .await
        .map(SsoSession::from)
        .map_err(map_err)
    }

    /// GORM `Save` with `updated_at` = now: update every column by ID; when no
    /// row matched, insert it with `ON CONFLICT (id) DO UPDATE` and a zero
    /// `created_at` set to now.
    async fn update(&self, mut session: SsoSession) -> RepoResult<SsoSession> {
        let now = now_utc(&*self.clock);
        session.updated_at = now;
        let id = parse_uuid(session.id.as_str())?;
        let account_id = parse_uuid(session.account_id.as_str())?;

        let updated = sqlx::query!(
            r#"UPDATE sso_sessions
               SET account_id = $2, status = $3, login_method = $4, authenticated_at = $5,
                   last_seen_at = $6, expires_at = $7, revoked_at = $8, created_at = $9,
                   updated_at = $10
               WHERE id = $1"#,
            id,
            account_id,
            session.status.as_str(),
            session.login_method,
            session.authenticated_at,
            session.last_seen_at,
            session.expires_at,
            session.revoked_at,
            session.created_at,
            session.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if updated.rows_affected() > 0 {
            return Ok(session);
        }

        if is_zero_time(session.created_at) {
            session.created_at = now;
        }
        sqlx::query!(
            r#"INSERT INTO sso_sessions
                (id, account_id, status, login_method, authenticated_at, last_seen_at,
                 expires_at, revoked_at, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (id) DO UPDATE SET
                   account_id = EXCLUDED.account_id,
                   status = EXCLUDED.status,
                   login_method = EXCLUDED.login_method,
                   authenticated_at = EXCLUDED.authenticated_at,
                   last_seen_at = EXCLUDED.last_seen_at,
                   expires_at = EXCLUDED.expires_at,
                   revoked_at = EXCLUDED.revoked_at,
                   updated_at = EXCLUDED.updated_at"#,
            id,
            account_id,
            session.status.as_str(),
            session.login_method,
            session.authenticated_at,
            session.last_seen_at,
            session.expires_at,
            session.revoked_at,
            session.created_at,
            session.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(session)
    }

    /// Sets `status = revoked`, `revoked_at` and `updated_at` to now. Like
    /// GORM `Updates`, an unknown (well-formed) ID is not an error, and an
    /// already revoked session gets fresh timestamps.
    async fn revoke_by_id(&self, id: &SessionId) -> RepoResult<()> {
        let now = now_utc(&*self.clock);
        let id = parse_uuid(id.as_str())?;
        sqlx::query!(
            r#"UPDATE sso_sessions SET status = $2, revoked_at = $3, updated_at = $3
               WHERE id = $1"#,
            id,
            SsoSessionStatus::Revoked.as_str(),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use auth_core::domain::{Account, ZERO_TIME};
    use auth_core::ports::{AccountRepository, RepoError};
    use time::Duration;

    use super::super::accounts::PgAccountRepository;
    use super::super::accounts::test_support::{T0, TestClock, TestIds};
    use super::*;

    async fn setup(pool: PgPool) -> (PgSsoSessionRepository, Arc<TestClock>, Account) {
        let clock = TestClock::new();
        let ids = TestIds::new();
        let accounts = PgAccountRepository::new(pool.clone(), clock.clone(), ids.clone());
        let account = accounts
            .create(Account {
                primary_verified_email: "ada@example.com".into(),
                display_name: "Ada".into(),
                ..Account::default()
            })
            .await
            .unwrap();
        (
            PgSsoSessionRepository::new(pool, clock.clone(), ids),
            clock,
            account,
        )
    }

    fn session(account: &Account) -> SsoSession {
        SsoSession {
            account_id: account.id.clone(),
            login_method: "email_otp".into(),
            authenticated_at: T0,
            last_seen_at: T0,
            expires_at: T0 + Duration::days(30),
            ..SsoSession::default()
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_applies_go_defaults(pool: PgPool) {
        let (repo, _, account) = setup(pool).await;
        let created = repo.create(session(&account)).await.unwrap();
        assert_eq!(created.id, "01900000-0000-7000-8000-000000000002");
        assert_eq!(created.status, SsoSessionStatus::Active);
        assert_eq!(created.created_at, T0);
        assert_eq!(created.updated_at, T0);
        assert_eq!(created.revoked_at, None);
        assert_eq!(repo.find_by_id(&created.id).await.unwrap(), created);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_keeps_given_values(pool: PgPool) {
        let (repo, _, account) = setup(pool).await;
        let earlier = T0 - Duration::hours(1);
        let input = SsoSession {
            id: SessionId::new("0190eeee-0000-7000-8000-000000000001"),
            status: SsoSessionStatus::Revoked,
            revoked_at: Some(earlier),
            created_at: earlier,
            updated_at: earlier,
            ..session(&account)
        };
        let created = repo.create(input.clone()).await.unwrap();
        assert_eq!(created, input);
        assert_eq!(repo.find_by_id(&created.id).await.unwrap(), input);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_for_unknown_account_is_other(pool: PgPool) {
        let (repo, _, _) = setup(pool).await;
        let ghost = Account {
            id: AccountId::new("0190ffff-0000-7000-8000-000000000001"),
            ..Account::default()
        };
        let err = repo.create(session(&ghost)).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "FK violation: {err:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_id_not_found_and_malformed(pool: PgPool) {
        let (repo, _, _) = setup(pool).await;
        let missing = repo
            .find_by_id(&SessionId::new("0190ffff-0000-7000-8000-000000000001"))
            .await
            .unwrap_err();
        assert!(missing.is_not_found());
        let malformed = repo
            .find_by_id(&SessionId::new("cookie-value"))
            .await
            .unwrap_err();
        assert!(matches!(malformed, RepoError::Other(_)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_stamps_updated_at_and_keeps_other_fields(pool: PgPool) {
        let (repo, clock, account) = setup(pool).await;
        let mut current = repo.create(session(&account)).await.unwrap();
        clock.advance(Duration::minutes(3));
        current.last_seen_at = T0 + Duration::minutes(3);
        current.updated_at = ZERO_TIME;
        let updated = repo.update(current.clone()).await.unwrap();
        assert_eq!(updated.updated_at, T0 + Duration::minutes(3));
        assert_eq!(updated.created_at, T0);
        assert_eq!(updated.last_seen_at, T0 + Duration::minutes(3));
        assert_eq!(repo.find_by_id(&updated.id).await.unwrap(), updated);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_missing_row_inserts_like_gorm_save(pool: PgPool) {
        let (repo, _, account) = setup(pool).await;
        let input = SsoSession {
            id: SessionId::new("0190eeee-0000-7000-8000-000000000002"),
            status: SsoSessionStatus::Active,
            ..session(&account)
        };
        let saved = repo.update(input).await.unwrap();
        assert_eq!(saved.created_at, T0);
        assert_eq!(saved.updated_at, T0);
        assert_eq!(repo.find_by_id(&saved.id).await.unwrap(), saved);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoke_by_id_sets_status_and_timestamps(pool: PgPool) {
        let (repo, clock, account) = setup(pool).await;
        let created = repo.create(session(&account)).await.unwrap();
        let other = repo.create(session(&account)).await.unwrap();
        clock.advance(Duration::minutes(7));
        repo.revoke_by_id(&created.id).await.unwrap();

        let revoked = repo.find_by_id(&created.id).await.unwrap();
        assert_eq!(revoked.status, SsoSessionStatus::Revoked);
        assert_eq!(revoked.revoked_at, Some(T0 + Duration::minutes(7)));
        assert_eq!(revoked.updated_at, T0 + Duration::minutes(7));
        assert_eq!(revoked.created_at, T0);
        assert_eq!(revoked.last_seen_at, created.last_seen_at);
        assert_eq!(repo.find_by_id(&other.id).await.unwrap(), other);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoke_by_id_unknown_is_ok_malformed_is_other(pool: PgPool) {
        let (repo, _, _) = setup(pool).await;
        repo.revoke_by_id(&SessionId::new("0190ffff-0000-7000-8000-000000000001"))
            .await
            .unwrap();
        let err = repo.revoke_by_id(&SessionId::new("")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)));
    }
}
