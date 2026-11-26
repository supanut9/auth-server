//! `access_tokens` audit repository
//! (`internal/adapter/out/persistence/access_token_repository.go`).
//!
//! Write-only: rows are never read back when validating tokens.

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{AccessTokenRecord, AccessTokenRecordId, AccessTokenStatus, is_zero_time};
use auth_core::ports::{AccessTokenRepository, Clock, IdGenerator, RepoResult};
use sqlx::PgPool;

use super::chains::parse_uuid;
use super::common::map_err;

/// Postgres [`AccessTokenRepository`].
#[derive(Clone)]
pub struct PgAccessTokenRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgAccessTokenRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

#[async_trait]
impl AccessTokenRepository for PgAccessTokenRepository {
    async fn create(&self, mut record: AccessTokenRecord) -> RepoResult<AccessTokenRecord> {
        let now = self.clock.now();
        if record.id.is_empty() {
            record.id = AccessTokenRecordId::new(self.ids.new_id());
        }
        if record.status.is_empty() {
            record.status = AccessTokenStatus::Active;
        }
        if is_zero_time(record.created_at) {
            record.created_at = now;
        }

        let account_id = record
            .account_id
            .as_ref()
            .map(|id| parse_uuid(id.as_str()))
            .transpose()?;
        let sso_session_id = record
            .sso_session_id
            .as_ref()
            .map(|id| parse_uuid(id.as_str()))
            .transpose()?;

        sqlx::query!(
            r#"INSERT INTO access_tokens (
                   id, jti, sid, account_id, client_id, sso_session_id, audience, scope,
                   issued_at, expires_at, status, revoked_at, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"#,
            parse_uuid(record.id.as_str())?,
            record.jti,
            record.sid,
            account_id,
            record.client_id.as_str(),
            sso_session_id,
            record.audience,
            record.scope,
            record.issued_at,
            record.expires_at,
            record.status.as_str(),
            record.revoked_at,
            record.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use auth_core::domain::{
        AccessTokenRecord, AccessTokenRecordId, AccessTokenStatus, AccountId, ClientId, SessionId,
    };
    use auth_core::ports::{AccessTokenRepository, RepoError};
    use sqlx::{PgPool, Row};
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::PgAccessTokenRepository;
    use crate::persistence::chains::test_support::{FixedClock, SeqIds, T0, seed_base, uid};

    fn repo(pool: PgPool) -> PgAccessTokenRepository {
        PgAccessTokenRepository::new(
            pool,
            Arc::new(FixedClock::new(T0)),
            Arc::new(SeqIds::new(300)),
        )
    }

    fn record(jti: &str) -> AccessTokenRecord {
        AccessTokenRecord {
            jti: jti.into(),
            sid: uid(10),
            account_id: Some(AccountId::new(uid(1))),
            client_id: ClientId::new("client-a"),
            sso_session_id: Some(SessionId::new(uid(10))),
            audience: "client-a".into(),
            scope: "openid email".into(),
            issued_at: T0,
            expires_at: T0 + Duration::minutes(15),
            ..AccessTokenRecord::default()
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_fills_defaults_and_persists_row(pool: PgPool) {
        seed_base(&pool).await;
        let created = repo(pool.clone()).create(record("jti-1")).await.unwrap();
        assert_eq!(created.id, AccessTokenRecordId::new(uid(300)));
        assert_eq!(created.status, AccessTokenStatus::Active);
        assert_eq!(created.created_at, T0);

        let row = sqlx::query(
            "SELECT id, account_id, sso_session_id, status, created_at, revoked_at FROM access_tokens WHERE jti = 'jti-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<Uuid, _>("id").to_string(), uid(300));
        assert_eq!(
            row.get::<Option<Uuid>, _>("account_id")
                .unwrap()
                .to_string(),
            uid(1)
        );
        assert_eq!(
            row.get::<Option<Uuid>, _>("sso_session_id")
                .unwrap()
                .to_string(),
            uid(10)
        );
        assert_eq!(row.get::<String, _>("status"), "active");
        assert_eq!(row.get::<OffsetDateTime, _>("created_at"), T0);
        assert_eq!(row.get::<Option<OffsetDateTime>, _>("revoked_at"), None);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn client_credentials_record_has_null_account_and_session(pool: PgPool) {
        seed_base(&pool).await;
        let mut input = record("jti-cc");
        input.account_id = None;
        input.sso_session_id = None;
        input.sid = String::new();
        input.id = AccessTokenRecordId::new(uid(55));
        input.status = AccessTokenStatus::Revoked;
        input.created_at = T0 - Duration::hours(1);
        let created = repo(pool.clone()).create(input.clone()).await.unwrap();
        assert_eq!(created, input);

        let row = sqlx::query(
            "SELECT account_id, sso_session_id, status FROM access_tokens WHERE jti = 'jti-cc'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<Option<Uuid>, _>("account_id"), None);
        assert_eq!(row.get::<Option<Uuid>, _>("sso_session_id"), None);
        assert_eq!(row.get::<String, _>("status"), "revoked");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn duplicate_jti_is_conflict_and_bad_uuid_is_other(pool: PgPool) {
        seed_base(&pool).await;
        let repo = repo(pool);
        repo.create(record("jti-1")).await.unwrap();
        let err = repo.create(record("jti-1")).await.unwrap_err();
        assert!(err.is_conflict(), "{err:?}");

        let mut bad = record("jti-2");
        bad.account_id = Some(AccountId::new("account-1"));
        let err = repo.create(bad).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
    }
}
