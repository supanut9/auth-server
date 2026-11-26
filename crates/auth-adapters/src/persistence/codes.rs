//! `authorization_codes` repository (Go `persistence.AuthorizationCodeRepository`).

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{
    AccountId, AuthorizationCode, AuthorizationCodeId, ClientId, SessionId, is_zero_time,
};
use auth_core::ports::{AuthorizationCodeRepository, Clock, IdGenerator, RepoError, RepoResult};
use sqlx::PgPool;
use time::UtcOffset;
use uuid::Uuid;

use super::common::{map_err, parse_uuid};

/// Postgres-backed [`AuthorizationCodeRepository`].
pub struct PgAuthorizationCodeRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgAuthorizationCodeRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

fn optional_parse_uuid(value: Option<&str>) -> RepoResult<Option<Uuid>> {
    value.map(parse_uuid).transpose()
}

/// Bound column values for one `authorization_codes` row.
struct Params {
    id: Uuid,
    authorization_request_id: Option<Uuid>,
    account_id: Uuid,
    sso_session_id: Option<Uuid>,
}

impl Params {
    fn of(code: &AuthorizationCode) -> RepoResult<Self> {
        Ok(Self {
            id: parse_uuid(code.id.as_str())?,
            authorization_request_id: optional_parse_uuid(
                code.authorization_request_id.as_deref(),
            )?,
            account_id: parse_uuid(code.account_id.as_str())?,
            sso_session_id: optional_parse_uuid(
                code.sso_session_id.as_ref().map(SessionId::as_str),
            )?,
        })
    }
}

impl PgAuthorizationCodeRepository {
    /// Plain insert (GORM `Create`), or with `upsert` the
    /// `ON CONFLICT (id) DO UPDATE` insert GORM `Save` falls back to when its
    /// `UPDATE` matched no row.
    async fn insert(&self, code: &AuthorizationCode, upsert: bool) -> RepoResult<()> {
        let p = Params::of(code)?;
        let result = if upsert {
            sqlx::query!(
                r#"INSERT INTO authorization_codes
                    (id, code_hash, authorization_request_id, account_id, client_id,
                     sso_session_id, redirect_uri, granted_scopes, pkce_code_challenge,
                     pkce_code_challenge_method, nonce, auth_time, expires_at, consumed_at,
                     created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                   ON CONFLICT (id) DO UPDATE SET
                     code_hash = EXCLUDED.code_hash,
                     authorization_request_id = EXCLUDED.authorization_request_id,
                     account_id = EXCLUDED.account_id,
                     client_id = EXCLUDED.client_id,
                     sso_session_id = EXCLUDED.sso_session_id,
                     redirect_uri = EXCLUDED.redirect_uri,
                     granted_scopes = EXCLUDED.granted_scopes,
                     pkce_code_challenge = EXCLUDED.pkce_code_challenge,
                     pkce_code_challenge_method = EXCLUDED.pkce_code_challenge_method,
                     nonce = EXCLUDED.nonce,
                     auth_time = EXCLUDED.auth_time,
                     expires_at = EXCLUDED.expires_at,
                     consumed_at = EXCLUDED.consumed_at,
                     created_at = EXCLUDED.created_at"#,
                p.id,
                code.code_hash,
                p.authorization_request_id,
                p.account_id,
                code.client_id.as_str(),
                p.sso_session_id,
                code.redirect_uri,
                code.granted_scopes,
                code.pkce_code_challenge,
                code.pkce_code_challenge_method,
                code.nonce,
                code.auth_time,
                code.expires_at,
                code.consumed_at,
                code.created_at,
            )
            .execute(&self.pool)
            .await
        } else {
            sqlx::query!(
                r#"INSERT INTO authorization_codes
                    (id, code_hash, authorization_request_id, account_id, client_id,
                     sso_session_id, redirect_uri, granted_scopes, pkce_code_challenge,
                     pkce_code_challenge_method, nonce, auth_time, expires_at, consumed_at,
                     created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
                p.id,
                code.code_hash,
                p.authorization_request_id,
                p.account_id,
                code.client_id.as_str(),
                p.sso_session_id,
                code.redirect_uri,
                code.granted_scopes,
                code.pkce_code_challenge,
                code.pkce_code_challenge_method,
                code.nonce,
                code.auth_time,
                code.expires_at,
                code.consumed_at,
                code.created_at,
            )
            .execute(&self.pool)
            .await
        };
        result.map_err(map_err)?;
        Ok(())
    }
}

#[async_trait]
impl AuthorizationCodeRepository for PgAuthorizationCodeRepository {
    /// Like Go: an empty ID gets a generated one and a zero `created_at` the
    /// clock time; every other field (including zero `auth_time`/`expires_at`)
    /// is stored as given.
    async fn create(&self, mut code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        let now = self.clock.now().to_offset(UtcOffset::UTC);
        if code.id.is_empty() {
            code.id = AuthorizationCodeId::new(self.ids.new_id());
        }
        if is_zero_time(code.created_at) {
            code.created_at = now;
        }
        self.insert(&code, false).await?;
        Ok(code)
    }

    /// GORM `Where("code_hash = ?").First` (`ORDER BY id LIMIT 1`; `code_hash`
    /// is unique anyway).
    async fn find_by_code_hash(&self, code_hash: &str) -> RepoResult<AuthorizationCode> {
        let row = sqlx::query!(
            r#"SELECT id, code_hash, authorization_request_id, account_id, client_id,
                      sso_session_id, redirect_uri, granted_scopes, pkce_code_challenge,
                      pkce_code_challenge_method, nonce, auth_time, expires_at, consumed_at,
                      created_at
               FROM authorization_codes
               WHERE code_hash = $1
               ORDER BY id
               LIMIT 1"#,
            code_hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(RepoError::NotFound)?;

        Ok(AuthorizationCode {
            id: AuthorizationCodeId::new(row.id.to_string()),
            code_hash: row.code_hash,
            authorization_request_id: row.authorization_request_id.map(|id| id.to_string()),
            account_id: AccountId::new(row.account_id.to_string()),
            client_id: ClientId::new(row.client_id),
            sso_session_id: row.sso_session_id.map(|id| SessionId::new(id.to_string())),
            redirect_uri: row.redirect_uri,
            granted_scopes: row.granted_scopes,
            pkce_code_challenge: row.pkce_code_challenge,
            pkce_code_challenge_method: row.pkce_code_challenge_method,
            nonce: row.nonce,
            auth_time: row.auth_time,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        })
    }

    /// GORM `Save`: overwrite every non-key column (zero and `NULL` values
    /// included) `WHERE id = $1`. When that matches no row, Save inserts the
    /// row with `ON CONFLICT (id) DO UPDATE`; on that path GORM's
    /// auto-create-time filled a zero `created_at` with the wall clock, here
    /// with the adapter clock. An empty or malformed ID is an error, as the
    /// Go insert into a `uuid` column was.
    async fn update(&self, mut code: AuthorizationCode) -> RepoResult<AuthorizationCode> {
        let p = Params::of(&code)?;
        let result = sqlx::query!(
            r#"UPDATE authorization_codes SET
                 code_hash = $2,
                 authorization_request_id = $3,
                 account_id = $4,
                 client_id = $5,
                 sso_session_id = $6,
                 redirect_uri = $7,
                 granted_scopes = $8,
                 pkce_code_challenge = $9,
                 pkce_code_challenge_method = $10,
                 nonce = $11,
                 auth_time = $12,
                 expires_at = $13,
                 consumed_at = $14,
                 created_at = $15
               WHERE id = $1"#,
            p.id,
            code.code_hash,
            p.authorization_request_id,
            p.account_id,
            code.client_id.as_str(),
            p.sso_session_id,
            code.redirect_uri,
            code.granted_scopes,
            code.pkce_code_challenge,
            code.pkce_code_challenge_method,
            code.nonce,
            code.auth_time,
            code.expires_at,
            code.consumed_at,
            code.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        if result.rows_affected() == 0 {
            if is_zero_time(code.created_at) {
                code.created_at = self.clock.now().to_offset(UtcOffset::UTC);
            }
            self.insert(&code, true).await?;
        }
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use time::OffsetDateTime;
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-05-16 12:00:00.123456 UTC);
    const ACCOUNT: &str = "01900000-0000-7000-8000-00000000a001";
    const SESSION: &str = "01900000-0000-7000-8000-00000000b001";

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            NOW
        }
    }

    struct SeqIds(AtomicU64);

    impl IdGenerator for SeqIds {
        fn new_id(&self) -> String {
            let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
            format!("01900000-0000-7000-8000-{n:012x}")
        }
    }

    fn repo(pool: PgPool) -> PgAuthorizationCodeRepository {
        PgAuthorizationCodeRepository::new(
            pool,
            Arc::new(FixedClock),
            Arc::new(SeqIds(AtomicU64::new(0))),
        )
    }

    async fn seed(pool: &PgPool) {
        let account = Uuid::parse_str(ACCOUNT).unwrap();
        sqlx::query(
            "INSERT INTO accounts (id, primary_verified_email, display_name, status, created_at, updated_at)
             VALUES ($1, 'a@example.test', 'A', 'active', now(), now())",
        )
        .bind(account)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, client_type, display_name, allowed_scopes, status, created_at, updated_at)
             VALUES ('01900000-0000-7000-8000-00000000c001', 'demo-web', 'public', 'Demo', 'openid', 'active', now(), now())",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sso_sessions (id, account_id, status, login_method, authenticated_at, last_seen_at, expires_at, created_at, updated_at)
             VALUES ($1, $2, 'active', 'google', now(), now(), now(), now(), now())",
        )
        .bind(Uuid::parse_str(SESSION).unwrap())
        .bind(account)
        .execute(pool)
        .await
        .unwrap();
    }

    fn code(hash: &str) -> AuthorizationCode {
        AuthorizationCode {
            code_hash: hash.into(),
            account_id: AccountId::new(ACCOUNT),
            client_id: ClientId::new("demo-web"),
            redirect_uri: "https://a.test/cb".into(),
            granted_scopes: "openid profile".into(),
            pkce_code_challenge: "challenge".into(),
            pkce_code_challenge_method: "S256".into(),
            auth_time: datetime!(2026-05-16 11:59:00 UTC),
            expires_at: datetime!(2026-05-16 12:01:00 UTC),
            ..AuthorizationCode::default()
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_defaults_and_round_trips_with_nulls(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let created = repo.create(code("h1")).await.unwrap();
        assert_eq!(created.id.as_str(), "01900000-0000-7000-8000-000000000001");
        assert_eq!(created.created_at, NOW);

        let found = repo.find_by_code_hash("h1").await.unwrap();
        assert_eq!(found, created);
        assert_eq!(found.authorization_request_id, None);
        assert_eq!(found.sso_session_id, None);
        assert_eq!(found.consumed_at, None);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_keeps_explicit_values(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let mut input = code("h2");
        input.id = AuthorizationCodeId::new("01900000-0000-7000-8000-0000000000ee");
        input.created_at = datetime!(2026-05-16 10:00:00 UTC);
        input.sso_session_id = Some(SessionId::new(SESSION));
        input.authorization_request_id = Some("01900000-0000-7000-8000-00000000d001".into());
        input.nonce = "n-0S6_WzA2Mj".into();
        let created = repo.create(input.clone()).await.unwrap();
        assert_eq!(created, input);
        assert_eq!(repo.find_by_code_hash("h2").await.unwrap(), input);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_overwrites_all_columns(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let mut stored = repo.create(code("h3")).await.unwrap();
        stored.consumed_at = Some(datetime!(2026-05-16 12:00:30 UTC));
        stored.sso_session_id = Some(SessionId::new(SESSION));
        stored.granted_scopes = "openid".into();
        stored.nonce = "n-0S6_WzA2Mj".into();
        repo.update(stored.clone()).await.unwrap();
        assert_eq!(repo.find_by_code_hash("h3").await.unwrap(), stored);

        // Clearing nullable columns writes NULL (Save writes zero values).
        stored.consumed_at = None;
        stored.sso_session_id = None;
        repo.update(stored.clone()).await.unwrap();
        assert_eq!(repo.find_by_code_hash("h3").await.unwrap(), stored);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_of_missing_row_inserts_like_gorm_save(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let mut input = code("h4");
        input.id = AuthorizationCodeId::new("01900000-0000-7000-8000-0000000000dd");
        let saved = repo.update(input).await.unwrap();
        assert_eq!(saved.created_at, NOW);
        assert_eq!(repo.find_by_code_hash("h4").await.unwrap(), saved);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn missing_hash_is_not_found(pool: PgPool) {
        let err = repo(pool).find_by_code_hash("nope").await.unwrap_err();
        assert!(err.is_not_found());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn duplicate_hash_conflicts(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        repo.create(code("dup")).await.unwrap();
        assert!(repo.create(code("dup")).await.unwrap_err().is_conflict());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn malformed_uuid_is_other_error(pool: PgPool) {
        let repo = repo(pool);
        let mut input = code("bad");
        input.sso_session_id = Some(SessionId::new("not-a-uuid"));
        let err = repo.create(input).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");

        let err = repo.update(code("bad")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "empty id: {err:?}");
    }
}
