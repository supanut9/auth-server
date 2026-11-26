//! `refresh_token_chains` repository
//! (`internal/adapter/out/persistence/refresh_token_chain_repository.go`).
//!
//! IDs are `uuid` columns but strings in the domain. A string that is not a
//! UUID fails with [`RepoError::Other`] before reaching the database. Go sent
//! it to Postgres, which failed with `invalid input syntax for type uuid`
//! (also a non-`NotFound` error), so callers see the same error class.

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{
    AccountId, ChainId, ClientId, RefreshTokenChain, RefreshTokenChainStatus, SessionId,
    is_zero_time,
};
use auth_core::ports::{Clock, IdGenerator, RefreshTokenChainRepository, RepoError, RepoResult};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::common::{map_err, parse_uuid};

/// Row shape shared with the support repository.
pub(super) struct ChainRow {
    pub(super) id: Uuid,
    pub(super) account_id: Uuid,
    pub(super) client_id: String,
    pub(super) sso_session_id: Uuid,
    pub(super) scope: String,
    pub(super) device_session_id: String,
    pub(super) status: String,
    pub(super) absolute_expires_at: OffsetDateTime,
    pub(super) inactive_expires_at: OffsetDateTime,
    pub(super) last_used_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl From<ChainRow> for RefreshTokenChain {
    fn from(row: ChainRow) -> Self {
        Self {
            id: ChainId::new(row.id.to_string()),
            account_id: AccountId::new(row.account_id.to_string()),
            client_id: ClientId::new(row.client_id),
            sso_session_id: SessionId::new(row.sso_session_id.to_string()),
            scope: row.scope,
            device_session_id: row.device_session_id,
            status: RefreshTokenChainStatus::from(row.status),
            absolute_expires_at: row.absolute_expires_at,
            inactive_expires_at: row.inactive_expires_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Postgres [`RefreshTokenChainRepository`].
#[derive(Clone)]
pub struct PgRefreshTokenChainRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgRefreshTokenChainRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

#[async_trait]
impl RefreshTokenChainRepository for PgRefreshTokenChainRepository {
    async fn create(&self, mut chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        let now = self.clock.now();
        if chain.id.is_empty() {
            chain.id = ChainId::new(self.ids.new_id());
        }
        if chain.status.is_empty() {
            chain.status = RefreshTokenChainStatus::Active;
        }
        if is_zero_time(chain.created_at) {
            chain.created_at = now;
        }
        if is_zero_time(chain.updated_at) {
            chain.updated_at = now;
        }

        sqlx::query!(
            r#"INSERT INTO refresh_token_chains (
                   id, account_id, client_id, sso_session_id, scope, device_session_id,
                   status, absolute_expires_at, inactive_expires_at, last_used_at,
                   revoked_at, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"#,
            parse_uuid(chain.id.as_str())?,
            parse_uuid(chain.account_id.as_str())?,
            chain.client_id.as_str(),
            parse_uuid(chain.sso_session_id.as_str())?,
            chain.scope,
            chain.device_session_id,
            chain.status.as_str(),
            chain.absolute_expires_at,
            chain.inactive_expires_at,
            chain.last_used_at,
            chain.revoked_at,
            chain.created_at,
            chain.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        // Go returns the written model, not a re-read row.
        Ok(chain)
    }

    async fn find_by_id(&self, id: &ChainId) -> RepoResult<RefreshTokenChain> {
        let id = parse_uuid(id.as_str())?;
        // GORM `First`: ORDER BY primary key LIMIT 1.
        sqlx::query_as!(
            ChainRow,
            r#"SELECT id, account_id, client_id, sso_session_id, scope, device_session_id,
                      status, absolute_expires_at, inactive_expires_at, last_used_at,
                      revoked_at, created_at, updated_at
               FROM refresh_token_chains
               WHERE id = $1
               ORDER BY id
               LIMIT 1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(RefreshTokenChain::from)
        .ok_or(RepoError::NotFound)
    }

    async fn list_active_ids_by_sso_session_id(
        &self,
        sso_session_id: &SessionId,
    ) -> RepoResult<Vec<ChainId>> {
        let sso_session_id = parse_uuid(sso_session_id.as_str())?;
        // GORM `Pluck` has no ORDER BY; row order is unspecified, as in Go.
        let ids = sqlx::query_scalar!(
            r#"SELECT id
               FROM refresh_token_chains
               WHERE sso_session_id = $1 AND status = $2 AND revoked_at IS NULL"#,
            sso_session_id,
            RefreshTokenChainStatus::Active.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(ids
            .into_iter()
            .map(|id| ChainId::new(id.to_string()))
            .collect())
    }

    async fn update(&self, mut chain: RefreshTokenChain) -> RepoResult<RefreshTokenChain> {
        // Go sets UpdatedAt from the clock, then GORM `Save` overwrote it with
        // its own wall-clock `NowFunc`. Rust uses the injected clock only.
        chain.updated_at = self.clock.now();

        // GORM `Save`: UPDATE every column by primary key, INSERT when no row
        // matched. The upsert reaches the same final state in one statement.
        sqlx::query!(
            r#"INSERT INTO refresh_token_chains (
                   id, account_id, client_id, sso_session_id, scope, device_session_id,
                   status, absolute_expires_at, inactive_expires_at, last_used_at,
                   revoked_at, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
               ON CONFLICT (id) DO UPDATE SET
                   account_id = EXCLUDED.account_id,
                   client_id = EXCLUDED.client_id,
                   sso_session_id = EXCLUDED.sso_session_id,
                   scope = EXCLUDED.scope,
                   device_session_id = EXCLUDED.device_session_id,
                   status = EXCLUDED.status,
                   absolute_expires_at = EXCLUDED.absolute_expires_at,
                   inactive_expires_at = EXCLUDED.inactive_expires_at,
                   last_used_at = EXCLUDED.last_used_at,
                   revoked_at = EXCLUDED.revoked_at,
                   created_at = EXCLUDED.created_at,
                   updated_at = EXCLUDED.updated_at"#,
            parse_uuid(chain.id.as_str())?,
            parse_uuid(chain.account_id.as_str())?,
            chain.client_id.as_str(),
            parse_uuid(chain.sso_session_id.as_str())?,
            chain.scope,
            chain.device_session_id,
            chain.status.as_str(),
            chain.absolute_expires_at,
            chain.inactive_expires_at,
            chain.last_used_at,
            chain.revoked_at,
            chain.created_at,
            chain.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(chain)
    }

    async fn revoke_by_id(&self, id: &ChainId) -> RepoResult<()> {
        let id = parse_uuid(id.as_str())?;
        let now = self.clock.now();
        // No status/revoked_at filter: an already revoked chain is overwritten,
        // and a missing chain is not an error, both as in Go.
        sqlx::query!(
            r#"UPDATE refresh_token_chains
               SET status = $2, revoked_at = $3, updated_at = $3
               WHERE id = $1"#,
            id,
            RefreshTokenChainStatus::Revoked.as_str(),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod test_support {
    //! Deterministic ports and raw-SQL fixtures shared by this lane's tests.

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use auth_core::ports::{Clock, IdGenerator};
    use sqlx::PgPool;
    use time::OffsetDateTime;
    use time::macros::datetime;
    use uuid::Uuid;

    pub const T0: OffsetDateTime = datetime!(2026-04-03 12:00:00 UTC);

    /// Clock fixed at a settable instant.
    pub struct FixedClock(Mutex<OffsetDateTime>);

    impl FixedClock {
        pub fn new(now: OffsetDateTime) -> Self {
            Self(Mutex::new(now))
        }

        pub fn set(&self, now: OffsetDateTime) {
            *self.0.lock().unwrap() = now;
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    /// Yields `00000000-0000-0000-0000-0000000000NN`-style IDs from `base`.
    pub struct SeqIds(AtomicU64);

    impl SeqIds {
        pub fn new(base: u64) -> Self {
            Self(AtomicU64::new(base))
        }
    }

    impl IdGenerator for SeqIds {
        fn new_id(&self) -> String {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            Uuid::from_u128(u128::from(n)).to_string()
        }
    }

    pub fn uid(n: u128) -> String {
        Uuid::from_u128(n).to_string()
    }

    pub async fn insert_account(pool: &PgPool, id: &str, email: &str) {
        sqlx::query(
            "INSERT INTO accounts (id, primary_verified_email, display_name, avatar_url, status, created_at, updated_at)
             VALUES ($1::uuid, $2, 'Alice Example', 'https://cdn.example/alice.png', 'active', $3, $3)",
        )
        .bind(id)
        .bind(email)
        .bind(T0)
        .execute(pool)
        .await
        .unwrap();
    }

    pub async fn insert_client(pool: &PgPool, record_id: &str, client_id: &str, display: &str) {
        sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, client_type, display_name, allowed_scopes, status, created_at, updated_at)
             VALUES ($1::uuid, $2, 'confidential', $3, 'openid email profile', 'active', $4, $4)",
        )
        .bind(record_id)
        .bind(client_id)
        .bind(display)
        .bind(T0)
        .execute(pool)
        .await
        .unwrap();
    }

    pub async fn insert_session(
        pool: &PgPool,
        id: &str,
        account_id: &str,
        login_method: &str,
        last_seen_at: OffsetDateTime,
    ) {
        sqlx::query(
            "INSERT INTO sso_sessions (id, account_id, status, login_method, authenticated_at, last_seen_at, expires_at, created_at, updated_at)
             VALUES ($1::uuid, $2::uuid, 'active', $3, $4, $4, $5, $4, $4)",
        )
        .bind(id)
        .bind(account_id)
        .bind(login_method)
        .bind(last_seen_at)
        .bind(last_seen_at + time::Duration::days(1))
        .execute(pool)
        .await
        .unwrap();
    }

    /// Inserts account `uid(1)`, client `client-a` and session `uid(10)`.
    pub async fn seed_base(pool: &PgPool) {
        insert_account(pool, &uid(1), "alice@example.com").await;
        insert_client(pool, &uid(100), "client-a", "Client A").await;
        insert_session(pool, &uid(10), &uid(1), "google", T0).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use auth_core::domain::{
        AccountId, ChainId, ClientId, RefreshTokenChain, RefreshTokenChainStatus, SessionId,
    };
    use auth_core::ports::{RefreshTokenChainRepository, RepoError};
    use sqlx::PgPool;
    use time::Duration;

    use super::PgRefreshTokenChainRepository;
    use super::test_support::{FixedClock, SeqIds, T0, insert_session, seed_base, uid};

    fn repo(pool: PgPool) -> (PgRefreshTokenChainRepository, Arc<FixedClock>) {
        let clock = Arc::new(FixedClock::new(T0));
        let repo =
            PgRefreshTokenChainRepository::new(pool, clock.clone(), Arc::new(SeqIds::new(500)));
        (repo, clock)
    }

    fn chain(id: &str, session: u128) -> RefreshTokenChain {
        RefreshTokenChain {
            id: ChainId::new(id),
            account_id: AccountId::new(uid(1)),
            client_id: ClientId::new("client-a"),
            sso_session_id: SessionId::new(uid(session)),
            scope: "openid email".into(),
            device_session_id: "device-1".into(),
            absolute_expires_at: T0 + Duration::days(30),
            inactive_expires_at: T0 + Duration::days(7),
            last_used_at: T0,
            ..RefreshTokenChain::default()
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_fills_defaults_and_round_trips(pool: PgPool) {
        seed_base(&pool).await;
        let (repo, _) = repo(pool);

        let created = repo.create(chain("", 10)).await.unwrap();
        assert_eq!(created.id, uid(500).as_str());
        assert_eq!(created.status, RefreshTokenChainStatus::Active);
        assert_eq!(created.created_at, T0);
        assert_eq!(created.updated_at, T0);
        assert_eq!(created.revoked_at, None);

        let found = repo.find_by_id(&created.id).await.unwrap();
        assert_eq!(found, created);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_keeps_explicit_values(pool: PgPool) {
        seed_base(&pool).await;
        let (repo, _) = repo(pool);
        let mut input = chain(&uid(42), 10);
        input.status = RefreshTokenChainStatus::Revoked;
        input.created_at = T0 - Duration::hours(1);
        input.updated_at = T0 - Duration::minutes(5);
        input.revoked_at = Some(T0 - Duration::minutes(5));

        let created = repo.create(input.clone()).await.unwrap();
        assert_eq!(created, input);
        assert_eq!(
            repo.find_by_id(&ChainId::new(uid(42))).await.unwrap(),
            input
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_id_missing_is_not_found(pool: PgPool) {
        let (repo, _) = repo(pool);
        let err = repo.find_by_id(&ChainId::new(uid(9))).await.unwrap_err();
        assert!(err.is_not_found(), "{err}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn malformed_id_is_other_error(pool: PgPool) {
        let (repo, _) = repo(pool);
        let err = repo.find_by_id(&ChainId::new("chain-1")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "ERROR: invalid input syntax for type uuid: \"chain-1\" (SQLSTATE 22P02)"
        );
        let err = repo.revoke_by_id(&ChainId::new("")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn duplicate_id_is_conflict(pool: PgPool) {
        seed_base(&pool).await;
        let (repo, _) = repo(pool);
        repo.create(chain(&uid(42), 10)).await.unwrap();
        let err = repo.create(chain(&uid(42), 10)).await.unwrap_err();
        assert!(err.is_conflict(), "{err:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_saves_all_columns_and_stamps_updated_at(pool: PgPool) {
        seed_base(&pool).await;
        let (repo, clock) = repo(pool);
        let mut current = repo.create(chain(&uid(42), 10)).await.unwrap();

        let later = T0 + Duration::minutes(3);
        clock.set(later);
        current.last_used_at = later;
        current.inactive_expires_at = later + Duration::days(7);
        current.scope = "openid".into();
        current.updated_at = T0 - Duration::days(9); // overwritten by the repo
        let updated = repo.update(current.clone()).await.unwrap();
        assert_eq!(updated.updated_at, later);
        assert_eq!(updated.last_used_at, later);

        let found = repo.find_by_id(&current.id).await.unwrap();
        assert_eq!(found, updated);
        assert_eq!(found.created_at, T0);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_of_missing_row_inserts_like_gorm_save(pool: PgPool) {
        seed_base(&pool).await;
        let (repo, _) = repo(pool);
        let mut input = chain(&uid(77), 10);
        input.status = RefreshTokenChainStatus::Active;
        input.created_at = T0;
        let saved = repo.update(input).await.unwrap();
        assert_eq!(repo.find_by_id(&saved.id).await.unwrap(), saved);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoke_by_id_sets_status_and_timestamps(pool: PgPool) {
        seed_base(&pool).await;
        let (repo, clock) = repo(pool);
        let created = repo.create(chain(&uid(42), 10)).await.unwrap();

        let at = T0 + Duration::hours(2);
        clock.set(at);
        repo.revoke_by_id(&created.id).await.unwrap();
        let found = repo.find_by_id(&created.id).await.unwrap();
        assert_eq!(found.status, RefreshTokenChainStatus::Revoked);
        assert_eq!(found.revoked_at, Some(at));
        assert_eq!(found.updated_at, at);
        assert_eq!(found.last_used_at, created.last_used_at);

        // Re-revoking overwrites the timestamps (no filter in Go).
        let again = at + Duration::hours(1);
        clock.set(again);
        repo.revoke_by_id(&created.id).await.unwrap();
        assert_eq!(
            repo.find_by_id(&created.id).await.unwrap().revoked_at,
            Some(again)
        );

        // Unknown ID: no rows, no error.
        repo.revoke_by_id(&ChainId::new(uid(999))).await.unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn list_active_ids_filters_status_revoked_at_and_session(pool: PgPool) {
        seed_base(&pool).await;
        insert_session(&pool, &uid(11), &uid(1), "email_otp", T0).await;
        let (repo, _) = repo(pool);

        repo.create(chain(&uid(41), 10)).await.unwrap(); // active
        repo.create(chain(&uid(42), 10)).await.unwrap(); // active
        let mut revoked = chain(&uid(43), 10);
        revoked.status = RefreshTokenChainStatus::Revoked;
        revoked.revoked_at = Some(T0);
        repo.create(revoked).await.unwrap();
        let mut stamped = chain(&uid(44), 10); // active status but revoked_at set
        stamped.status = RefreshTokenChainStatus::Active;
        stamped.revoked_at = Some(T0);
        repo.create(stamped).await.unwrap();
        let mut odd = chain(&uid(45), 10); // unknown status
        odd.status = RefreshTokenChainStatus::from("expired");
        repo.create(odd).await.unwrap();
        repo.create(chain(&uid(46), 11)).await.unwrap(); // other session

        let mut ids = repo
            .list_active_ids_by_sso_session_id(&SessionId::new(uid(10)))
            .await
            .unwrap();
        ids.sort();
        assert_eq!(ids, vec![ChainId::new(uid(41)), ChainId::new(uid(42))]);

        let none = repo
            .list_active_ids_by_sso_session_id(&SessionId::new(uid(12)))
            .await
            .unwrap();
        assert!(none.is_empty());
    }
}
