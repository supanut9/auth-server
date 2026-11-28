//! `consent_grants` repository (Go `persistence.ConsentGrantRepository`).

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{AccountId, ClientId, ConsentGrant, ConsentGrantId, is_zero_time};
use auth_core::ports::{Clock, ConsentGrantRepository, IdGenerator, RepoResult};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::common::{map_err, now_utc, parse_uuid};

/// Postgres-backed [`ConsentGrantRepository`].
pub struct PgConsentGrantRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgConsentGrantRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

struct ConsentGrantRow {
    id: Uuid,
    account_id: Uuid,
    client_id: String,
    granted_scopes: String,
    granted_at: OffsetDateTime,
    last_used_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

impl From<ConsentGrantRow> for ConsentGrant {
    fn from(row: ConsentGrantRow) -> Self {
        Self {
            id: ConsentGrantId::new(row.id.to_string()),
            account_id: AccountId::new(row.account_id.to_string()),
            client_id: ClientId::new(row.client_id),
            granted_scopes: row.granted_scopes,
            granted_at: row.granted_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[async_trait]
impl ConsentGrantRepository for PgConsentGrantRepository {
    async fn find_by_account_and_client(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
    ) -> RepoResult<ConsentGrant> {
        let account = parse_uuid(account_id.as_str())?;
        sqlx::query_as!(
            ConsentGrantRow,
            r#"SELECT id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at
               FROM consent_grants
               WHERE account_id = $1 AND client_id = $2"#,
            account,
            client_id.as_str(),
        )
        .fetch_one(&self.pool)
        .await
        .map(Into::into)
        .map_err(map_err)
    }

    async fn upsert(&self, mut grant: ConsentGrant) -> RepoResult<ConsentGrant> {
        let account = parse_uuid(grant.account_id.as_str())?;
        let now = now_utc(&*self.clock);
        if grant.id.is_empty() {
            grant.id = ConsentGrantId::new(self.ids.new_id());
        }
        if is_zero_time(grant.granted_at) {
            grant.granted_at = now;
        }
        if is_zero_time(grant.last_used_at) {
            grant.last_used_at = now;
        }

        // The flow service supplies the merged scope set.
        let id = parse_uuid(grant.id.as_str())?;
        sqlx::query_as!(
            ConsentGrantRow,
            r#"INSERT INTO consent_grants
                (id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (account_id, client_id) DO UPDATE SET
                 granted_scopes = EXCLUDED.granted_scopes,
                 last_used_at = $8,
                 revoked_at = NULL
               RETURNING id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at"#,
            id,
            account,
            grant.client_id.as_str(),
            grant.granted_scopes,
            grant.granted_at,
            grant.last_used_at,
            grant.revoked_at,
            now,
        )
        .fetch_one(&self.pool)
        .await
        .map(Into::into)
        .map_err(map_err)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use auth_core::ports::RepoError;
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-05-16 12:00:00.123456 UTC);
    const ACCOUNT: &str = "01900000-0000-7000-8000-00000000a001";

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

    fn repo(pool: PgPool) -> PgConsentGrantRepository {
        PgConsentGrantRepository::new(
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
    }

    fn grant(scopes: &str) -> ConsentGrant {
        ConsentGrant {
            account_id: AccountId::new(ACCOUNT),
            client_id: ClientId::new("demo-web"),
            granted_scopes: scopes.into(),
            ..ConsentGrant::default()
        }
    }

    fn ids() -> (AccountId, ClientId) {
        (AccountId::new(ACCOUNT), ClientId::new("demo-web"))
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn first_upsert_inserts_with_defaults(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let created = repo.upsert(grant("openid")).await.unwrap();
        assert_eq!(created.id.as_str(), "01900000-0000-7000-8000-000000000001");
        assert_eq!(created.granted_at, NOW);
        assert_eq!(created.last_used_at, NOW);
        assert_eq!(created.revoked_at, None);

        let (account, client) = ids();
        let found = repo
            .find_by_account_and_client(&account, &client)
            .await
            .unwrap();
        assert_eq!(found, created);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn insert_keeps_explicit_times_and_revoked_at(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let mut input = grant("openid");
        input.granted_at = datetime!(2026-01-01 0:00 UTC);
        input.last_used_at = datetime!(2026-02-01 0:00 UTC);
        input.revoked_at = Some(datetime!(2026-03-01 0:00 UTC));
        let created = repo.upsert(input.clone()).await.unwrap();
        assert_eq!(created.granted_at, input.granted_at);
        assert_eq!(created.last_used_at, input.last_used_at);
        assert_eq!(created.revoked_at, input.revoked_at);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn upsert_updates_existing_row_and_clears_revocation(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let granted_at = datetime!(2026-01-01 0:00 UTC);
        sqlx::query(
            "INSERT INTO consent_grants (id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at)
             VALUES ('01900000-0000-7000-8000-0000000000aa', $1, 'demo-web', 'openid', $2, $2, $2)",
        )
        .bind(Uuid::parse_str(ACCOUNT).unwrap())
        .bind(granted_at)
        .execute(&repo.pool)
        .await
        .unwrap();

        // The service passes the unioned scope set, the existing ID and
        // granted_at, and no revoked_at. A different ID / granted_at in the
        // input is ignored by the repository.
        let mut input = grant("email openid profile");
        input.id = ConsentGrantId::new("01900000-0000-7000-8000-0000000000bb");
        input.granted_at = datetime!(2026-04-01 0:00 UTC);
        input.last_used_at = input.granted_at;
        input.revoked_at = Some(input.granted_at);
        let saved = repo.upsert(input).await.unwrap();

        assert_eq!(saved.id.as_str(), "01900000-0000-7000-8000-0000000000aa");
        assert_eq!(saved.granted_scopes, "email openid profile");
        assert_eq!(saved.granted_at, granted_at, "granted_at kept");
        assert_eq!(saved.last_used_at, NOW);
        assert_eq!(saved.revoked_at, None, "un-revoked");

        let (account, client) = ids();
        assert_eq!(
            repo.find_by_account_and_client(&account, &client)
                .await
                .unwrap(),
            saved
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM consent_grants")
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn repository_replaces_scopes_without_union(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        repo.upsert(grant("email openid")).await.unwrap();
        let saved = repo.upsert(grant("profile")).await.unwrap();
        assert_eq!(saved.granted_scopes, "profile");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn concurrent_upserts_write_one_grant(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        let (first, second) =
            tokio::join!(repo.upsert(grant("openid")), repo.upsert(grant("email")));
        assert_eq!(first.unwrap().id, second.unwrap().id);

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM consent_grants")
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn missing_grant_is_not_found(pool: PgPool) {
        let (account, client) = ids();
        let err = repo(pool)
            .find_by_account_and_client(&account, &client)
            .await
            .unwrap_err();
        assert!(err.is_not_found());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn malformed_account_id_is_other_error(pool: PgPool) {
        let repo = repo(pool);
        let err = repo
            .find_by_account_and_client(&AccountId::new("nope"), &ClientId::new("demo-web"))
            .await
            .unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");

        let mut input = grant("openid");
        input.account_id = AccountId::new("nope");
        let err = repo.upsert(input).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
    }
}
