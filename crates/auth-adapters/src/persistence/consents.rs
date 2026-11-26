//! `consent_grants` repository (Go `persistence.ConsentGrantRepository`).

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{AccountId, ClientId, ConsentGrant, ConsentGrantId, is_zero_time};
use auth_core::ports::{Clock, ConsentGrantRepository, IdGenerator, RepoError, RepoResult};
use sqlx::PgPool;
use time::UtcOffset;
use uuid::Uuid;

use super::common::map_err;

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

/// Parses an ID bound to a `uuid` column. GORM sent the raw string and
/// Postgres rejected malformed values with an error that was not
/// `ErrRecordNotFound`, so this is [`RepoError::Other`], never `NotFound`.
fn uuid_param(value: &str) -> RepoResult<Uuid> {
    Uuid::parse_str(value)
        .map_err(|_| RepoError::other(format!("invalid input syntax for type uuid: \"{value}\"")))
}

impl PgConsentGrantRepository {
    /// GORM `Where("account_id = ? AND client_id = ?").First`. The table has
    /// no unique constraint on the pair; with duplicates the lowest `id` wins.
    async fn first(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
    ) -> RepoResult<ConsentGrant> {
        let account = uuid_param(account_id.as_str())?;
        let row = sqlx::query!(
            r#"SELECT id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at
               FROM consent_grants
               WHERE account_id = $1 AND client_id = $2
               ORDER BY id
               LIMIT 1"#,
            account,
            client_id.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(RepoError::NotFound)?;

        Ok(ConsentGrant {
            id: ConsentGrantId::new(row.id.to_string()),
            account_id: AccountId::new(row.account_id.to_string()),
            client_id: ClientId::new(row.client_id),
            granted_scopes: row.granted_scopes,
            granted_at: row.granted_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
        })
    }

    /// Plain insert (GORM `Create`), or with `upsert` the
    /// `ON CONFLICT (id) DO UPDATE` insert GORM `Save` falls back to when its
    /// `UPDATE` matched no row.
    async fn insert(&self, grant: &ConsentGrant, upsert: bool) -> RepoResult<()> {
        let id = uuid_param(grant.id.as_str())?;
        let account = uuid_param(grant.account_id.as_str())?;
        let result = if upsert {
            sqlx::query!(
                r#"INSERT INTO consent_grants
                    (id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)
                   ON CONFLICT (id) DO UPDATE SET
                     account_id = EXCLUDED.account_id,
                     client_id = EXCLUDED.client_id,
                     granted_scopes = EXCLUDED.granted_scopes,
                     granted_at = EXCLUDED.granted_at,
                     last_used_at = EXCLUDED.last_used_at,
                     revoked_at = EXCLUDED.revoked_at"#,
                id,
                account,
                grant.client_id.as_str(),
                grant.granted_scopes,
                grant.granted_at,
                grant.last_used_at,
                grant.revoked_at,
            )
            .execute(&self.pool)
            .await
        } else {
            sqlx::query!(
                r#"INSERT INTO consent_grants
                    (id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
                id,
                account,
                grant.client_id.as_str(),
                grant.granted_scopes,
                grant.granted_at,
                grant.last_used_at,
                grant.revoked_at,
            )
            .execute(&self.pool)
            .await
        };
        result.map_err(map_err)?;
        Ok(())
    }
}

#[async_trait]
impl ConsentGrantRepository for PgConsentGrantRepository {
    async fn find_by_account_and_client(
        &self,
        account_id: &AccountId,
        client_id: &ClientId,
    ) -> RepoResult<ConsentGrant> {
        self.first(account_id, client_id).await
    }

    /// Go `Upsert`, statement for statement (no transaction, like Go):
    ///
    /// - No row for (account, client): insert `grant`, defaulting an empty ID
    ///   and zero `granted_at`/`last_used_at` to generated ID / clock time.
    ///   `revoked_at` is stored as given.
    /// - Otherwise, on the first row (lowest `id`): replace `granted_scopes`
    ///   with `grant.granted_scopes`, set `last_used_at` to the clock time and
    ///   `revoked_at` to `grant.revoked_at` (so `None` un-revokes), keep its
    ///   `id`, `granted_at`, `account_id` and `client_id`; then GORM `Save`.
    ///
    /// Scope union with the existing grant happens in the flow service
    /// (`UpsertConsent`), not here.
    async fn upsert(&self, mut grant: ConsentGrant) -> RepoResult<ConsentGrant> {
        let now = self.clock.now().to_offset(UtcOffset::UTC);

        let mut existing = match self.first(&grant.account_id, &grant.client_id).await {
            Ok(existing) => existing,
            Err(RepoError::NotFound) => {
                if grant.id.is_empty() {
                    grant.id = ConsentGrantId::new(self.ids.new_id());
                }
                if is_zero_time(grant.granted_at) {
                    grant.granted_at = now;
                }
                if is_zero_time(grant.last_used_at) {
                    grant.last_used_at = now;
                }
                self.insert(&grant, false).await?;
                return Ok(grant);
            }
            Err(error) => return Err(error),
        };

        existing.granted_scopes = grant.granted_scopes;
        existing.last_used_at = now;
        existing.revoked_at = grant.revoked_at;

        let id = uuid_param(existing.id.as_str())?;
        let account = uuid_param(existing.account_id.as_str())?;
        let result = sqlx::query!(
            r#"UPDATE consent_grants SET
                 account_id = $2,
                 client_id = $3,
                 granted_scopes = $4,
                 granted_at = $5,
                 last_used_at = $6,
                 revoked_at = $7
               WHERE id = $1"#,
            id,
            account,
            existing.client_id.as_str(),
            existing.granted_scopes,
            existing.granted_at,
            existing.last_used_at,
            existing.revoked_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if result.rows_affected() == 0 {
            // Row deleted between the read and the update: GORM Save re-inserts.
            self.insert(&existing, true).await?;
        }
        Ok(existing)
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
    async fn upsert_updates_existing_row_like_go(pool: PgPool) {
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
    async fn duplicates_resolve_to_lowest_id(pool: PgPool) {
        seed(&pool).await;
        let repo = repo(pool);
        for (id, scopes) in [
            ("01900000-0000-7000-8000-0000000000f2", "second"),
            ("01900000-0000-7000-8000-0000000000f1", "first"),
        ] {
            sqlx::query(
                "INSERT INTO consent_grants (id, account_id, client_id, granted_scopes, granted_at, last_used_at)
                 VALUES ($1, $2, 'demo-web', $3, now(), now())",
            )
            .bind(Uuid::parse_str(id).unwrap())
            .bind(Uuid::parse_str(ACCOUNT).unwrap())
            .bind(scopes)
            .execute(&repo.pool)
            .await
            .unwrap();
        }
        let (account, client) = ids();
        let found = repo
            .find_by_account_and_client(&account, &client)
            .await
            .unwrap();
        assert_eq!(found.granted_scopes, "first");

        let saved = repo.upsert(grant("updated")).await.unwrap();
        assert_eq!(saved.id.as_str(), "01900000-0000-7000-8000-0000000000f1");
        let second: String = sqlx::query_scalar(
            "SELECT granted_scopes FROM consent_grants WHERE id = '01900000-0000-7000-8000-0000000000f2'",
        )
        .fetch_one(&repo.pool)
        .await
        .unwrap();
        assert_eq!(second, "second");
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
