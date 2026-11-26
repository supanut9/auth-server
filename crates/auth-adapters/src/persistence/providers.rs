//! `account_providers` repository
//! (`internal/adapter/out/persistence/provider_repository.go`).

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{AccountId, AccountProvider, AccountProviderId};
use auth_core::ports::{AccountProviderRepository, Clock, IdGenerator, RepoResult};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::accounts::{now_utc, parse_uuid};
use super::common::map_err;

/// Postgres-backed [`AccountProviderRepository`].
#[derive(Clone)]
pub struct PgAccountProviderRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgAccountProviderRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

struct AccountProviderRow {
    id: Uuid,
    account_id: Uuid,
    provider: String,
    provider_account_id: String,
    provider_email: String,
    provider_email_verified: bool,
    profile_name: String,
    profile_avatar_url: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<AccountProviderRow> for AccountProvider {
    fn from(row: AccountProviderRow) -> Self {
        Self {
            id: AccountProviderId::new(row.id.to_string()),
            account_id: AccountId::new(row.account_id.to_string()),
            provider: row.provider,
            provider_account_id: row.provider_account_id,
            provider_email: row.provider_email,
            provider_email_verified: row.provider_email_verified,
            profile_name: row.profile_name,
            profile_avatar_url: row.profile_avatar_url,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl AccountProviderRepository for PgAccountProviderRepository {
    /// Go always stamps both timestamps with the clock, ignoring the input.
    async fn create(&self, mut provider: AccountProvider) -> RepoResult<AccountProvider> {
        let now = now_utc(&*self.clock);
        if provider.id.is_empty() {
            provider.id = AccountProviderId::new(self.ids.new_id());
        }
        provider.created_at = now;
        provider.updated_at = now;

        let id = parse_uuid(provider.id.as_str())?;
        let account_id = parse_uuid(provider.account_id.as_str())?;
        sqlx::query!(
            r#"INSERT INTO account_providers
                (id, account_id, provider, provider_account_id, provider_email,
                 provider_email_verified, profile_name, profile_avatar_url, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
            id,
            account_id,
            provider.provider,
            provider.provider_account_id,
            provider.provider_email,
            provider.provider_email_verified,
            provider.profile_name,
            provider.profile_avatar_url,
            provider.created_at,
            provider.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(provider)
    }

    async fn find_by_provider_account_id(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> RepoResult<AccountProvider> {
        sqlx::query_as!(
            AccountProviderRow,
            r#"SELECT id, account_id, provider, provider_account_id, provider_email,
                      provider_email_verified, profile_name, profile_avatar_url, created_at, updated_at
               FROM account_providers
               WHERE provider = $1 AND provider_account_id = $2
               ORDER BY id LIMIT 1"#,
            provider,
            provider_account_id,
        )
        .fetch_one(&self.pool)
        .await
        .map(AccountProvider::from)
        .map_err(map_err)
    }

    async fn find_by_account_id_and_provider(
        &self,
        account_id: &AccountId,
        provider: &str,
    ) -> RepoResult<AccountProvider> {
        let account_id = parse_uuid(account_id.as_str())?;
        sqlx::query_as!(
            AccountProviderRow,
            r#"SELECT id, account_id, provider, provider_account_id, provider_email,
                      provider_email_verified, profile_name, profile_avatar_url, created_at, updated_at
               FROM account_providers
               WHERE account_id = $1 AND provider = $2
               ORDER BY id LIMIT 1"#,
            account_id,
            provider,
        )
        .fetch_one(&self.pool)
        .await
        .map(AccountProvider::from)
        .map_err(map_err)
    }
}

#[cfg(test)]
mod tests {
    use auth_core::domain::Account;
    use auth_core::ports::{AccountRepository, RepoError};
    use time::Duration;

    use super::super::accounts::PgAccountRepository;
    use super::super::accounts::test_support::{T0, TestClock, TestIds};
    use super::*;

    async fn setup(pool: PgPool) -> (PgAccountProviderRepository, Account) {
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
        (PgAccountProviderRepository::new(pool, clock, ids), account)
    }

    fn link(account: &Account, provider: &str, subject: &str) -> AccountProvider {
        AccountProvider {
            account_id: account.id.clone(),
            provider: provider.into(),
            provider_account_id: subject.into(),
            provider_email: "ada@example.com".into(),
            provider_email_verified: true,
            profile_name: "Ada".into(),
            profile_avatar_url: "https://example.com/a.png".into(),
            ..AccountProvider::default()
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_assigns_id_and_timestamps(pool: PgPool) {
        let (repo, account) = setup(pool).await;
        let input = AccountProvider {
            created_at: T0 - Duration::days(1),
            ..link(&account, "google", "g-1")
        };
        let created = repo.create(input).await.unwrap();
        // ID 1 went to the account.
        assert_eq!(created.id, "01900000-0000-7000-8000-000000000002");
        assert_eq!(created.created_at, T0);
        assert_eq!(created.updated_at, T0);
        assert_eq!(
            repo.find_by_provider_account_id("google", "g-1")
                .await
                .unwrap(),
            created
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_duplicate_subject_is_conflict(pool: PgPool) {
        let (repo, account) = setup(pool).await;
        repo.create(link(&account, "google", "g-1")).await.unwrap();
        let err = repo
            .create(link(&account, "google", "g-1"))
            .await
            .unwrap_err();
        assert!(err.is_conflict(), "{err:?}");
        // Same subject under another provider is fine.
        repo.create(link(&account, "github", "g-1")).await.unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_for_unknown_account_is_other(pool: PgPool) {
        let (repo, _) = setup(pool).await;
        let ghost = Account {
            id: AccountId::new("0190ffff-0000-7000-8000-000000000001"),
            ..Account::default()
        };
        let err = repo
            .create(link(&ghost, "google", "g-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "FK violation: {err:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_provider_account_id_is_exact(pool: PgPool) {
        let (repo, account) = setup(pool).await;
        repo.create(link(&account, "google", "Sub-1"))
            .await
            .unwrap();
        for (provider, subject) in [
            ("google", "sub-1"),
            ("Google", "Sub-1"),
            ("github", "Sub-1"),
        ] {
            let err = repo
                .find_by_provider_account_id(provider, subject)
                .await
                .unwrap_err();
            assert!(err.is_not_found(), "{provider}/{subject}");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_account_id_and_provider_returns_oldest(pool: PgPool) {
        let (repo, account) = setup(pool).await;
        let first = repo.create(link(&account, "github", "gh-1")).await.unwrap();
        repo.create(link(&account, "github", "gh-2")).await.unwrap();
        let found = repo
            .find_by_account_id_and_provider(&account.id, "github")
            .await
            .unwrap();
        assert_eq!(found, first, "GORM First orders by id");

        let missing = repo
            .find_by_account_id_and_provider(&account.id, "google")
            .await
            .unwrap_err();
        assert!(missing.is_not_found());
        let malformed = repo
            .find_by_account_id_and_provider(&AccountId::new("x"), "github")
            .await
            .unwrap_err();
        assert!(matches!(malformed, RepoError::Other(_)));
    }
}
