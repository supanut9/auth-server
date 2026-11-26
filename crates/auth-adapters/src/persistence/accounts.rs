//! `accounts` repository (`internal/adapter/out/persistence/account_repository.go`).
//!
//! Also holds the small helpers the B1 repositories share (UUID parsing and
//! the UTC clock read) plus their test fixtures.

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{Account, AccountId, AccountStatus, is_zero_time};
use auth_core::ports::{AccountRepository, Clock, IdGenerator, RepoResult};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::common::{map_err, now_utc, parse_uuid};

/// Postgres-backed [`AccountRepository`].
#[derive(Clone)]
pub struct PgAccountRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgAccountRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

struct AccountRow {
    id: Uuid,
    primary_verified_email: String,
    display_name: String,
    avatar_url: String,
    status: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<AccountRow> for Account {
    fn from(row: AccountRow) -> Self {
        Self {
            id: AccountId::new(row.id.to_string()),
            primary_verified_email: row.primary_verified_email,
            display_name: row.display_name,
            avatar_url: row.avatar_url,
            status: AccountStatus::from(row.status),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl AccountRepository for PgAccountRepository {
    /// Go always stamps both timestamps with the clock, ignoring the input.
    async fn create(&self, mut account: Account) -> RepoResult<Account> {
        let now = now_utc(&*self.clock);
        if account.id.is_empty() {
            account.id = AccountId::new(self.ids.new_id());
        }
        if account.status.is_empty() {
            account.status = AccountStatus::Active;
        }
        account.created_at = now;
        account.updated_at = now;

        let id = parse_uuid(account.id.as_str())?;
        sqlx::query!(
            r#"INSERT INTO accounts
                (id, primary_verified_email, display_name, avatar_url, status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            id,
            account.primary_verified_email,
            account.display_name,
            account.avatar_url,
            account.status.as_str(),
            account.created_at,
            account.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(account)
    }

    async fn find_by_id(&self, id: &AccountId) -> RepoResult<Account> {
        let id = parse_uuid(id.as_str())?;
        sqlx::query_as!(
            AccountRow,
            r#"SELECT id, primary_verified_email, display_name, avatar_url, status, created_at, updated_at
               FROM accounts WHERE id = $1 ORDER BY id LIMIT 1"#,
            id,
        )
        .fetch_one(&self.pool)
        .await
        .map(Account::from)
        .map_err(map_err)
    }

    /// Exact (case-sensitive) match, like Go's `primary_verified_email = ?`.
    async fn find_by_primary_verified_email(&self, email: &str) -> RepoResult<Account> {
        sqlx::query_as!(
            AccountRow,
            r#"SELECT id, primary_verified_email, display_name, avatar_url, status, created_at, updated_at
               FROM accounts WHERE primary_verified_email = $1 ORDER BY id LIMIT 1"#,
            email,
        )
        .fetch_one(&self.pool)
        .await
        .map(Account::from)
        .map_err(map_err)
    }

    /// GORM `Save`: update every column by ID (status is not defaulted and
    /// `created_at` is written as given); when no row matched, insert it with
    /// `ON CONFLICT (id) DO UPDATE` and a zero `created_at` set to now.
    async fn update(&self, mut account: Account) -> RepoResult<Account> {
        let now = now_utc(&*self.clock);
        account.updated_at = now;
        let id = parse_uuid(account.id.as_str())?;

        let updated = sqlx::query!(
            r#"UPDATE accounts
               SET primary_verified_email = $2, display_name = $3, avatar_url = $4,
                   status = $5, created_at = $6, updated_at = $7
               WHERE id = $1"#,
            id,
            account.primary_verified_email,
            account.display_name,
            account.avatar_url,
            account.status.as_str(),
            account.created_at,
            account.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        if updated.rows_affected() > 0 {
            return Ok(account);
        }

        if is_zero_time(account.created_at) {
            account.created_at = now;
        }
        sqlx::query!(
            r#"INSERT INTO accounts
                (id, primary_verified_email, display_name, avatar_url, status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (id) DO UPDATE SET
                   primary_verified_email = EXCLUDED.primary_verified_email,
                   display_name = EXCLUDED.display_name,
                   avatar_url = EXCLUDED.avatar_url,
                   status = EXCLUDED.status,
                   updated_at = EXCLUDED.updated_at"#,
            id,
            account.primary_verified_email,
            account.display_name,
            account.avatar_url,
            account.status.as_str(),
            account.created_at,
            account.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(account)
    }
}

/// Deterministic clock and ID generator shared by the B1 repository tests.
#[cfg(test)]
pub(super) mod test_support {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{Arc, Clock, IdGenerator, OffsetDateTime};
    use time::Duration;
    use time::macros::datetime;

    /// Microsecond-aligned so values survive a `timestamptz` round trip.
    pub const T0: OffsetDateTime = datetime!(2026-05-01 10:00:00.123456 UTC);

    pub struct TestClock(Mutex<OffsetDateTime>);

    impl TestClock {
        pub fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(T0)))
        }

        pub fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    /// Increasing UUIDv7-shaped IDs, so `ORDER BY id` follows creation order.
    pub struct TestIds(AtomicU64);

    impl TestIds {
        pub fn new() -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(1)))
        }
    }

    impl IdGenerator for TestIds {
        fn new_id(&self) -> String {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            format!("01900000-0000-7000-8000-{n:012x}")
        }
    }
}

#[cfg(test)]
mod tests {
    use auth_core::domain::ZERO_TIME;
    use auth_core::ports::RepoError;
    use time::Duration;

    use super::test_support::{T0, TestClock, TestIds};
    use super::*;

    fn repo(pool: PgPool) -> (PgAccountRepository, Arc<TestClock>) {
        let clock = TestClock::new();
        (
            PgAccountRepository::new(pool, clock.clone(), TestIds::new()),
            clock,
        )
    }

    fn account(email: &str) -> Account {
        Account {
            primary_verified_email: email.into(),
            display_name: "Ada".into(),
            ..Account::default()
        }
    }

    #[test]
    fn parse_uuid_rejects_malformed_ids_like_postgres() {
        assert!(parse_uuid("01900000-0000-7000-8000-000000000001").is_ok());
        assert!(parse_uuid("{01900000-0000-7000-8000-000000000001}").is_ok());
        for bad in ["", "abc", "urn:uuid:01900000-0000-7000-8000-000000000001"] {
            let err = parse_uuid(bad).unwrap_err();
            assert!(!err.is_not_found());
            assert_eq!(
                err.to_string(),
                format!("ERROR: invalid input syntax for type uuid: \"{bad}\" (SQLSTATE 22P02)")
            );
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_applies_go_defaults(pool: PgPool) {
        let (repo, _) = repo(pool);
        let input = Account {
            created_at: T0 - Duration::days(3),
            updated_at: T0 - Duration::days(2),
            ..account("ada@example.com")
        };
        let created = repo.create(input).await.unwrap();
        assert_eq!(created.id, "01900000-0000-7000-8000-000000000001");
        assert_eq!(created.status, AccountStatus::Active);
        assert_eq!(created.created_at, T0, "input timestamps are ignored");
        assert_eq!(created.updated_at, T0);
        assert_eq!(repo.find_by_id(&created.id).await.unwrap(), created);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_keeps_given_id_and_status(pool: PgPool) {
        let (repo, _) = repo(pool);
        let input = Account {
            id: AccountId::new("0190aaaa-0000-7000-8000-000000000001"),
            status: AccountStatus::from("suspended"),
            ..account("ada@example.com")
        };
        let created = repo.create(input).await.unwrap();
        assert_eq!(created.id, "0190aaaa-0000-7000-8000-000000000001");
        assert_eq!(created.status.as_str(), "suspended");
        assert_eq!(repo.find_by_id(&created.id).await.unwrap(), created);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_duplicate_email_is_conflict(pool: PgPool) {
        let (repo, _) = repo(pool);
        repo.create(account("ada@example.com")).await.unwrap();
        let err = repo.create(account("ada@example.com")).await.unwrap_err();
        assert!(err.is_conflict(), "{err:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_malformed_id_is_other(pool: PgPool) {
        let (repo, _) = repo(pool);
        let input = Account {
            id: AccountId::new("not-a-uuid"),
            ..account("ada@example.com")
        };
        let err = repo.create(input).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_id_not_found_and_malformed(pool: PgPool) {
        let (repo, _) = repo(pool);
        let missing = repo
            .find_by_id(&AccountId::new("01900000-0000-7000-8000-0000000000ff"))
            .await
            .unwrap_err();
        assert!(missing.is_not_found());
        let malformed = repo.find_by_id(&AccountId::new("nope")).await.unwrap_err();
        assert!(matches!(malformed, RepoError::Other(_)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_email_is_exact_match(pool: PgPool) {
        let (repo, _) = repo(pool);
        let created = repo.create(account("Ada@Example.com")).await.unwrap();
        assert_eq!(
            repo.find_by_primary_verified_email("Ada@Example.com")
                .await
                .unwrap(),
            created
        );
        let err = repo
            .find_by_primary_verified_email("ada@example.com")
            .await
            .unwrap_err();
        assert!(err.is_not_found());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_writes_all_columns_and_stamps_updated_at(pool: PgPool) {
        let (repo, clock) = repo(pool);
        let mut current = repo.create(account("ada@example.com")).await.unwrap();
        clock.advance(Duration::minutes(5));
        current.display_name = "Ada L".into();
        current.avatar_url = "https://example.com/a.png".into();
        current.status = AccountStatus::default();
        let updated = repo.update(current.clone()).await.unwrap();
        assert_eq!(updated.updated_at, T0 + Duration::minutes(5));
        assert_eq!(updated.created_at, T0);
        assert!(updated.status.is_empty(), "update does not default status");
        assert_eq!(repo.find_by_id(&updated.id).await.unwrap(), updated);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_missing_row_inserts_like_gorm_save(pool: PgPool) {
        let (repo, _) = repo(pool);
        let input = Account {
            id: AccountId::new("0190bbbb-0000-7000-8000-000000000001"),
            status: AccountStatus::Active,
            created_at: ZERO_TIME,
            ..account("new@example.com")
        };
        let saved = repo.update(input).await.unwrap();
        assert_eq!(saved.created_at, T0);
        assert_eq!(saved.updated_at, T0);
        assert_eq!(repo.find_by_id(&saved.id).await.unwrap(), saved);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_with_empty_id_fails_without_writing(pool: PgPool) {
        let (repo, _) = repo(pool);
        let err = repo.update(account("x@example.com")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)));
        assert!(
            repo.find_by_primary_verified_email("x@example.com")
                .await
                .unwrap_err()
                .is_not_found()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_to_taken_email_is_conflict(pool: PgPool) {
        let (repo, _) = repo(pool);
        repo.create(account("a@example.com")).await.unwrap();
        let mut second = repo.create(account("b@example.com")).await.unwrap();
        second.primary_verified_email = "a@example.com".into();
        assert!(repo.update(second).await.unwrap_err().is_conflict());
    }
}
