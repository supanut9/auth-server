//! `refresh_tokens` repository
//! (`internal/adapter/out/persistence/refresh_token_repository.go`).
//!
//! Like Go, this repository has no clock: `revoke_by_chain_id` stamps
//! `revoked_at` with the database's `NOW()` (transaction start time).

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{ChainId, RefreshToken, RefreshTokenId};
use auth_core::ports::{IdGenerator, RefreshTokenRepository, RepoError, RepoResult};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::common::map_err;
use super::common::parse_uuid;

struct TokenRow {
    id: Uuid,
    refresh_token_chain_id: Uuid,
    token_hash: String,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    used_at: Option<OffsetDateTime>,
    replaced_by_token_id: Option<Uuid>,
    revoked_at: Option<OffsetDateTime>,
}

impl From<TokenRow> for RefreshToken {
    fn from(row: TokenRow) -> Self {
        Self {
            id: RefreshTokenId::new(row.id.to_string()),
            refresh_token_chain_id: ChainId::new(row.refresh_token_chain_id.to_string()),
            token_hash: row.token_hash,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            used_at: row.used_at,
            replaced_by_token_id: row
                .replaced_by_token_id
                .map(|id| RefreshTokenId::new(id.to_string())),
            revoked_at: row.revoked_at,
        }
    }
}

/// Postgres [`RefreshTokenRepository`]. Go's constructor takes only an ID
/// generator, so there is no clock here.
#[derive(Clone)]
pub struct PgRefreshTokenRepository {
    pool: PgPool,
    ids: Arc<dyn IdGenerator>,
}

impl PgRefreshTokenRepository {
    #[must_use]
    pub fn new(pool: PgPool, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, ids }
    }
}

fn optional_uuid(value: Option<&RefreshTokenId>) -> RepoResult<Option<Uuid>> {
    value.map(|id| parse_uuid(id.as_str())).transpose()
}

#[async_trait]
impl RefreshTokenRepository for PgRefreshTokenRepository {
    async fn create(&self, mut token: RefreshToken) -> RepoResult<RefreshToken> {
        if token.id.is_empty() {
            token.id = RefreshTokenId::new(self.ids.new_id());
        }

        sqlx::query!(
            r#"INSERT INTO refresh_tokens (
                   id, refresh_token_chain_id, token_hash, issued_at, expires_at,
                   used_at, replaced_by_token_id, revoked_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
            parse_uuid(token.id.as_str())?,
            parse_uuid(token.refresh_token_chain_id.as_str())?,
            token.token_hash,
            token.issued_at,
            token.expires_at,
            token.used_at,
            optional_uuid(token.replaced_by_token_id.as_ref())?,
            token.revoked_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(token)
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> RepoResult<RefreshToken> {
        // GORM `First`: ORDER BY primary key LIMIT 1.
        sqlx::query_as!(
            TokenRow,
            r#"SELECT id, refresh_token_chain_id, token_hash, issued_at, expires_at,
                      used_at, replaced_by_token_id, revoked_at
               FROM refresh_tokens
               WHERE token_hash = $1
               ORDER BY id
               LIMIT 1"#,
            token_hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(RefreshToken::from)
        .ok_or(RepoError::NotFound)
    }

    async fn update(&self, token: RefreshToken) -> RepoResult<RefreshToken> {
        // GORM `Save`: UPDATE every column by primary key, INSERT when no row
        // matched. The model has no UpdatedAt, so nothing is auto-stamped.
        sqlx::query!(
            r#"INSERT INTO refresh_tokens (
                   id, refresh_token_chain_id, token_hash, issued_at, expires_at,
                   used_at, replaced_by_token_id, revoked_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (id) DO UPDATE SET
                   refresh_token_chain_id = EXCLUDED.refresh_token_chain_id,
                   token_hash = EXCLUDED.token_hash,
                   issued_at = EXCLUDED.issued_at,
                   expires_at = EXCLUDED.expires_at,
                   used_at = EXCLUDED.used_at,
                   replaced_by_token_id = EXCLUDED.replaced_by_token_id,
                   revoked_at = EXCLUDED.revoked_at"#,
            parse_uuid(token.id.as_str())?,
            parse_uuid(token.refresh_token_chain_id.as_str())?,
            token.token_hash,
            token.issued_at,
            token.expires_at,
            token.used_at,
            optional_uuid(token.replaced_by_token_id.as_ref())?,
            token.revoked_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(token)
    }

    async fn revoke_by_chain_id(&self, chain_id: &ChainId) -> RepoResult<()> {
        let chain_id = parse_uuid(chain_id.as_str())?;
        // Go: Update("revoked_at", gorm.Expr("NOW()")) with no revoked_at
        // filter, so already revoked tokens get a fresh timestamp too.
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE refresh_token_chain_id = $1",
            chain_id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use auth_core::domain::{
        AccountId, ChainId, ClientId, RefreshToken, RefreshTokenChain, RefreshTokenChainStatus,
        RefreshTokenId, SessionId,
    };
    use auth_core::ports::{RefreshTokenChainRepository, RefreshTokenRepository, RepoError};
    use sqlx::PgPool;
    use time::{Duration, OffsetDateTime};

    use super::PgRefreshTokenRepository;
    use crate::persistence::chains::PgRefreshTokenChainRepository;
    use crate::persistence::chains::test_support::{FixedClock, SeqIds, T0, seed_base, uid};

    async fn seed_chain(pool: &PgPool, id: u128) {
        let chains = PgRefreshTokenChainRepository::new(
            pool.clone(),
            Arc::new(FixedClock::new(T0)),
            Arc::new(SeqIds::new(900)),
        );
        chains
            .create(RefreshTokenChain {
                id: ChainId::new(uid(id)),
                account_id: AccountId::new(uid(1)),
                client_id: ClientId::new("client-a"),
                sso_session_id: SessionId::new(uid(10)),
                scope: "openid".into(),
                device_session_id: "device-1".into(),
                status: RefreshTokenChainStatus::Active,
                absolute_expires_at: T0 + Duration::days(30),
                inactive_expires_at: T0 + Duration::days(7),
                last_used_at: T0,
                ..RefreshTokenChain::default()
            })
            .await
            .unwrap();
    }

    fn token(id: &str, chain: u128, hash: &str) -> RefreshToken {
        RefreshToken {
            id: RefreshTokenId::new(id),
            refresh_token_chain_id: ChainId::new(uid(chain)),
            token_hash: hash.into(),
            issued_at: T0,
            expires_at: T0 + Duration::days(30),
            ..RefreshToken::default()
        }
    }

    fn repo(pool: PgPool) -> PgRefreshTokenRepository {
        PgRefreshTokenRepository::new(pool, Arc::new(SeqIds::new(700)))
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_assigns_id_and_round_trips(pool: PgPool) {
        seed_base(&pool).await;
        seed_chain(&pool, 40).await;
        let repo = repo(pool);

        let created = repo.create(token("", 40, "hash-1")).await.unwrap();
        assert_eq!(created.id, uid(700).as_str());
        assert_eq!(created.used_at, None);
        assert_eq!(repo.find_by_token_hash("hash-1").await.unwrap(), created);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_by_token_hash_missing_is_not_found(pool: PgPool) {
        let err = repo(pool).find_by_token_hash("nope").await.unwrap_err();
        assert!(err.is_not_found(), "{err}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn duplicate_hash_is_conflict(pool: PgPool) {
        seed_base(&pool).await;
        seed_chain(&pool, 40).await;
        let repo = repo(pool);
        repo.create(token("", 40, "hash-1")).await.unwrap();
        let err = repo.create(token("", 40, "hash-1")).await.unwrap_err();
        assert!(err.is_conflict(), "{err:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn malformed_chain_id_is_other_error(pool: PgPool) {
        let repo = repo(pool);
        let err = repo
            .revoke_by_chain_id(&ChainId::new("chain-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
        let err = repo.create(token("token-1", 40, "h")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
        // A well-formed but unknown chain ID fails the foreign key instead.
        let err = repo.create(token("", 40, "h")).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn update_rotates_token(pool: PgPool) {
        seed_base(&pool).await;
        seed_chain(&pool, 40).await;
        let repo = repo(pool);
        let old = repo.create(token(&uid(201), 40, "hash-old")).await.unwrap();
        let new = repo.create(token(&uid(202), 40, "hash-new")).await.unwrap();

        let used = T0 + Duration::minutes(1);
        let mut rotated = old.clone();
        rotated.used_at = Some(used);
        rotated.replaced_by_token_id = Some(new.id.clone());
        let saved = repo.update(rotated.clone()).await.unwrap();
        assert_eq!(saved, rotated);
        assert_eq!(repo.find_by_token_hash("hash-old").await.unwrap(), rotated);

        // Save writes zero values too: clearing the pointer clears the column.
        let mut cleared = rotated.clone();
        cleared.replaced_by_token_id = None;
        cleared.used_at = None;
        repo.update(cleared.clone()).await.unwrap();
        assert_eq!(repo.find_by_token_hash("hash-old").await.unwrap(), cleared);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoke_by_chain_id_uses_db_now_and_touches_only_that_chain(pool: PgPool) {
        seed_base(&pool).await;
        seed_chain(&pool, 40).await;
        seed_chain(&pool, 41).await;
        let repo = repo(pool.clone());
        let mut already = token(&uid(201), 40, "hash-a");
        already.revoked_at = Some(T0 - Duration::days(1));
        repo.create(already).await.unwrap();
        repo.create(token(&uid(202), 40, "hash-b")).await.unwrap();
        repo.create(token(&uid(203), 41, "hash-c")).await.unwrap();

        let before = OffsetDateTime::now_utc() - Duration::minutes(1);
        repo.revoke_by_chain_id(&ChainId::new(uid(40)))
            .await
            .unwrap();

        for hash in ["hash-a", "hash-b"] {
            let revoked_at = repo
                .find_by_token_hash(hash)
                .await
                .unwrap()
                .revoked_at
                .unwrap();
            // DB NOW(), not the fixed test clock (T0 is in the past).
            assert!(revoked_at > before, "{hash}: {revoked_at}");
        }
        assert_eq!(
            repo.find_by_token_hash("hash-c").await.unwrap().revoked_at,
            None
        );

        // A chain with no tokens is not an error.
        repo.revoke_by_chain_id(&ChainId::new(uid(999)))
            .await
            .unwrap();
    }
}
