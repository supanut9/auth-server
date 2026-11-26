//! Support API storage (Rust-only port).
//!
//! Go's support handler (`internal/adapter/in/http/support.go`) ran these
//! queries straight against GORM. They are mirrored here query for query:
//! no transaction around the summary reads, one transaction for sign-out.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use auth_core::domain::{
    Account, AccountId, AccountStatus, ChainId, ClientId, ConsentGrant, ConsentGrantId,
    RefreshTokenChain, RefreshTokenChainStatus, SessionId, SsoSession, SsoSessionStatus,
};
use auth_core::ports::{RepoError, RepoResult, SupportAccountSummary, SupportRepository};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::chains::ChainRow;
use super::common::map_err;
use super::common::{parse_uuid, parse_uuids};

struct AccountRow {
    id: Uuid,
    primary_verified_email: String,
    display_name: String,
    avatar_url: String,
    status: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

struct SessionRow {
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

struct ConsentRow {
    id: Uuid,
    account_id: Uuid,
    client_id: String,
    granted_scopes: String,
    granted_at: OffsetDateTime,
    last_used_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

/// Postgres [`SupportRepository`]. Needs no clock: sign-out receives `now`
/// from the caller, as Go's handler computed `time.Now().UTC()` itself.
#[derive(Clone)]
pub struct PgSupportRepository {
    pool: PgPool,
}

impl PgSupportRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SupportRepository for PgSupportRepository {
    async fn load_account_summary(
        &self,
        account_id: &AccountId,
    ) -> RepoResult<SupportAccountSummary> {
        let account_uuid = parse_uuid(account_id.as_str())?;

        // GORM `First`: ORDER BY primary key LIMIT 1; missing → NotFound.
        let account = sqlx::query_as!(
            AccountRow,
            r#"SELECT id, primary_verified_email, display_name, avatar_url, status,
                      created_at, updated_at
               FROM accounts
               WHERE id = $1
               ORDER BY id
               LIMIT 1"#,
            account_uuid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(RepoError::NotFound)?;

        // Revoked rows are included; ties keep Postgres' unspecified order,
        // exactly like Go's single-column ORDER BY.
        let sessions = sqlx::query_as!(
            SessionRow,
            r#"SELECT id, account_id, status, login_method, authenticated_at, last_seen_at,
                      expires_at, revoked_at, created_at, updated_at
               FROM sso_sessions
               WHERE account_id = $1
               ORDER BY last_seen_at DESC"#,
            account_uuid,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        let consents = sqlx::query_as!(
            ConsentRow,
            r#"SELECT id, account_id, client_id, granted_scopes, granted_at, last_used_at,
                      revoked_at
               FROM consent_grants
               WHERE account_id = $1
               ORDER BY last_used_at DESC"#,
            account_uuid,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        let chains = sqlx::query_as!(
            ChainRow,
            r#"SELECT id, account_id, client_id, sso_session_id, scope, device_session_id,
                      status, absolute_expires_at, inactive_expires_at, last_used_at,
                      revoked_at, created_at, updated_at
               FROM refresh_token_chains
               WHERE account_id = $1
               ORDER BY last_used_at DESC"#,
            account_uuid,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        // Go `uniqueClientIDs`: non-empty, de-duplicated, sorted.
        let client_ids: Vec<String> = consents
            .iter()
            .map(|consent| consent.client_id.as_str())
            .chain(chains.iter().map(|chain| chain.client_id.as_str()))
            .filter(|id| !id.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(str::to_owned)
            .collect();

        let mut client_display_names = BTreeMap::new();
        if !client_ids.is_empty() {
            let clients = sqlx::query!(
                r#"SELECT client_id, display_name
                   FROM oauth_clients
                   WHERE client_id = ANY($1)"#,
                &client_ids,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?;
            for client in clients {
                client_display_names.insert(ClientId::new(client.client_id), client.display_name);
            }
        }

        Ok(SupportAccountSummary {
            account: Account {
                id: AccountId::new(account.id.to_string()),
                primary_verified_email: account.primary_verified_email,
                display_name: account.display_name,
                avatar_url: account.avatar_url,
                status: AccountStatus::from(account.status),
                created_at: account.created_at,
                updated_at: account.updated_at,
            },
            sessions: sessions
                .into_iter()
                .map(|row| SsoSession {
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
                })
                .collect(),
            consents: consents
                .into_iter()
                .map(|row| ConsentGrant {
                    id: ConsentGrantId::new(row.id.to_string()),
                    account_id: AccountId::new(row.account_id.to_string()),
                    client_id: ClientId::new(row.client_id),
                    granted_scopes: row.granted_scopes,
                    granted_at: row.granted_at,
                    last_used_at: row.last_used_at,
                    revoked_at: row.revoked_at,
                })
                .collect(),
            refresh_token_chains: chains.into_iter().map(RefreshTokenChain::from).collect(),
            client_display_names,
        })
    }

    async fn sign_out(
        &self,
        session_ids: &[SessionId],
        chain_ids: &[ChainId],
        now: OffsetDateTime,
    ) -> RepoResult<()> {
        let session_ids = parse_uuids(session_ids)?;
        let chain_ids = parse_uuids(chain_ids)?;

        let mut tx = self.pool.begin().await.map_err(map_err)?;
        // No status filter: already revoked rows get the new timestamps too.
        if !session_ids.is_empty() {
            sqlx::query!(
                r#"UPDATE sso_sessions
                   SET status = $2, revoked_at = $3, updated_at = $3
                   WHERE id = ANY($1)"#,
                &session_ids,
                SsoSessionStatus::Revoked.as_str(),
                now,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }
        if !chain_ids.is_empty() {
            sqlx::query!(
                r#"UPDATE refresh_token_chains
                   SET status = $2, revoked_at = $3, updated_at = $3
                   WHERE id = ANY($1)"#,
                &chain_ids,
                RefreshTokenChainStatus::Revoked.as_str(),
                now,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
            // App time here, unlike `revoke_by_chain_id`'s database NOW().
            sqlx::query!(
                "UPDATE refresh_tokens SET revoked_at = $2 WHERE refresh_token_chain_id = ANY($1)",
                &chain_ids,
                now,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }
        tx.commit().await.map_err(map_err)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use auth_core::domain::{
        AccountId, AccountStatus, ChainId, ClientId, RefreshToken, RefreshTokenChain,
        RefreshTokenChainStatus, RefreshTokenId, SessionId, SsoSessionStatus,
    };
    use auth_core::ports::{
        RefreshTokenChainRepository, RefreshTokenRepository, RepoError, SupportRepository,
    };
    use sqlx::{PgPool, Row};
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::PgSupportRepository;
    use crate::persistence::chains::PgRefreshTokenChainRepository;
    use crate::persistence::chains::test_support::{
        FixedClock, SeqIds, T0, insert_account, insert_client, insert_session, uid,
    };
    use crate::persistence::refresh_tokens::PgRefreshTokenRepository;

    const ACCOUNT: u128 = 1;
    const OTHER_ACCOUNT: u128 = 2;
    const SESSION_A: u128 = 10;
    const SESSION_B: u128 = 11;
    const SESSION_OTHER: u128 = 12;
    const CHAIN_A: u128 = 40;
    const CHAIN_B: u128 = 41;
    const CHAIN_OTHER: u128 = 42;

    async fn insert_consent(
        pool: &PgPool,
        id: u128,
        account: u128,
        client_id: &str,
        last_used_at: OffsetDateTime,
        revoked_at: Option<OffsetDateTime>,
    ) {
        sqlx::query(
            "INSERT INTO consent_grants (id, account_id, client_id, granted_scopes, granted_at, last_used_at, revoked_at)
             VALUES ($1::uuid, $2::uuid, $3, 'openid email', $4, $5, $6)",
        )
        .bind(uid(id))
        .bind(uid(account))
        .bind(client_id)
        .bind(last_used_at - Duration::hours(1))
        .bind(last_used_at)
        .bind(revoked_at)
        .execute(pool)
        .await
        .unwrap();
    }

    fn chain(
        id: u128,
        account: u128,
        client: &str,
        session: u128,
        last_used_at: OffsetDateTime,
    ) -> RefreshTokenChain {
        RefreshTokenChain {
            id: ChainId::new(uid(id)),
            account_id: AccountId::new(uid(account)),
            client_id: ClientId::new(client),
            sso_session_id: SessionId::new(uid(session)),
            scope: "openid email profile".into(),
            device_session_id: format!("device-{id}"),
            status: RefreshTokenChainStatus::Active,
            absolute_expires_at: T0 + Duration::days(30),
            inactive_expires_at: T0 + Duration::days(7),
            last_used_at,
            ..RefreshTokenChain::default()
        }
    }

    /// Port of Go's `seedSupportFixture`, plus a second account whose rows
    /// must never be touched and a second token on chain A.
    async fn seed(pool: &PgPool) {
        insert_account(pool, &uid(ACCOUNT), "alice@example.com").await;
        insert_account(pool, &uid(OTHER_ACCOUNT), "bob@example.com").await;
        insert_client(pool, &uid(100), "client-a", "Client A").await;
        insert_client(pool, &uid(101), "client-b", "Client B").await;
        // Session A is newer than session B, as in Go's fixture.
        insert_session(pool, &uid(SESSION_A), &uid(ACCOUNT), "google", T0).await;
        insert_session(
            pool,
            &uid(SESSION_B),
            &uid(ACCOUNT),
            "email_otp",
            T0 - Duration::hours(1),
        )
        .await;
        insert_session(pool, &uid(SESSION_OTHER), &uid(OTHER_ACCOUNT), "google", T0).await;

        let clock = Arc::new(FixedClock::new(T0));
        let ids = Arc::new(SeqIds::new(800));
        let chains = PgRefreshTokenChainRepository::new(pool.clone(), clock, ids.clone());
        chains
            .create(chain(CHAIN_A, ACCOUNT, "client-a", SESSION_A, T0))
            .await
            .unwrap();
        chains
            .create(chain(
                CHAIN_B,
                ACCOUNT,
                "client-b",
                SESSION_B,
                T0 - Duration::hours(1),
            ))
            .await
            .unwrap();
        chains
            .create(chain(
                CHAIN_OTHER,
                OTHER_ACCOUNT,
                "client-a",
                SESSION_OTHER,
                T0,
            ))
            .await
            .unwrap();

        let tokens = PgRefreshTokenRepository::new(pool.clone(), ids);
        for (id, chain_id, hash) in [
            (200, CHAIN_A, "token-hash-1"),
            (201, CHAIN_B, "token-hash-2"),
            (202, CHAIN_A, "token-hash-3"),
            (203, CHAIN_OTHER, "token-hash-other"),
        ] {
            tokens
                .create(RefreshToken {
                    id: RefreshTokenId::new(uid(id)),
                    refresh_token_chain_id: ChainId::new(uid(chain_id)),
                    token_hash: hash.into(),
                    issued_at: T0,
                    expires_at: T0 + Duration::days(30),
                    ..RefreshToken::default()
                })
                .await
                .unwrap();
        }

        // Consent B was used more recently than consent A (Go fixture).
        insert_consent(pool, 60, ACCOUNT, "client-a", T0 - Duration::hours(1), None).await;
        insert_consent(
            pool,
            61,
            ACCOUNT,
            "client-b",
            T0 - Duration::minutes(30),
            None,
        )
        .await;
        insert_consent(pool, 62, OTHER_ACCOUNT, "client-a", T0, None).await;
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn summary_returns_account_sessions_consents_chains_in_order(pool: PgPool) {
        seed(&pool).await;
        let repo = PgSupportRepository::new(pool);

        let summary = repo
            .load_account_summary(&AccountId::new(uid(ACCOUNT)))
            .await
            .unwrap();

        assert_eq!(summary.account.id, uid(ACCOUNT).as_str());
        assert_eq!(summary.account.primary_verified_email, "alice@example.com");
        assert_eq!(summary.account.display_name, "Alice Example");
        assert_eq!(summary.account.avatar_url, "https://cdn.example/alice.png");
        assert_eq!(summary.account.status, AccountStatus::Active);
        assert_eq!(summary.account.created_at, T0);

        let session_ids: Vec<_> = summary.sessions.iter().map(|s| s.id.to_string()).collect();
        assert_eq!(session_ids, [uid(SESSION_A), uid(SESSION_B)]);
        assert_eq!(summary.sessions[0].login_method, "google");
        assert_eq!(summary.sessions[1].login_method, "email_otp");
        assert_eq!(summary.sessions[0].expires_at, T0 + Duration::days(1));

        let consent_clients: Vec<_> = summary
            .consents
            .iter()
            .map(|c| c.client_id.to_string())
            .collect();
        assert_eq!(consent_clients, ["client-b", "client-a"]);
        assert_eq!(summary.consents[0].id, uid(61).as_str());

        let chain_ids: Vec<_> = summary
            .refresh_token_chains
            .iter()
            .map(|c| c.id.to_string())
            .collect();
        assert_eq!(chain_ids, [uid(CHAIN_A), uid(CHAIN_B)]);
        assert_eq!(
            summary.refresh_token_chains[1].sso_session_id,
            uid(SESSION_B).as_str()
        );
        assert_eq!(
            summary.refresh_token_chains[1].device_session_id,
            "device-41"
        );

        assert_eq!(summary.client_display_names.len(), 2);
        assert_eq!(
            summary
                .client_display_names
                .get("client-a")
                .map(String::as_str),
            Some("Client A")
        );
        assert_eq!(
            summary
                .client_display_names
                .get("client-b")
                .map(String::as_str),
            Some("Client B")
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn summary_includes_revoked_rows(pool: PgPool) {
        seed(&pool).await;
        let repo = PgSupportRepository::new(pool.clone());
        let revoked_at = T0 - Duration::minutes(10);
        repo.sign_out(
            &[SessionId::new(uid(SESSION_B))],
            &[ChainId::new(uid(CHAIN_B))],
            revoked_at,
        )
        .await
        .unwrap();
        sqlx::query("UPDATE consent_grants SET revoked_at = $1 WHERE id = $2::uuid")
            .bind(revoked_at)
            .bind(uid(60))
            .execute(&pool)
            .await
            .unwrap();

        let summary = repo
            .load_account_summary(&AccountId::new(uid(ACCOUNT)))
            .await
            .unwrap();
        assert_eq!(summary.sessions.len(), 2);
        assert_eq!(summary.sessions[1].status, SsoSessionStatus::Revoked);
        assert_eq!(summary.sessions[1].revoked_at, Some(revoked_at));
        assert_eq!(summary.consents.len(), 2);
        assert_eq!(summary.consents[1].revoked_at, Some(revoked_at));
        assert_eq!(summary.refresh_token_chains.len(), 2);
        assert_eq!(
            summary.refresh_token_chains[1].status,
            RefreshTokenChainStatus::Revoked
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn summary_omits_display_name_of_missing_client(pool: PgPool) {
        seed(&pool).await;
        // Foreign keys normally prevent a dangling client_id; bypass them
        // (superuser test DB) to cover Go's `clientsByID[...]` zero value.
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("SET session_replication_role = replica")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO consent_grants (id, account_id, client_id, granted_scopes, granted_at, last_used_at)
             VALUES ($1::uuid, $2::uuid, 'ghost', 'openid', $3, $3)",
        )
        .bind(uid(63))
        .bind(uid(ACCOUNT))
        .bind(T0 + Duration::hours(5))
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query("SET session_replication_role = origin")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);

        let summary = PgSupportRepository::new(pool)
            .load_account_summary(&AccountId::new(uid(ACCOUNT)))
            .await
            .unwrap();
        assert_eq!(summary.consents[0].client_id, "ghost");
        assert!(!summary.client_display_names.contains_key("ghost"));
        assert_eq!(summary.client_display_names.len(), 2);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn summary_for_account_without_rows_is_empty(pool: PgPool) {
        insert_account(&pool, &uid(ACCOUNT), "alice@example.com").await;
        let summary = PgSupportRepository::new(pool)
            .load_account_summary(&AccountId::new(uid(ACCOUNT)))
            .await
            .unwrap();
        assert!(summary.sessions.is_empty());
        assert!(summary.consents.is_empty());
        assert!(summary.refresh_token_chains.is_empty());
        assert!(summary.client_display_names.is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn summary_missing_account_is_not_found_and_bad_id_is_other(pool: PgPool) {
        let repo = PgSupportRepository::new(pool);
        let err = repo
            .load_account_summary(&AccountId::new(uid(9)))
            .await
            .unwrap_err();
        assert!(err.is_not_found(), "{err}");
        let err = repo
            .load_account_summary(&AccountId::new("account-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
    }

    async fn status_of(
        pool: &PgPool,
        table: &str,
        id: u128,
    ) -> (String, Option<OffsetDateTime>, OffsetDateTime) {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT status, revoked_at, updated_at FROM {table} WHERE id = $1::uuid"
        )))
        .bind(uid(id))
        .fetch_one(pool)
        .await
        .unwrap();
        (row.get(0), row.get(1), row.get(2))
    }

    async fn token_revoked_at(pool: &PgPool) -> Vec<(Uuid, Option<OffsetDateTime>)> {
        sqlx::query("SELECT id, revoked_at FROM refresh_tokens ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn sign_out_revokes_sessions_chains_and_tokens(pool: PgPool) {
        seed(&pool).await;
        let repo = PgSupportRepository::new(pool.clone());
        let summary = repo
            .load_account_summary(&AccountId::new(uid(ACCOUNT)))
            .await
            .unwrap();
        let session_ids: Vec<_> = summary.sessions.iter().map(|s| s.id.clone()).collect();
        let chain_ids: Vec<_> = summary
            .refresh_token_chains
            .iter()
            .map(|c| c.id.clone())
            .collect();
        assert_eq!((session_ids.len(), chain_ids.len()), (2, 2));

        // Pre-revoke one session to show it is overwritten, as in Go.
        let earlier = T0 - Duration::days(2);
        repo.sign_out(&[SessionId::new(uid(SESSION_B))], &[], earlier)
            .await
            .unwrap();

        let now = T0 + Duration::hours(1);
        repo.sign_out(&session_ids, &chain_ids, now).await.unwrap();

        for id in [SESSION_A, SESSION_B] {
            assert_eq!(
                status_of(&pool, "sso_sessions", id).await,
                ("revoked".to_owned(), Some(now), now)
            );
        }
        for id in [CHAIN_A, CHAIN_B] {
            assert_eq!(
                status_of(&pool, "refresh_token_chains", id).await,
                ("revoked".to_owned(), Some(now), now)
            );
        }
        // The other account is untouched.
        assert_eq!(
            status_of(&pool, "sso_sessions", SESSION_OTHER).await,
            ("active".to_owned(), None, T0)
        );
        assert_eq!(
            status_of(&pool, "refresh_token_chains", CHAIN_OTHER).await,
            ("active".to_owned(), None, T0)
        );

        let tokens = token_revoked_at(&pool).await;
        let expected: Vec<_> = [
            (200, Some(now)),
            (201, Some(now)),
            (202, Some(now)),
            (203, None),
        ]
        .into_iter()
        .map(|(id, at)| (Uuid::from_u128(id), at))
        .collect();
        assert_eq!(tokens, expected);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn sign_out_with_no_ids_is_a_no_op(pool: PgPool) {
        seed(&pool).await;
        let repo = PgSupportRepository::new(pool.clone());
        repo.sign_out(&[], &[], T0 + Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(
            status_of(&pool, "sso_sessions", SESSION_A).await,
            ("active".to_owned(), None, T0)
        );
        assert!(
            token_revoked_at(&pool)
                .await
                .iter()
                .all(|(_, at)| at.is_none())
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn sign_out_with_bad_id_changes_nothing(pool: PgPool) {
        seed(&pool).await;
        let repo = PgSupportRepository::new(pool.clone());
        let err = repo
            .sign_out(
                &[SessionId::new(uid(SESSION_A))],
                &[ChainId::new("chain-1")],
                T0 + Duration::hours(1),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
        assert_eq!(
            status_of(&pool, "sso_sessions", SESSION_A).await,
            ("active".to_owned(), None, T0)
        );
    }
}
