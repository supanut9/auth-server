//! `oauth_clients` + `oauth_client_redirect_uris` repository
//! (Go `persistence.OAuthClientRepository`).

use std::sync::Arc;

use async_trait::async_trait;
use auth_core::domain::{ClientId, ClientRecordId, ClientStatus, ClientType, OAuthClient};
use auth_core::ports::{Clock, IdGenerator, OAuthClientRepository, RepoError, RepoResult};
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use time::UtcOffset;

use super::common::{map_err, parse_uuid};

/// Postgres-backed [`OAuthClientRepository`].
pub struct PgOAuthClientRepository {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PgOAuthClientRepository {
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, clock, ids }
    }
}

/// Go `buildRedirectURIModels`: drop empty and repeated URIs, keep first-seen
/// order.
fn dedupe_redirect_uris(uris: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(uris.len());
    for uri in uris {
        if uri.is_empty() || out.contains(uri) {
            continue;
        }
        out.push(uri.clone());
    }
    out
}

#[async_trait]
impl OAuthClientRepository for PgOAuthClientRepository {
    /// Inserts the client and its redirect URIs in one transaction (GORM's
    /// default transaction around a `Create` with associations).
    ///
    /// Like Go: the ID is generated when empty (before the redirect URI IDs),
    /// `created_at`/`updated_at` are always the clock time (input values are
    /// ignored), and `status` is stored as given with no default.
    async fn create(&self, mut client: OAuthClient) -> RepoResult<OAuthClient> {
        let now = self.clock.now().to_offset(UtcOffset::UTC);
        if client.id.is_empty() {
            client.id = ClientRecordId::new(self.ids.new_id());
        }

        let redirect_uris = dedupe_redirect_uris(&client.redirect_uris);
        let redirect_ids: Vec<String> = redirect_uris.iter().map(|_| self.ids.new_id()).collect();

        let id = parse_uuid(client.id.as_str())?;
        let redirect_ids = redirect_ids
            .iter()
            .map(|value| parse_uuid(value))
            .collect::<RepoResult<Vec<_>>>()?;

        let mut tx = self.pool.begin().await.map_err(map_err)?;
        sqlx::query!(
            r#"INSERT INTO oauth_clients
                (id, client_id, client_type, client_secret_hash, display_name, logo_uri,
                 allowed_scopes, status, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
            id,
            client.client_id.as_str(),
            client.client_type.as_str(),
            client.client_secret_hash.expose_secret(),
            client.display_name,
            client.logo_uri,
            client.allowed_scopes,
            client.status.as_str(),
            now,
            now,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

        // GORM appended `ON CONFLICT (id) DO UPDATE SET client_id` to the
        // association insert; the IDs are freshly generated, so a plain insert
        // is equivalent.
        for (redirect_id, uri) in redirect_ids.into_iter().zip(&redirect_uris) {
            sqlx::query!(
                r#"INSERT INTO oauth_client_redirect_uris
                    (id, client_id, redirect_uri, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, $5)"#,
                redirect_id,
                client.client_id.as_str(),
                uri,
                now,
                now,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }
        tx.commit().await.map_err(map_err)?;

        client.redirect_uris = redirect_uris;
        client.created_at = now;
        client.updated_at = now;
        Ok(client)
    }

    /// GORM `Preload("RedirectURIs").Where("client_id = ?").First`: the client
    /// row (`ORDER BY id LIMIT 1`), then its redirect URIs in a second,
    /// non-transactional query.
    ///
    /// GORM's preload query had no `ORDER BY` (heap order). This orders by
    /// `created_at, id`: Go inserts every URI of a client with the same
    /// timestamp and time-ordered UUIDv7 IDs, so this is insertion order made
    /// deterministic.
    async fn find_by_client_id(&self, client_id: &ClientId) -> RepoResult<OAuthClient> {
        let row = sqlx::query!(
            r#"SELECT id, client_id, client_type, client_secret_hash, display_name, logo_uri,
                      allowed_scopes, status, created_at, updated_at
               FROM oauth_clients
               WHERE client_id = $1
               ORDER BY id
               LIMIT 1"#,
            client_id.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or(RepoError::NotFound)?;

        let redirect_uris = sqlx::query_scalar!(
            r#"SELECT redirect_uri
               FROM oauth_client_redirect_uris
               WHERE client_id = $1
               ORDER BY created_at, id"#,
            row.client_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(OAuthClient {
            id: ClientRecordId::new(row.id.to_string()),
            client_id: ClientId::new(row.client_id),
            client_type: ClientType::from(row.client_type),
            client_secret_hash: SecretString::from(row.client_secret_hash),
            display_name: row.display_name,
            logo_uri: row.logo_uri,
            redirect_uris,
            allowed_scopes: row.allowed_scopes,
            status: ClientStatus::from(row.status),
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use uuid::Uuid;

    use auth_core::domain::ZERO_TIME;
    use time::OffsetDateTime;
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-05-16 12:00:00.123456 UTC);

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

    fn seq_id(n: u64) -> String {
        format!("01900000-0000-7000-8000-{n:012x}")
    }

    fn repo(pool: PgPool) -> PgOAuthClientRepository {
        PgOAuthClientRepository::new(
            pool,
            Arc::new(FixedClock),
            Arc::new(SeqIds(AtomicU64::new(0))),
        )
    }

    fn client(client_id: &str, uris: &[&str]) -> OAuthClient {
        OAuthClient {
            client_id: ClientId::new(client_id),
            client_type: ClientType::Public,
            client_secret_hash: SecretString::from("sha256:abc"),
            display_name: "Demo".into(),
            redirect_uris: uris.iter().map(|uri| (*uri).to_owned()).collect(),
            allowed_scopes: "openid profile email".into(),
            created_at: datetime!(2020-01-01 0:00 UTC),
            updated_at: datetime!(2020-01-01 0:00 UTC),
            ..OAuthClient::default()
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_applies_go_defaults_and_round_trips(pool: PgPool) {
        let repo = repo(pool);
        let created = repo
            .create(client(
                "demo-web",
                &[
                    "https://a.test/cb",
                    "",
                    "https://b.test/cb",
                    "https://a.test/cb",
                ],
            ))
            .await
            .unwrap();

        // Client ID is generated before the redirect URI IDs.
        assert_eq!(created.id.as_str(), seq_id(1));
        assert_eq!(created.created_at, NOW);
        assert_eq!(created.updated_at, NOW);
        assert_eq!(
            created.redirect_uris,
            ["https://a.test/cb", "https://b.test/cb"]
        );
        // No status default for clients (Go stores the empty string).
        assert!(created.status.is_empty());
        assert_eq!(created.logo_uri, "");

        let found = repo
            .find_by_client_id(&ClientId::new("demo-web"))
            .await
            .unwrap();
        assert_eq!(found.id, created.id);
        assert_eq!(found.client_type, ClientType::Public);
        assert_eq!(found.client_secret_hash.expose_secret(), "sha256:abc");
        assert_eq!(found.display_name, "Demo");
        assert_eq!(found.logo_uri, "");
        assert_eq!(found.allowed_scopes, "openid profile email");
        assert!(found.status.is_empty());
        assert_eq!(found.created_at, NOW);
        assert_eq!(found.updated_at, NOW);
        assert_eq!(
            found.redirect_uris,
            ["https://a.test/cb", "https://b.test/cb"]
        );

        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM oauth_client_redirect_uris WHERE client_id = 'demo-web' ORDER BY id",
        )
        .fetch_all(&repo.pool)
        .await
        .unwrap();
        let ids: Vec<String> = ids.iter().map(Uuid::to_string).collect();
        assert_eq!(ids, [seq_id(2), seq_id(3)]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_keeps_explicit_id_status_and_logo(pool: PgPool) {
        let repo = repo(pool);
        let mut input = client("conf", &[]);
        input.id = ClientRecordId::new("01900000-0000-7000-8000-0000000000ff");
        input.client_type = ClientType::Confidential;
        input.status = ClientStatus::Active;
        input.logo_uri = "https://cdn.test/logo.png".into();
        repo.create(input).await.unwrap();

        let found = repo
            .find_by_client_id(&ClientId::new("conf"))
            .await
            .unwrap();
        assert_eq!(found.id.as_str(), "01900000-0000-7000-8000-0000000000ff");
        assert_eq!(found.status, ClientStatus::Active);
        assert_eq!(found.client_type, ClientType::Confidential);
        assert_eq!(found.logo_uri, "https://cdn.test/logo.png");
        assert!(found.redirect_uris.is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn redirect_uris_load_in_insertion_order(pool: PgPool) {
        let repo = repo(pool);
        let uris = [
            "https://z.test/cb",
            "https://a.test/cb",
            "https://m.test/cb",
        ];
        repo.create(client("ordered", &uris)).await.unwrap();
        let found = repo
            .find_by_client_id(&ClientId::new("ordered"))
            .await
            .unwrap();
        assert_eq!(found.redirect_uris, uris);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn find_missing_client_is_not_found(pool: PgPool) {
        let err = repo(pool)
            .find_by_client_id(&ClientId::new("nope"))
            .await
            .unwrap_err();
        assert!(err.is_not_found());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn duplicate_client_id_conflicts_and_rolls_back(pool: PgPool) {
        let repo = repo(pool);
        repo.create(client("dup", &["https://a.test/cb"]))
            .await
            .unwrap();
        let err = repo
            .create(client("dup", &["https://other.test/cb"]))
            .await
            .unwrap_err();
        assert!(err.is_conflict());
        let found = repo.find_by_client_id(&ClientId::new("dup")).await.unwrap();
        assert_eq!(found.redirect_uris, ["https://a.test/cb"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn malformed_id_is_other_error(pool: PgPool) {
        let mut input = client("bad", &[]);
        input.id = ClientRecordId::new("not-a-uuid");
        input.created_at = ZERO_TIME;
        let err = repo(pool).create(input).await.unwrap_err();
        assert!(matches!(err, RepoError::Other(_)), "{err:?}");
    }
}
