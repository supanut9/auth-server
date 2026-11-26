//! OAuth client seeding tool, a port of `cmd/devseed`.
//!
//! Upserts the 12 known OAuth clients with their secrets and redirect URIs
//! taken from the environment (or the dev-only defaults below).
//!
//! **Never run it unfiltered against a shared (deployed) database**: an
//! unfiltered run resets EVERY client's secret and redirect URIs to this
//! process's env/defaults. Seed one client at a time with
//! `DEVSEED_CLIENTS=<client-id>` (see `docs/deploy/vercel-deploy-runbook.md`).

use std::collections::HashSet;
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use auth_adapters::config::Config;
use auth_adapters::persistence::clients::PgOAuthClientRepository;
use auth_core::domain::{ClientId, ClientStatus, ClientType, OAuthClient};
use auth_core::ports::{Clock, IdGenerator, OAuthClientRepository};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Uuid;
use sqlx::types::time::{OffsetDateTime, UtcOffset};

/// Env var holding the client filter.
const FILTER_KEY: &str = "DEVSEED_CLIENTS";

/// One seeded client. The env prefix is derived from `client_id`
/// (`language-web` -> `LANGUAGE_WEB_`); Go spells the same names out.
struct ClientSpec {
    client_id: &'static str,
    confidential: bool,
    display_name: &'static str,
    allowed_scopes: &'static str,
    /// `None`: the client has no redirect URIs and reads no redirect env var.
    default_redirect_uri: Option<&'static str>,
    /// `None`: public client, stored with an empty secret hash.
    default_secret: Option<&'static str>,
}

const USER_SCOPES: &str = "openid email profile offline_access";
const TRADING_SCOPES: &str = "trading.read trading.write";

/// The clients in Go's seeding order. Secrets are dev-only defaults.
const CLIENTS: [ClientSpec; 12] = [
    ClientSpec {
        client_id: "dev-browser",
        confidential: false,
        display_name: "Development Browser Client",
        allowed_scopes: "openid email profile trading.read trading.write",
        default_redirect_uri: Some("http://localhost:8050/dev/callback"),
        default_secret: None,
    },
    ClientSpec {
        client_id: "community-web",
        confidential: true,
        display_name: "Community Web",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:3006/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("community-web-secret"),
    },
    ClientSpec {
        client_id: "knowledge-web",
        confidential: true,
        display_name: "Knowledge",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:3007/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("knowledge-web-secret"),
    },
    ClientSpec {
        client_id: "language-web",
        confidential: true,
        display_name: "Language Coach",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:3008/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("language-web-secret"),
    },
    ClientSpec {
        client_id: "interview-web",
        confidential: true,
        display_name: "Interview Prep",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:4301/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("interview-web-secret"),
    },
    ClientSpec {
        client_id: "portal-web",
        confidential: true,
        display_name: "Portal",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:3009/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("portal-web-secret"),
    },
    ClientSpec {
        client_id: "trading-web",
        confidential: true,
        display_name: "Trading",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:3011/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("trading-web-secret"),
    },
    ClientSpec {
        client_id: "macro-web",
        confidential: true,
        display_name: "Macro",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:3013/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("macro-web-secret"),
    },
    ClientSpec {
        client_id: "portfolio-manager-web",
        confidential: true,
        display_name: "Folio",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:3014/api/auth/oauth2/callback/auth-server"),
        default_secret: Some("portfolio-manager-web-secret"),
    },
    ClientSpec {
        client_id: "dev-worker",
        confidential: true,
        display_name: "Development Worker Client",
        allowed_scopes: TRADING_SCOPES,
        default_redirect_uri: Some("http://localhost:8050/dev/callback"),
        default_secret: Some("dev-worker-secret"),
    },
    ClientSpec {
        client_id: "cms-admin",
        confidential: true,
        display_name: "CMS Admin",
        allowed_scopes: USER_SCOPES,
        default_redirect_uri: Some("http://localhost:4101/auth/callback"),
        default_secret: Some("cms-admin-secret"),
    },
    ClientSpec {
        client_id: "realtime-service",
        confidential: true,
        display_name: "Realtime Service",
        allowed_scopes: TRADING_SCOPES,
        default_redirect_uri: None,
        default_secret: Some("dev-realtime-secret"),
    },
];

/// A client spec resolved against the environment (Go `seedSettings`).
struct SeedClient {
    spec: &'static ClientSpec,
    redirect_uris: Vec<String>,
    /// Plaintext secret; `None` for the public client.
    secret: Option<String>,
}

impl SeedClient {
    fn client_type(&self) -> ClientType {
        if self.spec.confidential {
            ClientType::Confidential
        } else {
            ClientType::Public
        }
    }

    /// Stored secret hash; empty for the public client (as in Go).
    fn secret_hash(&self) -> String {
        self.secret.as_deref().map(hash_secret).unwrap_or_default()
    }

    fn to_domain(&self) -> OAuthClient {
        let spec = self.spec;
        OAuthClient {
            client_id: ClientId::new(spec.client_id),
            client_type: self.client_type(),
            client_secret_hash: self.secret_hash().into(),
            display_name: spec.display_name.to_owned(),
            redirect_uris: self.redirect_uris.clone(),
            allowed_scopes: spec.allowed_scopes.to_owned(),
            status: ClientStatus::Active,
            ..OAuthClient::default()
        }
    }
}

/// Raw env lookup; `None` and `Some("")` both mean unset, as in Go.
type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn getenv(env: Env<'_>, key: &str) -> String {
    env(key).unwrap_or_default()
}

/// `language-web` -> `LANGUAGE_WEB`.
fn env_prefix(client_id: &str) -> String {
    client_id.to_ascii_uppercase().replace('-', "_")
}

/// Go `loadSeedSettings`, in `CLIENTS` order.
fn load_seed_clients(env: Env<'_>) -> Vec<SeedClient> {
    CLIENTS
        .iter()
        .map(|spec| {
            let prefix = env_prefix(spec.client_id);
            SeedClient {
                spec,
                redirect_uris: spec.default_redirect_uri.map_or_else(Vec::new, |fallback| {
                    redirect_uris_from_env(
                        env,
                        &format!("{prefix}_REDIRECT_URIS"),
                        &format!("{prefix}_REDIRECT_URI"),
                        fallback,
                    )
                }),
                secret: spec.default_secret.map(|fallback| {
                    env_or_default(env, &format!("{prefix}_CLIENT_SECRET"), fallback)
                }),
            }
        })
        .collect()
}

/// Go `clientFilterFromEnv`: split on comma, newline and space; trimmed;
/// empties dropped; order and duplicates kept.
fn client_filter_from_env(env: Env<'_>, key: &str) -> Vec<String> {
    getenv(env, key)
        .split([',', '\n', ' '])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Go `selectClients`: every client when `only` is empty, else the named
/// clients in `only` order. An unknown ID is fatal so a typo never silently
/// seeds nothing.
fn select_clients<'a>(
    clients: &'a [SeedClient],
    only: &[String],
) -> Result<Vec<&'a SeedClient>, String> {
    if only.is_empty() {
        return Ok(clients.iter().collect());
    }
    only.iter()
        .map(|id| {
            clients
                .iter()
                .find(|client| client.spec.client_id == id)
                .ok_or_else(|| format!("{FILTER_KEY}: unknown client {id:?}"))
        })
        .collect()
}

/// Go `envOrDefault`: trimmed value, or `fallback` when blank.
fn env_or_default(env: Env<'_>, key: &str, fallback: &str) -> String {
    let value = getenv(env, key);
    let value = value.trim();
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

/// Go `redirectURIsFromEnv`: the list key beats the single key beats the
/// fallback.
fn redirect_uris_from_env(
    env: Env<'_>,
    list_key: &str,
    single_key: &str,
    fallback: &str,
) -> Vec<String> {
    let values = split_redirect_uris(&getenv(env, list_key));
    if !values.is_empty() {
        return values;
    }
    let single = getenv(env, single_key);
    let single = single.trim();
    if !single.is_empty() {
        return vec![single.to_owned()];
    }
    vec![fallback.to_owned()]
}

/// Go `splitRedirectURIs`: split on comma and newline, trim, drop empties and
/// repeats, keep first-seen order.
fn split_redirect_uris(value: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|uri| !uri.is_empty() && seen.insert(*uri))
        .map(str::to_owned)
        .collect()
}

/// Go `hashSecret`: `sha256:` + base64url_nopad(SHA-256(secret)), the
/// `oauth_clients.client_secret_hash` storage format.
///
/// Private helper: `auth_core::crypto` has no client-secret hashing yet
/// (AUTH-029). Switch to it once it lands.
fn hash_secret(secret: &str) -> String {
    format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
    )
}

/// Wall clock (Go `system.NewClock`).
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// UUIDv7 IDs (Go `uuid.NewGenerator`).
struct UuidV7Ids;

impl IdGenerator for UuidV7Ids {
    fn new_id(&self) -> String {
        Uuid::now_v7().to_string()
    }
}

/// Go `upsertClient`.
///
/// Missing client (any lookup error, as in Go): `repo.create`, which inserts
/// the client and its redirect URIs in one transaction. Existing client:
/// update type, secret hash, display name, scopes, status and `updated_at`
/// (never `logo_uri`, `id` or `created_at`), then delete and re-insert its
/// redirect URIs. Go ran those three statements without a transaction; here
/// they share one, so a failure cannot leave the client without redirect URIs.
async fn upsert_client(
    pool: &PgPool,
    repo: &PgOAuthClientRepository,
    clock: &dyn Clock,
    ids: &dyn IdGenerator,
    client: &SeedClient,
) -> Result<(), String> {
    let client_id = client.spec.client_id;
    if repo
        .find_by_client_id(&ClientId::new(client_id))
        .await
        .is_err()
    {
        repo.create(client.to_domain())
            .await
            .map_err(|err| format!("create client {client_id}: {err}"))?;
        return Ok(());
    }

    let now = clock.now().to_offset(UtcOffset::UTC);
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| format!("begin transaction for client {client_id}: {err}"))?;

    let client_type = client.client_type();
    sqlx::query!(
        r#"UPDATE oauth_clients
           SET client_type = $1, client_secret_hash = $2, display_name = $3,
               allowed_scopes = $4, status = $5, updated_at = $6
           WHERE client_id = $7"#,
        client_type.as_str(),
        client.secret_hash(),
        client.spec.display_name,
        client.spec.allowed_scopes,
        ClientStatus::Active.as_str(),
        now,
        client_id,
    )
    .execute(&mut *tx)
    .await
    .map_err(|err| format!("update client {client_id}: {err}"))?;

    sqlx::query!(
        "DELETE FROM oauth_client_redirect_uris WHERE client_id = $1",
        client_id,
    )
    .execute(&mut *tx)
    .await
    .map_err(|err| format!("clear redirect uris for client {client_id}: {err}"))?;

    for uri in &client.redirect_uris {
        let id = Uuid::parse_str(&ids.new_id()).map_err(|err| format!("generate id: {err}"))?;
        sqlx::query!(
            r#"INSERT INTO oauth_client_redirect_uris
                (id, client_id, redirect_uri, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5)"#,
            id,
            client_id,
            uri,
            now,
            now,
        )
        .execute(&mut *tx)
        .await
        .map_err(|err| format!("create redirect uris for client {client_id}: {err}"))?;
    }

    tx.commit()
        .await
        .map_err(|err| format!("commit client {client_id}: {err}"))
}

/// Seeds the selected clients and returns the lines Go printed to stdout.
///
/// The filter is resolved before any write, so an unknown client ID writes
/// nothing.
async fn seed(
    env: Env<'_>,
    pool: &PgPool,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
) -> Result<Vec<String>, String> {
    let repo = PgOAuthClientRepository::new(pool.clone(), clock.clone(), ids.clone());
    let clients = load_seed_clients(env);
    let only = client_filter_from_env(env, FILTER_KEY);
    for client in select_clients(&clients, &only)? {
        upsert_client(pool, &repo, clock.as_ref(), ids.as_ref(), client).await?;
    }
    Ok(summary_lines(&clients, &only))
}

/// Go's stdout. Secrets are printed only on an unfiltered run, exactly as Go
/// does (cms-admin is never printed, dev-worker's redirect URIs neither).
fn summary_lines(clients: &[SeedClient], only: &[String]) -> Vec<String> {
    if !only.is_empty() {
        return vec![format!("seeded only: {}", only.join(", "))];
    }

    let find = |id: &str| {
        clients
            .iter()
            .find(|client| client.spec.client_id == id)
            .unwrap_or_else(|| unreachable!("{id} is in CLIENTS"))
    };
    let secret = |id: &str| find(id).secret.clone().unwrap_or_default();
    let uris = |id: &str| find(id).redirect_uris.join(", ");

    let mut lines = vec![
        "seeded oauth clients:".to_owned(),
        "- public client_id: dev-browser".to_owned(),
    ];
    for id in [
        "community-web",
        "knowledge-web",
        "language-web",
        "interview-web",
        "portal-web",
        "trading-web",
    ] {
        lines.push(format!("- confidential client_id: {id}"));
        lines.push(format!("- confidential client_secret: {}", secret(id)));
    }
    lines.push(format!(
        "- macro web client_secret: {}",
        secret("macro-web")
    ));
    lines.push(format!(
        "- portfolio manager web client_secret: {}",
        secret("portfolio-manager-web")
    ));
    for id in ["dev-worker", "realtime-service"] {
        lines.push(format!("- confidential client_id: {id}"));
        lines.push(format!("- confidential client_secret: {}", secret(id)));
    }
    for (label, id) in [
        ("demo", "dev-browser"),
        ("community web", "community-web"),
        ("knowledge web", "knowledge-web"),
        ("language web", "language-web"),
        ("interview web", "interview-web"),
        ("portal web", "portal-web"),
        ("trading web", "trading-web"),
        ("macro web", "macro-web"),
        ("portfolio manager web", "portfolio-manager-web"),
    ] {
        lines.push(format!("- {label} redirect_uris: {}", uris(id)));
    }
    lines
}

fn process_env(key: &str) -> Option<String> {
    std::env::var_os(key).map(|value| value.to_string_lossy().into_owned())
}

/// Go `log.Fatalf`: message on stderr, exit status 1.
fn fatal(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    // Go `godotenv/autoload`: load `./.env` if present, never overriding
    // variables already set; a missing or unreadable file is ignored. Done
    // before the runtime starts any threads.
    let _ = dotenvy::from_path(".env");

    // Loaded for parity (same required env vars and validation as the
    // server); only the database URL is used. Never print config values.
    if let Err(err) = Config::from_process_env() {
        return fatal(&format!("load config: {err}"));
    }
    // Same raw value the config loader just accepted as non-empty.
    let database_url = process_env("DATABASE_URL").unwrap_or_default();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => return fatal(&format!("start runtime: {err}")),
    };

    runtime.block_on(async {
        // Like `gorm.Open`, connect eagerly so a bad URL fails before seeding.
        let pool = match PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
        {
            Ok(pool) => pool,
            Err(err) => return fatal(&format!("open database: {err}")),
        };

        let result = seed(
            &process_env,
            &pool,
            Arc::new(SystemClock),
            Arc::new(UuidV7Ids),
        )
        .await;
        pool.close().await;
        match result {
            Ok(lines) => {
                let mut stdout = std::io::stdout().lock();
                for line in lines {
                    // Go's fmt.Println ignores write errors too.
                    let _ = writeln!(stdout, "{line}");
                }
                ExitCode::SUCCESS
            }
            Err(message) => fatal(&message),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Fake environment for the pure helpers.
    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    fn ids(clients: &[&SeedClient]) -> Vec<&'static str> {
        clients.iter().map(|client| client.spec.client_id).collect()
    }

    // ---- Port of cmd/devseed/main_test.go ----

    #[test]
    fn split_redirect_uris_trims_and_dedupes() {
        let got = split_redirect_uris(
            " https://a.example/callback,\nhttp://localhost:3008/callback ,https://a.example/callback ",
        );
        assert_eq!(
            got,
            [
                "https://a.example/callback",
                "http://localhost:3008/callback"
            ]
        );
    }

    #[test]
    fn select_clients_filters() {
        let clients = load_seed_clients(&env_from(&[]));
        assert_eq!(select_clients(&clients, &[]).unwrap().len(), 12);

        let only = ["portal-web".to_owned(), "dev-browser".to_owned()];
        let got = select_clients(&clients, &only).unwrap();
        assert_eq!(ids(&got), ["portal-web", "dev-browser"]);
    }

    #[test]
    fn client_filter_from_env_splits() {
        let env = env_from(&[(
            "DEVSEED_CLIENTS_TEST",
            " portfolio-manager-web, macro-web\nx ",
        )]);
        let got = client_filter_from_env(&env, "DEVSEED_CLIENTS_TEST");
        assert_eq!(got, ["portfolio-manager-web", "macro-web", "x"]);
    }

    // ---- Additional parity cases ----

    #[test]
    fn split_redirect_uris_edge_cases() {
        assert!(split_redirect_uris("").is_empty());
        assert!(split_redirect_uris(" ,\n , ").is_empty());
        // Space is not a separator for redirect URIs (only for the client filter).
        assert_eq!(split_redirect_uris("a b"), ["a b"]);
        assert_eq!(split_redirect_uris("b,a\r\n,b"), ["b", "a"]);
    }

    #[test]
    fn client_filter_keeps_order_and_duplicates() {
        let env = env_from(&[("K", ",,a  b,\n\ta\r\n")]);
        assert_eq!(client_filter_from_env(&env, "K"), ["a", "b", "a"]);
        assert!(client_filter_from_env(&env_from(&[]), "K").is_empty());
        assert!(client_filter_from_env(&env_from(&[("K", " ,\n")]), "K").is_empty());
    }

    #[test]
    fn select_unknown_client_is_an_error() {
        let clients = load_seed_clients(&env_from(&[]));
        let only = ["macro-web".to_owned(), "macro-wbe".to_owned()];
        let err = select_clients(&clients, &only).err().unwrap();
        assert_eq!(err, r#"DEVSEED_CLIENTS: unknown client "macro-wbe""#);
    }

    #[test]
    fn env_names_match_go() {
        // Every env var name Go's loadSeedSettings reads, derived here from the
        // client ID.
        let read = std::cell::RefCell::new(Vec::new());
        let env = |key: &str| {
            read.borrow_mut().push(key.to_owned());
            None
        };
        load_seed_clients(&env);
        let mut read = read.into_inner();
        read.sort();
        let mut want = vec![
            "COMMUNITY_WEB_CLIENT_SECRET",
            "KNOWLEDGE_WEB_CLIENT_SECRET",
            "LANGUAGE_WEB_CLIENT_SECRET",
            "INTERVIEW_WEB_CLIENT_SECRET",
            "PORTAL_WEB_CLIENT_SECRET",
            "TRADING_WEB_CLIENT_SECRET",
            "MACRO_WEB_CLIENT_SECRET",
            "PORTFOLIO_MANAGER_WEB_CLIENT_SECRET",
            "CMS_ADMIN_CLIENT_SECRET",
            "DEV_WORKER_CLIENT_SECRET",
            "REALTIME_SERVICE_CLIENT_SECRET",
        ];
        for prefix in [
            "DEV_BROWSER",
            "COMMUNITY_WEB",
            "KNOWLEDGE_WEB",
            "LANGUAGE_WEB",
            "INTERVIEW_WEB",
            "PORTAL_WEB",
            "TRADING_WEB",
            "MACRO_WEB",
            "PORTFOLIO_MANAGER_WEB",
            "CMS_ADMIN",
            "DEV_WORKER",
        ] {
            // Single-URI key is read only when the list key is blank.
            want.push(Box::leak(
                format!("{prefix}_REDIRECT_URIS").into_boxed_str(),
            ));
            want.push(Box::leak(format!("{prefix}_REDIRECT_URI").into_boxed_str()));
        }
        want.sort_unstable();
        assert_eq!(read, want);
    }

    #[test]
    fn redirect_uri_precedence() {
        let pick = |pairs: &[(&str, &str)]| {
            let clients = load_seed_clients(&env_from(pairs));
            clients
                .iter()
                .find(|client| client.spec.client_id == "language-web")
                .unwrap()
                .redirect_uris
                .clone()
        };
        assert_eq!(
            pick(&[]),
            ["http://localhost:3008/api/auth/oauth2/callback/auth-server"]
        );
        assert_eq!(
            pick(&[("LANGUAGE_WEB_REDIRECT_URI", "  https://one.test/cb  ")]),
            ["https://one.test/cb"]
        );
        assert_eq!(
            pick(&[
                ("LANGUAGE_WEB_REDIRECT_URI", "https://one.test/cb"),
                (
                    "LANGUAGE_WEB_REDIRECT_URIS",
                    "https://b.test/cb,https://a.test/cb\nhttps://b.test/cb"
                ),
            ]),
            ["https://b.test/cb", "https://a.test/cb"]
        );
        // A blank list falls through to the single key, a blank single key to the
        // default.
        assert_eq!(
            pick(&[
                ("LANGUAGE_WEB_REDIRECT_URIS", " , \n"),
                ("LANGUAGE_WEB_REDIRECT_URI", "https://one.test/cb"),
            ]),
            ["https://one.test/cb"]
        );
        assert_eq!(
            pick(&[("LANGUAGE_WEB_REDIRECT_URI", "   ")]),
            ["http://localhost:3008/api/auth/oauth2/callback/auth-server"]
        );
    }

    #[test]
    fn secret_override_is_trimmed_and_blank_falls_back() {
        let secret = |pairs: &[(&str, &str)], id: &str| {
            load_seed_clients(&env_from(pairs))
                .into_iter()
                .find(|client| client.spec.client_id == id)
                .unwrap()
                .secret
        };
        assert_eq!(
            secret(&[], "realtime-service").as_deref(),
            Some("dev-realtime-secret")
        );
        assert_eq!(
            secret(&[("MACRO_WEB_CLIENT_SECRET", " s3cret ")], "macro-web").as_deref(),
            Some("s3cret")
        );
        assert_eq!(
            secret(&[("MACRO_WEB_CLIENT_SECRET", "  ")], "macro-web").as_deref(),
            Some("macro-web-secret")
        );
        assert_eq!(secret(&[], "dev-browser"), None);
    }

    /// client_id, type, display name, scopes, redirect URIs, secret hash.
    type ClientDef = (
        &'static str,
        ClientType,
        &'static str,
        &'static str,
        Vec<String>,
        String,
    );

    #[test]
    fn clients_match_go_definitions() {
        let clients = load_seed_clients(&env_from(&[]));
        let rows: Vec<ClientDef> = clients
            .iter()
            .map(|client| {
                let domain = client.to_domain();
                assert_eq!(domain.status, ClientStatus::Active);
                assert!(domain.id.is_empty());
                assert!(domain.logo_uri.is_empty());
                (
                    client.spec.client_id,
                    client.client_type(),
                    client.spec.display_name,
                    client.spec.allowed_scopes,
                    client.redirect_uris.clone(),
                    client.secret_hash(),
                )
            })
            .collect();

        let cb = |port: u16| {
            vec![format!(
                "http://localhost:{port}/api/auth/oauth2/callback/auth-server"
            )]
        };
        let dev = vec!["http://localhost:8050/dev/callback".to_owned()];
        let user = "openid email profile offline_access";
        let trading = "trading.read trading.write";
        let want: Vec<ClientDef> = vec![
            (
                "dev-browser",
                ClientType::Public,
                "Development Browser Client",
                "openid email profile trading.read trading.write",
                dev.clone(),
                String::new(),
            ),
            (
                "community-web",
                ClientType::Confidential,
                "Community Web",
                user,
                cb(3006),
                hash_secret("community-web-secret"),
            ),
            (
                "knowledge-web",
                ClientType::Confidential,
                "Knowledge",
                user,
                cb(3007),
                hash_secret("knowledge-web-secret"),
            ),
            (
                "language-web",
                ClientType::Confidential,
                "Language Coach",
                user,
                cb(3008),
                hash_secret("language-web-secret"),
            ),
            (
                "interview-web",
                ClientType::Confidential,
                "Interview Prep",
                user,
                cb(4301),
                hash_secret("interview-web-secret"),
            ),
            (
                "portal-web",
                ClientType::Confidential,
                "Portal",
                user,
                cb(3009),
                hash_secret("portal-web-secret"),
            ),
            (
                "trading-web",
                ClientType::Confidential,
                "Trading",
                user,
                cb(3011),
                hash_secret("trading-web-secret"),
            ),
            (
                "macro-web",
                ClientType::Confidential,
                "Macro",
                user,
                cb(3013),
                hash_secret("macro-web-secret"),
            ),
            (
                "portfolio-manager-web",
                ClientType::Confidential,
                "Folio",
                user,
                cb(3014),
                hash_secret("portfolio-manager-web-secret"),
            ),
            (
                "dev-worker",
                ClientType::Confidential,
                "Development Worker Client",
                trading,
                dev,
                hash_secret("dev-worker-secret"),
            ),
            (
                "cms-admin",
                ClientType::Confidential,
                "CMS Admin",
                user,
                vec!["http://localhost:4101/auth/callback".to_owned()],
                hash_secret("cms-admin-secret"),
            ),
            (
                "realtime-service",
                ClientType::Confidential,
                "Realtime Service",
                trading,
                vec![],
                hash_secret("dev-realtime-secret"),
            ),
        ];
        assert_eq!(rows, want);
    }

    #[test]
    fn unfiltered_summary_matches_go_output() {
        let clients = load_seed_clients(&env_from(&[(
            "MACRO_WEB_REDIRECT_URIS",
            "https://a.test/cb,https://b.test/cb",
        )]));
        let want = [
            "seeded oauth clients:",
            "- public client_id: dev-browser",
            "- confidential client_id: community-web",
            "- confidential client_secret: community-web-secret",
            "- confidential client_id: knowledge-web",
            "- confidential client_secret: knowledge-web-secret",
            "- confidential client_id: language-web",
            "- confidential client_secret: language-web-secret",
            "- confidential client_id: interview-web",
            "- confidential client_secret: interview-web-secret",
            "- confidential client_id: portal-web",
            "- confidential client_secret: portal-web-secret",
            "- confidential client_id: trading-web",
            "- confidential client_secret: trading-web-secret",
            "- macro web client_secret: macro-web-secret",
            "- portfolio manager web client_secret: portfolio-manager-web-secret",
            "- confidential client_id: dev-worker",
            "- confidential client_secret: dev-worker-secret",
            "- confidential client_id: realtime-service",
            "- confidential client_secret: dev-realtime-secret",
            "- demo redirect_uris: http://localhost:8050/dev/callback",
            "- community web redirect_uris: http://localhost:3006/api/auth/oauth2/callback/auth-server",
            "- knowledge web redirect_uris: http://localhost:3007/api/auth/oauth2/callback/auth-server",
            "- language web redirect_uris: http://localhost:3008/api/auth/oauth2/callback/auth-server",
            "- interview web redirect_uris: http://localhost:4301/api/auth/oauth2/callback/auth-server",
            "- portal web redirect_uris: http://localhost:3009/api/auth/oauth2/callback/auth-server",
            "- trading web redirect_uris: http://localhost:3011/api/auth/oauth2/callback/auth-server",
            "- macro web redirect_uris: https://a.test/cb, https://b.test/cb",
            "- portfolio manager web redirect_uris: http://localhost:3014/api/auth/oauth2/callback/auth-server",
        ];
        assert_eq!(summary_lines(&clients, &[]), want);
    }

    #[test]
    fn filtered_summary_prints_no_secrets() {
        let clients = load_seed_clients(&env_from(&[]));
        let only = ["macro-web".to_owned(), "cms-admin".to_owned()];
        assert_eq!(
            summary_lines(&clients, &only),
            ["seeded only: macro-web, cms-admin"]
        );
    }

    // ---- Golden vectors (testdata/golden/hashes.json, client_secret_storage) ----

    /// Reads the JSON string starting at `s[0] == '"'`; returns it unescaped and
    /// the rest of the input. Enough JSON for the golden file, no extra deps.
    fn json_string(s: &str) -> (String, &str) {
        let mut out = String::new();
        let mut chars = s.char_indices().skip(1);
        let mut pending_high: Option<u32> = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return (out, &s[i + 1..]),
                '\\' => {
                    let (_, esc) = chars.next().unwrap();
                    match esc {
                        'u' => {
                            let hex: String = (0..4).map(|_| chars.next().unwrap().1).collect();
                            let unit = u32::from_str_radix(&hex, 16).unwrap();
                            if (0xD800..0xDC00).contains(&unit) {
                                pending_high = Some(unit);
                                continue;
                            }
                            let code = match pending_high.take() {
                                Some(high) => 0x10000 + ((high - 0xD800) << 10) + (unit - 0xDC00),
                                None => unit,
                            };
                            out.push(char::from_u32(code).unwrap());
                        }
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
        panic!("unterminated JSON string");
    }

    /// Values of `"<key>": "<string>"` pairs, in file order, within `section`.
    fn string_values(section: &str, key: &str) -> Vec<String> {
        let needle = format!("\"{key}\":");
        let mut out = Vec::new();
        let mut rest = section;
        while let Some(pos) = rest.find(&needle) {
            let after = rest[pos + needle.len()..].trim_start();
            let (value, tail) = json_string(after);
            out.push(value);
            rest = tail;
        }
        out
    }

    #[test]
    fn golden_client_secret_storage() {
        let file = include_str!("../../testdata/golden/hashes.json");
        let start = file
            .find("\"client_secret_storage\"")
            .expect("client_secret_storage section");
        let section = &file[start..];
        // The section's cases end at its own "description" key (keys are sorted).
        let section = &section[..section.find("\"description\"").unwrap()];

        let secrets = string_values(section, "secret");
        let stored = string_values(section, "stored");
        assert_eq!(secrets.len(), stored.len());
        assert!(secrets.len() >= 4, "expected golden cases, got {secrets:?}");
        for (secret, stored) in secrets.iter().zip(&stored) {
            assert_eq!(&hash_secret(secret), stored, "secret {secret:?}");
        }
        // Non-ASCII input is hashed as UTF-8 bytes.
        assert!(secrets.iter().any(|secret| !secret.is_ascii()));
    }

    // ---- Database: seeding into a fresh, migrated database ----

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ClientRow {
        id: Uuid,
        client_id: String,
        client_type: String,
        client_secret_hash: String,
        display_name: String,
        logo_uri: String,
        allowed_scopes: String,
        status: String,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        redirect_uris: Vec<String>,
    }

    /// `oauth_clients` columns in `ClientRow` order.
    type RawClientRow = (
        Uuid,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        OffsetDateTime,
        OffsetDateTime,
    );

    async fn snapshot(pool: &PgPool) -> Vec<ClientRow> {
        let rows: Vec<RawClientRow> = sqlx::query_as(
            "SELECT id, client_id, client_type, client_secret_hash, display_name, logo_uri,
                    allowed_scopes, status, created_at, updated_at
             FROM oauth_clients ORDER BY client_id",
        )
        .fetch_all(pool)
        .await
        .unwrap();

        let mut out = Vec::new();
        for row in rows {
            let redirect_uris: Vec<String> = sqlx::query_scalar(
                "SELECT redirect_uri FROM oauth_client_redirect_uris
                 WHERE client_id = $1 ORDER BY created_at, id",
            )
            .bind(&row.1)
            .fetch_all(pool)
            .await
            .unwrap();
            out.push(ClientRow {
                id: row.0,
                client_id: row.1,
                client_type: row.2,
                client_secret_hash: row.3,
                display_name: row.4,
                logo_uri: row.5,
                allowed_scopes: row.6,
                status: row.7,
                created_at: row.8,
                updated_at: row.9,
                redirect_uris,
            });
        }
        out
    }

    fn row<'a>(rows: &'a [ClientRow], client_id: &str) -> &'a ClientRow {
        rows.iter()
            .find(|row| row.client_id == client_id)
            .unwrap_or_else(|| panic!("no row for {client_id}"))
    }

    async fn run_seed(pool: &PgPool, pairs: &[(&str, &str)]) -> Result<Vec<String>, String> {
        seed(
            &env_from(pairs),
            pool,
            Arc::new(SystemClock),
            Arc::new(UuidV7Ids),
        )
        .await
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn unfiltered_seed_creates_every_client(pool: PgPool) {
        let lines = run_seed(&pool, &[]).await.unwrap();
        assert_eq!(lines[0], "seeded oauth clients:");

        let rows = snapshot(&pool).await;
        assert_eq!(rows.len(), 12);
        for client in load_seed_clients(&env_from(&[])) {
            let got = row(&rows, client.spec.client_id);
            assert_eq!(got.client_type, client.client_type().as_str());
            assert_eq!(got.display_name, client.spec.display_name);
            assert_eq!(got.allowed_scopes, client.spec.allowed_scopes);
            assert_eq!(got.status, "active");
            assert_eq!(got.logo_uri, "");
            assert_eq!(got.redirect_uris, client.redirect_uris);
            assert_eq!(got.id.get_version_num(), 7);
        }

        let community = row(&rows, "community-web");
        assert_eq!(
            community.client_secret_hash,
            hash_secret("community-web-secret")
        );
        assert!(community.client_secret_hash.starts_with("sha256:"));
        assert_eq!(community.client_secret_hash.len(), "sha256:".len() + 43);
        assert_eq!(row(&rows, "dev-browser").client_secret_hash, "");
        assert!(row(&rows, "realtime-service").redirect_uris.is_empty());

        // A second unfiltered run is idempotent apart from updated_at and the
        // re-inserted redirect URI rows.
        run_seed(&pool, &[]).await.unwrap();
        let again = snapshot(&pool).await;
        for (before, after) in rows.iter().zip(&again) {
            assert_eq!(
                ClientRow {
                    updated_at: before.updated_at,
                    ..after.clone()
                },
                *before
            );
            assert!(after.updated_at >= before.updated_at);
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn update_replaces_redirect_uris_and_keeps_logo(pool: PgPool) {
        run_seed(&pool, &[("DEVSEED_CLIENTS", "language-web")])
            .await
            .unwrap();
        // Simulate a hand-edited production row.
        sqlx::query(
            "UPDATE oauth_clients
             SET logo_uri = 'https://cdn.test/logo.png', display_name = 'Old', status = 'disabled',
                 client_type = 'public', allowed_scopes = 'openid'
             WHERE client_id = 'language-web'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let before = row(&snapshot(&pool).await, "language-web").clone();

        let lines = run_seed(
            &pool,
            &[
                ("DEVSEED_CLIENTS", "language-web"),
                (
                    "LANGUAGE_WEB_REDIRECT_URIS",
                    "https://lang.test/b, https://lang.test/a\nhttps://lang.test/b",
                ),
                ("LANGUAGE_WEB_REDIRECT_URI", "https://ignored.test/cb"),
                ("LANGUAGE_WEB_CLIENT_SECRET", "rotated"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(lines, ["seeded only: language-web"]);

        let rows = snapshot(&pool).await;
        assert_eq!(rows.len(), 1);
        let after = row(&rows, "language-web");
        assert_eq!(after.id, before.id);
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(after.logo_uri, "https://cdn.test/logo.png");
        assert_eq!(after.client_secret_hash, hash_secret("rotated"));
        assert_eq!(after.display_name, "Language Coach");
        assert_eq!(after.status, "active");
        assert_eq!(after.client_type, "confidential");
        assert_eq!(after.allowed_scopes, "openid email profile offline_access");
        assert_eq!(
            after.redirect_uris,
            ["https://lang.test/b", "https://lang.test/a"]
        );
        assert!(after.updated_at >= before.updated_at);

        let uri_rows: Vec<(OffsetDateTime, OffsetDateTime)> = sqlx::query_as(
            "SELECT created_at, updated_at FROM oauth_client_redirect_uris
             WHERE client_id = 'language-web'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        for (created_at, updated_at) in uri_rows {
            assert_eq!(created_at, after.updated_at);
            assert_eq!(updated_at, after.updated_at);
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn filter_only_touches_selected_clients(pool: PgPool) {
        run_seed(
            &pool,
            &[
                ("MACRO_WEB_CLIENT_SECRET", "prod-macro"),
                ("CMS_ADMIN_REDIRECT_URIS", "https://cms.test/cb"),
            ],
        )
        .await
        .unwrap();
        let before = snapshot(&pool).await;

        run_seed(
            &pool,
            &[
                (
                    "DEVSEED_CLIENTS",
                    " portfolio-manager-web,\nrealtime-service ",
                ),
                (
                    "PORTFOLIO_MANAGER_WEB_REDIRECT_URIS",
                    "https://folio.test/cb",
                ),
                ("REALTIME_SERVICE_CLIENT_SECRET", "rt"),
            ],
        )
        .await
        .unwrap();
        let after = snapshot(&pool).await;

        assert_eq!(before.len(), after.len());
        for (b, a) in before.iter().zip(&after) {
            match a.client_id.as_str() {
                "portfolio-manager-web" => {
                    assert_eq!(a.redirect_uris, ["https://folio.test/cb"]);
                    assert_eq!(a.id, b.id);
                }
                "realtime-service" => {
                    assert_eq!(a.client_secret_hash, hash_secret("rt"));
                    assert!(a.redirect_uris.is_empty());
                }
                _ => assert_eq!(a, b, "{} changed", a.client_id),
            }
        }
        assert_eq!(
            row(&after, "macro-web").client_secret_hash,
            hash_secret("prod-macro")
        );
        assert_eq!(
            row(&after, "cms-admin").redirect_uris,
            ["https://cms.test/cb"]
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn unknown_filter_client_writes_nothing(pool: PgPool) {
        run_seed(&pool, &[("DEVSEED_CLIENTS", "macro-web")])
            .await
            .unwrap();
        let before = snapshot(&pool).await;

        // The valid ID listed first must not be written either.
        let err = run_seed(
            &pool,
            &[
                ("DEVSEED_CLIENTS", "language-web,nope"),
                ("MACRO_WEB_CLIENT_SECRET", "changed"),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(err, r#"DEVSEED_CLIENTS: unknown client "nope""#);
        assert_eq!(snapshot(&pool).await, before);
    }
}
