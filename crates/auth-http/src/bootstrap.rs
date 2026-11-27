//! Builds the router from [`Config`] (Go `httpserver.NewRouterFromEnv`).
//! Shared by the Vercel function and the local server binary.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use auth_adapters::{
    config::Config,
    jwks::JwksManager,
    mail::{SmtpSender, TemplateOtpMailer},
    persistence::{
        self, access_audit::PgAccessTokenRepository, accounts::PgAccountRepository,
        chains::PgRefreshTokenChainRepository, clients::PgOAuthClientRepository,
        codes::PgAuthorizationCodeRepository, consents::PgConsentGrantRepository,
        jtis::PgSignedStateJtiRepository, otp::PgOtpChallengeRepository,
        providers::PgAccountProviderRepository, readiness::PgReadinessProbe,
        refresh_tokens::PgRefreshTokenRepository, sessions::PgSsoSessionRepository,
        support::PgSupportRepository,
    },
    provider::{GitHubProvider, GoogleProvider},
    system::{SystemClock, UuidV7Ids},
};
use auth_core::{
    crypto::{RandomOtpCodeGenerator, SystemRandom},
    flow::{FlowConfig, FlowPorts, FlowService},
    identity::{FixedOtpCodeGenerator, IdentityConfig, IdentityDeps, IdentityService},
    oauth::{AuthorizeRequestValidator, envelope::EnvelopeSigner},
    ports::{
        Clock, IdGenerator, IdentityProvider, JtiStore, OtpCodeGenerator, OtpMailer, RandomSource,
        RepositoryJtiStore,
    },
    token::{TokenConfig, TokenService, TokenServiceDeps},
};
use axum::{Extension, Router};
use secrecy::ExposeSecret;

use crate::{
    apply_global_layers,
    cookies::CookiePolicy,
    handlers::{self, protocol::OtpHintSource},
    middleware::{RateLimiter, SupportAuth},
    state::AppState,
};

/// Connections per serverless instance (plan §4: small, lazy pool).
const DB_MAX_CONNECTIONS: u32 = 2;

/// A boot failure. Its text is what Go returned as the 500 body when
/// `NewRouterFromEnv` failed.
#[derive(Debug)]
pub struct BootError(String);

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BootError {}

fn boot_err(error: impl fmt::Display) -> BootError {
    BootError(error.to_string())
}

/// Loads config from the process environment and builds the full router.
///
/// # Errors
/// Config, key, envelope, provider or mailer setup failures.
pub fn router_from_env() -> Result<Router, BootError> {
    let config = Config::from_process_env().map_err(boot_err)?;
    build_router(config)
}

/// Builds the full router (all routes + global layers) for `config`.
///
/// # Errors
/// See [`build_state`].
pub fn build_router(config: Config) -> Result<Router, BootError> {
    let (state, otp_hint) = build_state_with_hint(config)?;
    let config = Arc::clone(&state.config);
    let routes = handlers::routes(&config).with_state(state);
    Ok(apply_global_layers(routes, &config).layer(Extension(otp_hint)))
}

/// Wires repositories, services and adapters like Go `NewRouterFromEnv`.
///
/// # Errors
/// Invalid database URL, signing keys, envelope secret, provider or SMTP
/// configuration.
pub fn build_state(config: Config) -> Result<AppState, BootError> {
    build_state_with_hint(config).map(|(state, _)| state)
}

/// [`build_state`] plus the OTP challenge store the non-production test-hint
/// handler reads through an [`Extension`].
fn build_state_with_hint(config: Config) -> Result<(AppState, OtpHintSource), BootError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let ids: Arc<dyn IdGenerator> = Arc::new(UuidV7Ids);
    let random: Arc<dyn RandomSource> = Arc::new(SystemRandom);

    let pool = persistence::connect_lazy(config.database_url.expose_secret(), DB_MAX_CONNECTIONS)
        .map_err(boot_err)?;
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let pool = pool.clone();
        handle.spawn(async move {
            // Warm one connection without making startup depend on PostgreSQL.
            let _ = tokio::time::timeout(Duration::from_secs(5), pool.acquire()).await;
        });
    }

    let clients = Arc::new(PgOAuthClientRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let accounts = Arc::new(PgAccountRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let account_providers = Arc::new(PgAccountProviderRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let otp_challenges = Arc::new(PgOtpChallengeRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let otp_hint = OtpHintSource(otp_challenges.clone());
    let sso_sessions = Arc::new(PgSsoSessionRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let codes = Arc::new(PgAuthorizationCodeRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let consents = Arc::new(PgConsentGrantRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let chains = Arc::new(PgRefreshTokenChainRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let refresh_tokens = Arc::new(PgRefreshTokenRepository::new(pool.clone(), ids.clone()));
    let access_tokens = Arc::new(PgAccessTokenRepository::new(
        pool.clone(),
        clock.clone(),
        ids.clone(),
    ));
    let jtis = Arc::new(PgSignedStateJtiRepository::new(pool.clone(), clock.clone()));
    let support = Arc::new(PgSupportRepository::new(pool.clone()));
    let readiness = Arc::new(PgReadinessProbe::new(pool));

    let jwks = Arc::new(
        JwksManager::from_sources(
            &config.jwt_signing_alg,
            &config.jwt_private_key_path,
            &config.jwt_public_key_path,
            config.jwt_private_key_pem.expose_secret(),
            &config.jwt_public_key_pem,
        )
        .map_err(boot_err)?,
    );

    let jti_store: Arc<dyn JtiStore> = Arc::new(RepositoryJtiStore::new(jtis));
    let envelope = Arc::new(
        EnvelopeSigner::new(
            config
                .flow_envelope_secret
                .expose_secret()
                .as_bytes()
                .to_vec(),
            config.flow_envelope_ttl,
            jti_store,
            clock.clone(),
            random.clone(),
        )
        .map_err(boot_err)?,
    );

    let flow = Arc::new(FlowService::new(
        FlowConfig {
            authorization_code_ttl: config.authorization_code_ttl,
            sso_session_ttl: config.sso_session_ttl,
        },
        FlowPorts {
            clock: clock.clone(),
            id_generator: ids.clone(),
            random: random.clone(),
            authorization_codes: codes,
            consent_grants: consents,
            sso_sessions: sso_sessions.clone(),
            refresh_token_chains: chains.clone(),
            refresh_tokens: refresh_tokens.clone(),
        },
    ));

    let token = Arc::new(TokenService::new(
        TokenConfig {
            issuer: config.jwt_issuer.clone(),
            audience: config.platform_audience.clone(),
            access_token_ttl: config.access_token_ttl,
            id_token_ttl: config.id_token_ttl,
            refresh_token_absolute_ttl: config.refresh_absolute_ttl,
            refresh_token_inactive_ttl: config.refresh_inactive_ttl,
            refresh_reuse_grace: config.refresh_reuse_grace,
        },
        TokenServiceDeps {
            clock: clock.clone(),
            ids: ids.clone(),
            random: random.clone(),
            signer: jwks.clone(),
            access_tokens,
            sso_sessions: sso_sessions.clone(),
            refresh_token_chains: chains.clone(),
            refresh_tokens: refresh_tokens.clone(),
        },
    ));

    let otp_code_generator: Arc<dyn OtpCodeGenerator> = if config.fixed_otp_code.is_empty() {
        Arc::new(RandomOtpCodeGenerator::new(random.clone()))
    } else {
        Arc::new(FixedOtpCodeGenerator::new(config.fixed_otp_code.clone()))
    };
    let otp_mailer: Option<Arc<dyn OtpMailer>> = match SmtpSender::from_config(&config) {
        None => None,
        Some(sender) => Some(Arc::new(TemplateOtpMailer::new(
            Arc::new(sender.map_err(boot_err)?),
            &config.app_name,
            clock.clone(),
        ))),
    };
    let identity = Arc::new(IdentityService::new(
        IdentityConfig {
            otp_challenge_ttl: config.otp_challenge_ttl,
            otp_max_attempts: config.otp_max_attempts,
            otp_max_resends: config.otp_max_resends,
            otp_resend_cooldown: config.otp_resend_cooldown,
        },
        IdentityDeps {
            clock: clock.clone(),
            otp_code_generator,
            accounts: accounts.clone(),
            account_providers,
            otp_challenges,
            otp_mailer,
            sso_sessions: flow.clone(),
        },
    ));

    let mut providers: BTreeMap<String, Arc<dyn IdentityProvider>> = BTreeMap::new();
    if let Some(google) = GoogleProvider::from_config(&config) {
        providers.insert("google".to_owned(), Arc::new(google.map_err(boot_err)?));
    }
    if let Some(github) = GitHubProvider::from_config(&config) {
        providers.insert("github".to_owned(), Arc::new(github.map_err(boot_err)?));
    }

    let state = AppState {
        cookies: Arc::new(CookiePolicy::from_config(&config)),
        otp_rate_limiter: Arc::new(RateLimiter::otp()),
        support_auth: Arc::new(SupportAuth::from_config(&config)),
        validator: Arc::new(AuthorizeRequestValidator::new(clients.clone())),
        config: Arc::new(config),
        clock,
        random,
        clients,
        accounts,
        sso_sessions,
        refresh_token_chains: chains,
        refresh_tokens,
        support,
        readiness,
        flow,
        token,
        identity,
        envelope,
        jwks: jwks.clone(),
        jwt_verifier: jwks,
        providers: Arc::new(providers),
    };
    Ok((state, otp_hint))
}

/// The router to serve: the real one, or — if boot failed — one that answers
/// every request with `500` and the boot error as `text/plain`, like Go's
/// `api/index.go` (`http.Error(w, err.Error(), 500)` on a cached boot error).
pub fn serving_router(result: Result<Router, BootError>) -> Router {
    match result {
        Ok(router) => router,
        Err(error) => {
            let body = format!("{error}\n");
            Router::new().fallback(move || {
                let body = body.clone();
                async move {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        [
                            (
                                axum::http::header::CONTENT_TYPE,
                                "text/plain; charset=utf-8",
                            ),
                            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                        ],
                        body,
                    )
                }
            })
        }
    }
}
