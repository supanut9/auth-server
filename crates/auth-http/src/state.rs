//! Shared handler state. Built once per process by the entrypoints
//! (`api/auth.rs`, `src/bin/server.rs`) and cloned cheaply into handlers.

use std::{collections::BTreeMap, sync::Arc};

use auth_adapters::config::Config;
use auth_core::{
    flow::FlowService,
    identity::IdentityService,
    oauth::{AuthorizeRequestValidator, envelope::EnvelopeSigner},
    ports::{
        AccountRepository, CleanupRepository, Clock, IdentityProvider, JwksProvider, JwtVerifier,
        OAuthClientRepository, OtpRateLimiter, RandomSource, ReadinessProbe,
        RefreshTokenChainRepository, RefreshTokenRepository, SsoSessionRepository,
        SupportRepository,
    },
    token::TokenService,
};

use crate::{cookies::CookiePolicy, middleware::SupportAuth};

/// Everything the handlers need. Mirrors Go's `application.App` plus the
/// handler-level pieces (cookie policy, OTP limiter, support auth).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<dyn RandomSource>,

    pub clients: Arc<dyn OAuthClientRepository>,
    pub accounts: Arc<dyn AccountRepository>,
    pub sso_sessions: Arc<dyn SsoSessionRepository>,
    pub refresh_token_chains: Arc<dyn RefreshTokenChainRepository>,
    pub refresh_tokens: Arc<dyn RefreshTokenRepository>,
    pub support: Arc<dyn SupportRepository>,
    pub readiness: Arc<dyn ReadinessProbe>,
    pub cleanup: Arc<dyn CleanupRepository>,

    pub validator: Arc<AuthorizeRequestValidator>,
    pub flow: Arc<FlowService>,
    pub token: Arc<TokenService>,
    pub identity: Arc<IdentityService>,
    pub envelope: Arc<EnvelopeSigner>,
    pub jwks: Arc<dyn JwksProvider>,
    pub jwt_verifier: Arc<dyn JwtVerifier>,
    /// Registered identity providers keyed by name (`google`, `github`);
    /// absent when the provider's env vars are unset, like Go.
    pub providers: Arc<BTreeMap<String, Arc<dyn IdentityProvider>>>,

    pub cookies: Arc<CookiePolicy>,
    pub otp_rate_limiter: Arc<dyn OtpRateLimiter>,
    pub support_auth: Arc<SupportAuth>,
}
