//! Route handlers. `protocol` (discovery, JWKS, health, token, revoke,
//! introspect, userinfo, client info, me/csrf, logout, support, test-hint)
//! and `flow` (authorize, provider login, consent, OTP) register their own
//! routes; `common` holds helpers both use.

pub mod common;
pub mod flow;
pub mod protocol;

use auth_adapters::config::Config;

use crate::{routing::GinRouter, state::AppState};

/// Every route of the authorization server, in gin path syntax. Dev-only
/// routes (`/dev/callback`, `/v1/auth/otp/test-hint`) are mounted only
/// outside production, like Go.
#[must_use]
pub fn routes(config: &Config) -> GinRouter<AppState> {
    flow::register(protocol::register_for(GinRouter::new(), config))
}
