//! Route handlers. `protocol` (discovery, JWKS, health, token, revoke,
//! introspect, userinfo, client info, me/csrf, logout, support, test-hint)
//! and `flow` (authorize, provider login, consent, OTP) register their own
//! routes; `common` holds helpers both use.

pub mod common;
pub mod flow;
pub mod protocol;

use crate::{routing::GinRouter, state::AppState};

/// Every route of the authorization server, in gin path syntax.
#[must_use]
pub fn routes() -> GinRouter<AppState> {
    flow::register(protocol::register(GinRouter::new()))
}
