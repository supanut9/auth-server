//! Protocol routes (AUTH-034): health, discovery and JWKS, the token,
//! revoke, introspect and userinfo endpoints, client public info, the
//! `/v1/auth` session helpers (`me`, `csrf`, local and global logout), the
//! support API and the non-production OTP test hint.
//!
//! Ports of `router.go`, `helpers.go`, `support.go` and
//! `handlers_otp_test_hint.go`. Every JSON body goes through
//! [`crate::json::json_response`]; `gin.H` maps are built with
//! `serde_json::json!` (sorted keys) and Go structs with ordered
//! `Serialize` structs.

mod discovery;
mod gohttp;
mod health;
mod logout;
mod otp_hint;
mod session;
mod support;
mod token;
mod userinfo;

use auth_adapters::config::Config;

use crate::{routing::GinRouter, state::AppState};

pub use self::{
    gohttp::{
        basic_auth, format_go_time, go_sprint, hex_escape_non_ascii, parse_query,
        split_protocol_list,
    },
    otp_hint::OtpHintSource,
};

/// Registers every protocol route on `router`.
///
/// The non-production routes (`GET /dev/callback`, `GET
/// /v1/auth/otp/test-hint`) are always mounted here, because the router is
/// built before the config is known; in production their handlers refuse
/// (`/dev/callback` with gin's plain `404 page not found`, the test hint
/// with its own `404 {"error":"not_found"}`, Go's defence in depth). Use
/// [`register_for`] to leave them unmounted in production, exactly like Go.
#[must_use]
pub fn register(router: GinRouter<AppState>) -> GinRouter<AppState> {
    register_routes(router, true)
}

/// [`register`], mounting the non-production routes only when `APP_ENV` is
/// not `production` (Go `RegisterRoutes`).
#[must_use]
pub fn register_for(router: GinRouter<AppState>, config: &Config) -> GinRouter<AppState> {
    register_routes(router, !config.is_production())
}

fn register_routes(router: GinRouter<AppState>, non_production: bool) -> GinRouter<AppState> {
    let mut router = router
        .get("/healthz", health::healthz)
        .get("/readyz", health::readyz);
    if non_production {
        router = router.get("/dev/callback", health::dev_callback);
    }
    let mut router = router
        .get(
            "/.well-known/openid-configuration",
            discovery::openid_configuration,
        )
        .get("/.well-known/jwks.json", discovery::jwks)
        .post("/v1/oauth2/token", token::token)
        .post("/v1/oauth2/revoke", token::revoke)
        .post("/v1/oauth2/introspect", token::introspect)
        .get("/v1/oidc/userinfo", userinfo::userinfo)
        .get(
            "/v1/clients/:clientID/public-info",
            session::client_public_info,
        )
        .get("/v1/auth/me", session::current_user)
        .get("/v1/auth/csrf", session::csrf_token);
    if non_production {
        router = router.get("/v1/auth/otp/test-hint", otp_hint::test_otp_hint);
    }
    router
        .get("/v1/auth/logout", logout::logout_local)
        .get("/v1/auth/logout/global", logout::logout_global)
        .get(
            "/v1/support/accounts/:accountID",
            support::get_support_account,
        )
        .post(
            "/v1/support/accounts/:accountID/sign-out",
            support::sign_out_support_account,
        )
}
