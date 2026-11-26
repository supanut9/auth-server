//! Auth-flow routes (AUTH-035): authorize, provider login, consent and OTP.
//! Port of Go `handlers_stateless.go`, `handlers_provider_stateless.go` and
//! `handlers_otp_consent_stateless.go`; the redirect helpers of `router.go`
//! live in [`redirects`].

pub mod authorize;
pub mod body;
pub mod consent;
pub mod otp;
pub mod provider;
pub mod redirects;
pub mod respond;

use crate::{routing::GinRouter, state::AppState};

/// Registers the flow routes on `router` (Go `RegisterRoutes`).
///
/// The OTP routes carry the OTP rate limit (20 requests per 60 s per route
/// and client IP) through the [`respond::OtpRateLimit`] extractor, which
/// reads the limiter from [`AppState`].
#[must_use]
pub fn register(router: GinRouter<AppState>) -> GinRouter<AppState> {
    router
        .get("/v1/oauth2/authorize", authorize::authorize)
        .post("/v1/auth/login/google", provider::start_google)
        .post("/v1/auth/login/github", provider::start_github)
        .get("/v1/auth/login/callback/google", provider::callback_google)
        .get("/v1/auth/login/callback/github", provider::callback_github)
        .post("/v1/auth/consent/accept", consent::accept)
        .post("/v1/auth/consent/reject", consent::reject)
        .post("/v1/auth/otp/start", otp::start)
        .post("/v1/auth/otp/verify", otp::verify)
        .post("/v1/auth/otp/resend", otp::resend)
}
