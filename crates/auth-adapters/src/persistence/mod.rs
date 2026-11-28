//! PostgreSQL repository adapters (sqlx). One module per aggregate; shared
//! helpers live in `common`.

mod common;

pub mod access_audit;
pub mod accounts;
pub mod chains;
pub mod clients;
pub mod codes;
pub mod consents;
pub mod jtis;
pub mod otp;
pub mod providers;
pub mod rate_limit;
pub mod readiness;
pub mod refresh_tokens;
pub mod sessions;
pub mod support;

pub use common::{PgPool, connect_lazy};
