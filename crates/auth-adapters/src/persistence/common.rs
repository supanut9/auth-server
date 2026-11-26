//! Helpers shared by every repository adapter.

use auth_core::ports::RepoError;
pub use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Builds a lazily connecting pool sized for serverless instances.
///
/// # Errors
/// Returns an error when `url` is not a valid Postgres connection string.
pub fn connect_lazy(url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_lazy(url)
}

/// Maps sqlx errors onto the port error contract: missing rows become
/// `NotFound`, unique violations become `Conflict`.
#[allow(dead_code)] // TODO(AUTH-028): drop once repositories call it.
pub(crate) fn map_err(error: sqlx::Error) -> RepoError {
    match &error {
        sqlx::Error::RowNotFound => RepoError::NotFound,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => RepoError::Conflict,
        _ => RepoError::other(error),
    }
}
