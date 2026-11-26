//! Helpers shared by every repository adapter.

use auth_core::ports::{Clock, RepoError, RepoResult};
pub use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

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
pub(crate) fn map_err(error: sqlx::Error) -> RepoError {
    match &error {
        sqlx::Error::RowNotFound => RepoError::NotFound,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => RepoError::Conflict,
        _ => RepoError::other(error),
    }
}

/// Parses a string ID for a `uuid` column.
///
/// GORM passed IDs to Postgres as text, so a malformed ID failed with
/// `invalid input syntax for type uuid` (SQLSTATE 22P02) and the Go adapter
/// returned that error, not `ErrRecordNotFound`. This returns the same text
/// as [`RepoError::Other`] without the round trip. `urn:uuid:` input, which
/// `uuid` accepts but Postgres rejects, is refused too.
pub(crate) fn parse_uuid(value: &str) -> RepoResult<Uuid> {
    let parsed = if value.starts_with("urn:") {
        None
    } else {
        Uuid::try_parse(value).ok()
    };
    parsed.ok_or_else(|| {
        RepoError::other(format!(
            "ERROR: invalid input syntax for type uuid: \"{value}\" (SQLSTATE 22P02)"
        ))
    })
}

/// Go `r.clock.Now().UTC()`.
pub(crate) fn now_utc(clock: &dyn Clock) -> OffsetDateTime {
    clock.now().to_offset(UtcOffset::UTC)
}

/// Parses a list of domain ID strings (see [`parse_uuid`]).
pub(crate) fn parse_uuids<T: AsRef<str>>(values: &[T]) -> RepoResult<Vec<Uuid>> {
    values
        .iter()
        .map(|value| parse_uuid(value.as_ref()))
        .collect()
}
