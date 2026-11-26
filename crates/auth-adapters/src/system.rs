//! Production clock and ID generator (Go `system.NewClock`, `uuid` adapter).

use auth_core::ports::{Clock, IdGenerator};
use time::OffsetDateTime;
use uuid::Uuid;

/// Wall clock in UTC.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// UUIDv7 entity IDs.
#[derive(Debug, Clone, Copy, Default)]
pub struct UuidV7Ids;

impl IdGenerator for UuidV7Ids {
    fn new_id(&self) -> String {
        Uuid::now_v7().to_string()
    }
}
