//! Timestamp helpers shared by entities.

use time::OffsetDateTime;
use time::macros::datetime;

/// Go's zero `time.Time` (`0001-01-01T00:00:00Z`).
///
/// Entity `Default` impls use it so Go-style "fill if zero" logic in
/// repositories (`CreatedAt.IsZero()`) ports directly.
pub const ZERO_TIME: OffsetDateTime = datetime!(0001-01-01 0:00 UTC);

/// Go `time.Time.IsZero`: true only for the zero instant.
#[must_use]
pub fn is_zero_time(value: OffsetDateTime) -> bool {
    value == ZERO_TIME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_time_matches_go() {
        assert!(is_zero_time(ZERO_TIME));
        assert!(!is_zero_time(OffsetDateTime::UNIX_EPOCH));
        assert_eq!(ZERO_TIME.year(), 1);
    }
}
