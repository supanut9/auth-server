//! protocol routes (filled by AUTH-034).

use crate::{routing::GinRouter, state::AppState};

/// Registers the protocol routes on `router`.
#[must_use]
pub fn register(router: GinRouter<AppState>) -> GinRouter<AppState> {
    router
}
