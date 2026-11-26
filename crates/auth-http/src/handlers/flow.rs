//! flow routes (filled by AUTH-035).

use crate::{routing::GinRouter, state::AppState};

/// Registers the flow routes on `router`.
#[must_use]
pub fn register(router: GinRouter<AppState>) -> GinRouter<AppState> {
    router
}
