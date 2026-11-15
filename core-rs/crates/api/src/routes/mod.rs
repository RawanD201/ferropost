//! Natively served routes. Anything not registered here is proxied to Go.
//!
//! To port a domain: add a module, register its routes in [`router`] under
//! the same paths and methods Go uses, and verify the JSON matches.

mod tags;

use axum::Router;
use axum::middleware::from_fn_with_state;

use crate::state::AppState;
use crate::{auth, rbac};

pub fn router(state: AppState) -> Router<AppState> {
    // Route layers run outermost-last: auth, then RBAC, then the handler.
    let authenticated = Router::new()
        .merge(tags::routes())
        .route_layer(from_fn_with_state(state.clone(), rbac::require_permission))
        .route_layer(from_fn_with_state(state, auth::require_auth));

    Router::new().merge(authenticated)
}
