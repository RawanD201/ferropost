//! `/api/askai/*` (Go: `controller/askai`). See `crate::askai`.

mod projects;
mod suppliers;

use axum::Router;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(suppliers::routes())
        .merge(projects::routes())
}
