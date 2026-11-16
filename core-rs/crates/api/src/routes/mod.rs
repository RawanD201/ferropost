//! Natively served routes. Anything not registered here is proxied to Go.
//!
//! To port a domain: add a module, register its routes in [`router`] under
//! the same paths and methods Go uses, and verify the JSON matches.

mod campaigns;
mod contact_groups;
mod contacts;
mod email_template;
mod mailboxes;
mod operation_log;
mod overview;
mod send_api;
mod subscriptions;
mod tags;
mod tracking;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;

use crate::state::AppState;
use crate::{auth, rbac};

const BODY_LIMIT: usize = 32 * 1024 * 1024;

/// Current Unix time for the schema's `INTEGER` timestamp columns.
pub(crate) fn now() -> i32 {
    i32::try_from(chrono::Utc::now().timestamp()).unwrap_or(i32::MAX)
}

pub fn router(state: AppState) -> Router<AppState> {
    // Route layers run outermost-last: auth, then RBAC, then the handler.
    let mut authenticated = Router::new()
        .merge(tags::routes())
        .merge(operation_log::routes())
        .merge(email_template::routes())
        .merge(contact_groups::routes())
        .merge(contacts::routes())
        .merge(overview::routes())
        .merge(mailboxes::routes())
        .merge(send_api::routes());
    // Campaign routes act on the sender, so they are native only where it
    // runs; otherwise Go serves them next to its own sender.
    if state.config.runs_job(crate::campaigns::JOB) {
        authenticated = authenticated.merge(campaigns::routes());
    }
    let authenticated = authenticated
        // Pasted address lists can be large; Go allowed up to 800 MB.
        .route_layer(DefaultBodyLimit::max(BODY_LIMIT))
        .route_layer(from_fn_with_state(state.clone(), rbac::require_permission))
        .route_layer(from_fn_with_state(state, auth::require_auth));

    // Public routes: reached by recipients and other servers, not the console.
    let public = Router::new()
        .merge(tracking::routes())
        .merge(subscriptions::routes())
        // Authenticated by the API key instead of a login.
        .merge(send_api::public_routes());

    Router::new().merge(authenticated).merge(public)
}
