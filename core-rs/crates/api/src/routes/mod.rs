//! Natively served routes. Anything not registered here is proxied to Go.
//!
//! To port a domain: add a module, register its routes in [`router`] under
//! the same paths and methods Go uses, and verify the JSON matches.

mod abnormal_recipient;
mod askai;
mod blocklist;
mod campaigns;
mod contact_groups;
mod contacts;
mod docker_api;
mod domains;
mod email_template;
mod files;
mod languages;
mod mail_bcc;
mod mail_forward;
mod mail_services;
mod mailboxes;
mod multi_ip;
mod operation_log;
mod overview;
mod postfix_queue;
mod relay;
mod send_api;
mod settings;
mod sign_in;
mod ssl;
mod subscription_form;
pub(crate) mod subscriptions;
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
        .merge(abnormal_recipient::routes())
        .merge(send_api::routes())
        .merge(settings::routes())
        .merge(relay::routes())
        .merge(mail_services::routes())
        .merge(mail_bcc::routes())
        .merge(mail_forward::routes())
        .merge(postfix_queue::routes())
        .merge(ssl::routes())
        .merge(multi_ip::routes())
        .merge(blocklist::routes())
        .merge(domains::routes())
        .merge(askai::routes())
        .merge(docker_api::routes())
        .merge(files::routes());
    // Campaign routes act on the sender, so they are native only where it
    // runs; otherwise Go serves them next to its own sender.
    if state.config.runs_job(crate::campaigns::JOB) {
        authenticated = authenticated.merge(campaigns::routes());
    }
    let authenticated = authenticated
        // Pasted address lists can be large; Go allowed up to 800 MB.
        .route_layer(DefaultBodyLimit::max(BODY_LIMIT))
        .route_layer(from_fn_with_state(state.clone(), rbac::require_permission))
        .route_layer(from_fn_with_state(state.clone(), auth::require_auth));

    // A login without a permission check (Go exempted these from RBAC).
    let signed_in = Router::new()
        .merge(languages::signed_in_routes())
        .merge(sign_in::signed_in_routes())
        .route_layer(from_fn_with_state(state, auth::require_auth));

    // Public routes: reached by recipients and other servers, not the console.
    let public = Router::new()
        .merge(tracking::routes())
        .merge(subscriptions::routes())
        .merge(subscription_form::routes())
        .merge(languages::public_routes())
        .merge(sign_in::public_routes())
        // Authenticated by its own cookie (an iframe sends no token).
        .merge(crate::rspamd::routes())
        // AskAI's brand images, which mail clients load.
        .route(
            "/media/{file}",
            axum::routing::get(crate::askai::media::serve),
        )
        // Let's Encrypt's HTTP-01 validation.
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(crate::acme::challenge),
        )
        // Authenticated by the API key instead of a login.
        .merge(send_api::public_routes());

    Router::new()
        .merge(authenticated)
        .merge(signed_in)
        .merge(public)
}
