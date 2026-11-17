//! HTTP layer of Ferropost.
//!
//! Every request passes through [`edge::edge`] (client IP, base path, IP
//! whitelist, safe entrance, access log). Routes already ported to Rust are
//! served natively, the console's files by [`static_files::fallback`], and
//! Roundcube through PHP-FPM ([`webmail`]). Only Go's API documentation
//! still goes to the Go core ([`proxy::forward`]) while it runs.

pub mod acme;
pub mod api_mail;
pub mod askai;
pub mod blocklist;
pub mod bootstrap;
pub mod campaigns;
pub mod captcha;
pub mod certs;
pub mod dkim;
pub mod domains;
pub mod export;
pub mod fastcgi;
pub mod mail_tls;
pub mod mailbox_jobs;
pub mod multi_ip;
pub mod relay;
pub mod routes;
pub mod service_config;
pub mod static_files;
pub mod templates;
pub mod webmail;

// The shared HTTP layer, under the names this crate's modules and the
// tests use.
pub use ferropost_app::{
    access_log, audit, auth, base_url, body, conn, de, dns, docker, edge, envelope, fsio, lang,
    maildir, postfix, postfix_queue, proxy, rbac, rspamd, state, system_mail, validate,
};

use axum::Router;
use axum::middleware::from_fn_with_state;

pub use ferropost_app::{AppState, ClientIp, ConnInfo};

/// Builds the complete application.
pub fn app(state: AppState) -> Router {
    let router: Router = routes::router(state.clone())
        .fallback(static_files::fallback)
        .with_state(state.clone());

    // The edge layer wraps the whole router (rather than being added with
    // `Router::layer`) so it can rewrite the base path before routing happens.
    let edge = tower::ServiceBuilder::new()
        .layer(from_fn_with_state(state, edge::edge))
        .service(router);
    Router::new().fallback_service(edge)
}
