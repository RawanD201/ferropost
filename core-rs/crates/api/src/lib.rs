//! HTTP layer of BillionMail.
//!
//! Every request passes through [`edge::edge`] (client IP, base path, IP
//! whitelist, safe entrance, access log). Routes already ported to Rust are
//! served natively; everything else falls through to [`proxy::forward`], which
//! hands it to the Go core. Porting a domain means adding its routes here, and
//! the Go version simply stops receiving that traffic.

pub mod access_log;
pub mod auth;
pub mod conn;
pub mod de;
pub mod edge;
pub mod envelope;
pub mod lang;
pub mod proxy;
pub mod rbac;
pub mod routes;
pub mod state;

use axum::Router;
use axum::middleware::from_fn_with_state;

pub use conn::{ClientIp, ConnInfo};
pub use state::AppState;

/// Builds the complete application.
pub fn app(state: AppState) -> Router {
    let router: Router = routes::router(state.clone())
        .fallback(proxy::forward)
        .with_state(state.clone());

    // The edge layer wraps the whole router (rather than being added with
    // `Router::layer`) so it can rewrite the base path before routing happens.
    let edge = tower::ServiceBuilder::new()
        .layer(from_fn_with_state(state, edge::edge))
        .service(router);
    Router::new().fallback_service(edge)
}
