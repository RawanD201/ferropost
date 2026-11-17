//! The HTTP layer every part of Ferropost's API shares: the app state, the
//! edge every request passes ([`edge::edge`]), sign-in and roles, the
//! response envelope, request parsing, and access to the mail services.
//!
//! The routes live in crates built on this one, so that no single crate is
//! large enough to need more memory to compile than a small server has.

pub mod access_log;
pub mod audit;
pub mod auth;
pub mod base_url;
pub mod body;
pub mod conn;
pub mod de;
pub mod dns;
pub mod docker;
pub mod edge;
pub mod envelope;
pub mod fsio;
pub mod lang;
pub mod maildir;
pub mod postfix;
pub mod postfix_queue;
pub mod proxy;
pub mod rbac;
pub mod rspamd;
pub mod state;
pub mod system_mail;
pub mod validate;

pub use conn::{ClientIp, ConnInfo};
pub use state::AppState;

/// Current Unix time for the schema's `INTEGER` timestamp columns.
pub fn now() -> i32 {
    i32::try_from(chrono::Utc::now().timestamp()).unwrap_or(i32::MAX)
}
