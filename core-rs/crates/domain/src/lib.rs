//! Domain types and pure rules for Ferropost.
//!
//! Nothing in this crate performs IO, so every rule here is unit-testable
//! without a database, network or filesystem.

pub mod audit;
pub mod campaigns;
pub mod contacts;
pub mod groups;
pub mod mail;
pub mod mailboxes;
pub mod maillog;
pub mod overview;
pub mod paging;
pub mod rbac;
pub mod send_api;
pub mod settings;
pub mod tags;
pub mod templates;
pub mod tracking;
pub mod warmup;
pub mod web;
