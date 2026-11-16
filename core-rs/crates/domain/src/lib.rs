//! Domain types and pure rules for Ferropost.
//!
//! Nothing in this crate performs IO, so every rule here is unit-testable
//! without a database, network or filesystem.

pub mod audit;
pub mod contacts;
pub mod groups;
pub mod mail;
pub mod maillog;
pub mod overview;
pub mod paging;
pub mod rbac;
pub mod tags;
pub mod templates;
pub mod tracking;
pub mod warmup;
pub mod web;
