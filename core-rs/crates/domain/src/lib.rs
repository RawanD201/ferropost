//! Domain types and pure rules for Ferropost.
//!
//! Nothing in this crate performs IO, so every rule here is unit-testable
//! without a database, network or filesystem.

pub mod audit;
pub mod contacts;
pub mod mail;
pub mod paging;
pub mod rbac;
pub mod tags;
pub mod templates;
pub mod web;
