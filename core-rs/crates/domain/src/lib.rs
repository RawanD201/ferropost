//! Domain types and pure rules for Ferropost.
//!
//! Nothing in this crate performs IO, so every rule here is unit-testable
//! without a database, network or filesystem.

pub mod audit;
pub mod blocklist;
pub mod campaigns;
pub mod contacts;
pub mod domains;
pub mod groups;
pub mod mail;
pub mod mail_services;
pub mod mailboxes;
pub mod maillog;
pub mod multi_ip;
pub mod overview;
pub mod paging;
pub mod postfix;
pub mod rbac;
pub mod relay;
pub mod send_api;
pub mod settings;
pub mod spf;
pub mod tags;
pub mod templates;
pub mod tls;
pub mod tracking;
pub mod warmup;
pub mod web;
