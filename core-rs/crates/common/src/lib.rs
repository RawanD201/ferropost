//! Configuration, `.env` access and i18n shared by every BillionMail crate.

pub mod config;
pub mod envfile;
pub mod i18n;

pub use config::Config;
pub use envfile::EnvFile;
pub use i18n::Translator;
