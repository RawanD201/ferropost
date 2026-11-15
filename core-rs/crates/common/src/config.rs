//! Process configuration.
//!
//! Values shared with the rest of the stack (passwords, ports, SafePath, ...)
//! come from the BillionMail `.env` file. Settings specific to the Rust service
//! use `FERROPOST_*` process environment variables so they never clash with Go.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;

use crate::envfile::EnvFile;

/// Default address of the Go core while it runs behind this service.
pub const DEFAULT_GO_UPSTREAM: &str = "http://127.0.0.1:8181";

#[derive(Debug, Clone)]
pub struct Config {
    /// Core directory (`/opt/billionmail/core` in the container). Holds
    /// `languages/`, `public/` and `logs/`.
    pub root: PathBuf,
    pub env: Arc<EnvFile>,
    /// Base URL of the Go core that serves every route not yet ported.
    pub go_upstream: String,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub ssl_dir: PathBuf,
    pub http_port: u16,
    pub https_port: u16,
    /// Peers allowed to set `X-Forwarded-For`. Empty means nobody, so the
    /// client IP is always the TCP peer.
    pub trusted_proxies: Vec<IpNet>,
    /// The server's public address (`FERROPOST_SERVER_IP`), always allowed through
    /// the IP whitelist. When unset it is looked up online, as Go did.
    pub server_ip: Option<IpAddr>,
    pub jwt_secret: String,
    pub access_log_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Full URL override (`FERROPOST_DATABASE_URL`), mainly for development.
    pub url: Option<String>,
    pub socket_dir: PathBuf,
    pub user: String,
    pub name: String,
    pub password: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    /// Full URL override (`FERROPOST_REDIS_URL`), mainly for development.
    pub url: Option<String>,
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub db: u8,
}

impl Config {
    /// Loads configuration from the process environment and the `.env` file.
    pub fn load() -> Result<Self> {
        let root = match std::env::var_os("FERROPOST_ROOT") {
            Some(dir) => PathBuf::from(dir),
            None => std::env::current_dir().context("resolve current directory")?,
        };
        let env_path = std::env::var_os("FERROPOST_ENV_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("../.env"));
        Self::from_sources(root, Arc::new(EnvFile::load(env_path)), |key| {
            std::env::var(key).ok()
        })
    }

    /// Builds configuration from explicit sources; `var` reads process
    /// environment variables. Used directly by tests.
    pub fn from_sources(
        root: PathBuf,
        env: Arc<EnvFile>,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let var = |key: &str| var(key).filter(|v| !v.trim().is_empty());
        let in_container = Path::new("/.dockerenv").exists();

        let db_password = env.get("DBPASS").unwrap_or_default();
        let redis_password = env.get("REDISPASS");

        let jwt_secret = match var("FERROPOST_JWT_SECRET") {
            Some(secret) => secret,
            // Same derivation as Go's newJWTService so tokens stay valid
            // across both servers.
            None => format!(
                "{db_password}{}",
                redis_password.as_deref().unwrap_or_default()
            ),
        };
        if jwt_secret.is_empty() {
            bail!("no JWT secret: set DBPASS/REDISPASS in .env or FERROPOST_JWT_SECRET");
        }

        let (redis_host, redis_port) = if in_container {
            ("redis".to_owned(), 6379)
        } else {
            ("127.0.0.1".to_owned(), 26379)
        };

        Ok(Self {
            go_upstream: var("FERROPOST_GO_UPSTREAM")
                .unwrap_or_else(|| DEFAULT_GO_UPSTREAM.to_owned()),
            database: DatabaseConfig {
                url: var("FERROPOST_DATABASE_URL"),
                socket_dir: root.join("../postgresql-socket"),
                user: "billionmail".to_owned(),
                name: "billionmail".to_owned(),
                password: db_password,
                max_connections: parse_or(var("FERROPOST_DB_MAX_CONNECTIONS"), 20)?,
            },
            redis: RedisConfig {
                url: var("FERROPOST_REDIS_URL"),
                host: redis_host,
                port: redis_port,
                password: redis_password,
                db: parse_or(env.get("REDISDB"), 1)?,
            },
            ssl_dir: var("FERROPOST_SSL_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/etc/ssl/mail")),
            http_port: parse_or(
                var("FERROPOST_HTTP_PORT").or_else(|| env.get("HTTP_PORT")),
                80,
            )?,
            https_port: parse_or(
                var("FERROPOST_HTTPS_PORT").or_else(|| env.get("HTTPS_PORT")),
                443,
            )?,
            trusted_proxies: parse_trusted_proxies(var("FERROPOST_TRUSTED_PROXIES").as_deref())?,
            server_ip: var("FERROPOST_SERVER_IP")
                .map(|ip| ip.trim().parse::<IpAddr>().map(|ip| ip.to_canonical()))
                .transpose()
                .context("invalid FERROPOST_SERVER_IP")?,
            jwt_secret,
            access_log_dir: var("FERROPOST_ACCESS_LOG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("logs")),
            root,
            env,
        })
    }

    /// Normalised console base path (`WEB_BASE_PATH`, then `PUBLIC_PATH`).
    /// Read on each call so changes in `.env` apply without a restart.
    pub fn web_base_path(&self) -> String {
        ["WEB_BASE_PATH", "PUBLIC_PATH"]
            .into_iter()
            .filter_map(|key| std::env::var(key).ok().or_else(|| self.env.get(key)))
            .map(|value| ferropost_domain::web::normalize_base_path(&value))
            .find(|value| !value.is_empty())
            .unwrap_or_default()
    }
}

fn parse_or<T: std::str::FromStr>(value: Option<String>, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match value {
        None => Ok(default),
        Some(raw) => raw
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid value {raw:?}: {e}")),
    }
}

/// Parses a comma-separated list of IPs or CIDRs.
pub fn parse_trusted_proxies(value: Option<&str>) -> Result<Vec<IpNet>> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .with_context(|| format!("invalid FERROPOST_TRUSTED_PROXIES entry {s:?}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> Arc<EnvFile> {
        Arc::new(EnvFile::from_map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect::<HashMap<_, _>>(),
        ))
    }

    #[test]
    fn jwt_secret_matches_go_derivation() {
        let cfg = Config::from_sources(
            PathBuf::from("/opt/billionmail/core"),
            env(&[("DBPASS", "db"), ("REDISPASS", "redis")]),
            |_| None,
        )
        .expect("config");
        assert_eq!(cfg.jwt_secret, "dbredis");
        assert_eq!(cfg.go_upstream, DEFAULT_GO_UPSTREAM);
        assert_eq!(cfg.http_port, 80);
        assert_eq!(cfg.https_port, 443);
        assert_eq!(cfg.redis.db, 1);
        assert!(cfg.trusted_proxies.is_empty());
    }

    #[test]
    fn missing_secret_is_an_error() {
        let result = Config::from_sources(PathBuf::from("/x"), env(&[]), |_| None);
        assert!(result.is_err());
    }

    #[test]
    fn process_env_overrides() {
        let vars: HashMap<&str, &str> = HashMap::from([
            ("FERROPOST_JWT_SECRET", "override"),
            ("FERROPOST_HTTP_PORT", "8080"),
            ("FERROPOST_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.1"),
        ]);
        let cfg = Config::from_sources(
            PathBuf::from("/x"),
            env(&[("HTTP_PORT", "80"), ("HTTPS_PORT", "8443")]),
            |k| vars.get(k).map(|v| (*v).to_owned()),
        )
        .expect("config");
        assert_eq!(cfg.jwt_secret, "override");
        assert_eq!(cfg.http_port, 8080);
        assert_eq!(cfg.https_port, 8443);
        assert_eq!(cfg.trusted_proxies.len(), 2);
    }

    #[test]
    fn invalid_port_is_an_error() {
        let result = Config::from_sources(
            PathBuf::from("/x"),
            env(&[("DBPASS", "a"), ("HTTP_PORT", "eighty")]),
            |_| None,
        );
        assert!(result.is_err());
    }
}
