//! PostgreSQL and Redis access.
//!
//! The schema is still owned by the Go core (`database_initialization`).
//! Queries here target that schema unchanged so both servers can share one
//! database during the migration.

pub mod abnormal;
pub mod audit;
pub mod campaigns;
pub mod contacts;
pub mod domains;
pub mod groups;
pub mod mailboxes;
pub mod maillog;
pub mod options;
pub mod overview;
pub mod ratelimit;
pub mod rbac;
pub mod send_api;
pub mod subscriptions;
pub mod tags;
pub mod templates;
pub mod tokens;
pub mod tracking;
pub mod warmup;
pub mod whitelist;

use std::time::Duration;

use anyhow::{Context, Result};
use ferropost_common::Config;
use fred::prelude::{Builder, ClientLike, Config as RedisClientConfig, Server, ServerConfig};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

pub use fred::prelude::Client as RedisClient;
pub use sqlx::PgPool;

const CONNECT_ATTEMPTS: u32 = 10;
const RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Store {
    pub pg: PgPool,
    pub redis: RedisClient,
}

impl Store {
    /// Connects to PostgreSQL and Redis, retrying like the Go core does while
    /// the other containers start.
    pub async fn connect(cfg: &Config) -> Result<Self> {
        let pg = retry("postgres", || connect_pg(cfg)).await?;
        let redis = retry("redis", || connect_redis(cfg)).await?;
        Ok(Self { pg, redis })
    }
}

async fn connect_pg(cfg: &Config) -> Result<PgPool> {
    let db = &cfg.database;
    let options = match &db.url {
        Some(url) => url
            .parse::<PgConnectOptions>()
            .context("parse FERROPOST_DATABASE_URL")?,
        None => PgConnectOptions::new()
            .socket(&db.socket_dir)
            .username(&db.user)
            .password(&db.password)
            .database(&db.name),
    }
    .application_name("ferropost");

    let pool = PgPoolOptions::new()
        .max_connections(db.max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await
        .context("connect to postgres")?;
    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .context("postgres ping")?;
    Ok(pool)
}

async fn connect_redis(cfg: &Config) -> Result<RedisClient> {
    let r = &cfg.redis;
    let config = match &r.url {
        Some(url) => RedisClientConfig::from_url(url).context("parse FERROPOST_REDIS_URL")?,
        None => RedisClientConfig {
            server: ServerConfig::Centralized {
                server: Server::new(r.host.clone(), r.port),
            },
            password: r.password.clone(),
            database: Some(r.db),
            ..Default::default()
        },
    };

    let client = Builder::from_config(config)
        .with_connection_config(|c| c.connection_timeout = Duration::from_secs(5))
        .build()
        .context("build redis client")?;
    client.init().await.context("connect to redis")?;
    Ok(client)
}

async fn retry<T, F, Fut>(what: &str, mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_err = None;
    for n in 1..=CONNECT_ATTEMPTS {
        match attempt().await {
            Ok(value) => {
                tracing::info!(what, "connected");
                return Ok(value);
            }
            Err(err) => {
                tracing::warn!(what, attempt = n, error = %format!("{err:#}"), "connection failed, retrying");
                last_err = Some(err);
                if n < CONNECT_ATTEMPTS {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("{what}: no attempts made")))
        .with_context(|| format!("{what} unavailable after {CONNECT_ATTEMPTS} attempts"))
}

/// Outcome of an update that can hit a missing row or a unique constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Write {
    Done,
    NotFound,
    Duplicate,
}

/// Escapes `%`, `_` and `\` so user input matches literally inside `LIKE`.
pub(crate) fn like_contains(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len() + 2);
    escaped.push('%');
    for c in input.chars() {
        if matches!(c, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped.push('%');
    escaped
}

#[cfg(test)]
mod tests {
    use super::like_contains;

    #[test]
    fn like_patterns_are_escaped() {
        assert_eq!(like_contains("vip"), "%vip%");
        assert_eq!(like_contains("50%_off\\"), "%50\\%\\_off\\\\%");
    }
}
