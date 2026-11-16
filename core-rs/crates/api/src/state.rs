//! Shared application state.

use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ferropost_common::{Config, Translator};
use ferropost_domain::rbac::RouteInfo;
use ferropost_store::Store;
use ipnet::IpNet;
use moka::future::Cache;

use crate::access_log::AccessLog;
use crate::auth::JwtVerifier;
use crate::proxy::Upstream;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub config: Config,
    pub store: Store,
    pub i18n: Translator,
    pub jwt: JwtVerifier,
    pub upstream: Upstream,
    /// rspamd's controller (its web interface).
    pub rspamd: Upstream,
    pub access_log: AccessLog,
    pub caches: Caches,
    /// Key for signing the safe-entrance cookie.
    pub entrance_key: [u8; 32],
    /// Key for signing tracking links.
    pub tracking_key: [u8; 32],
    /// Signalled when send-API mail is queued, so it goes out at once.
    pub api_mail_queued: tokio::sync::Notify,
}

/// Short-lived caches in front of hot database lookups. TTLs bound how long a
/// change made through the Go admin UI takes to apply here.
pub struct Caches {
    /// Role names per account (Go cached these for 20 seconds as well).
    /// `None` for disabled or deleted accounts.
    pub roles: Cache<i64, Option<Arc<[String]>>>,
    pub permissions: Cache<(i64, RouteInfo), bool>,
    pub whitelist: Cache<(), Arc<Vec<IpNet>>>,
    pub default_language: Cache<(), Option<String>>,
    pub server_ip: Cache<(), Option<IpAddr>>,
    /// Postfix deferred-queue size (Go cached it for 120 seconds too).
    pub deferred_queue: Cache<(), i64>,
    /// Public base URL per sender domain (`""` for the global one).
    pub base_urls: Cache<String, String>,
    pub token_keys: Cache<(), ferropost_sender::tokens::TokenKeys>,
    /// The API token issued last (`API_TOKEN`); older ones are refused.
    pub api_token: Cache<(), Option<Arc<str>>>,
    /// Host directory of `docker-compose.yml`.
    pub compose_dir: Cache<(), Option<String>>,
    /// Last connection check per relay.
    pub relay_status: Cache<i64, crate::relay::Status>,
    /// Published SPF record per domain (`None`: none found).
    pub spf_records: Cache<String, Option<String>>,
    /// HTTP-01 key authorizations by token, while an order is validated.
    pub acme_challenges: Cache<String, String>,
    /// Each domain's DNS records as last checked (Go kept them ten minutes).
    pub dns_records: Cache<String, ferropost_domain::domains::DnsRecords>,
}

impl Caches {
    fn new() -> Self {
        Self {
            roles: ttl_cache(Duration::from_secs(20), 10_000),
            permissions: ttl_cache(Duration::from_secs(20), 100_000),
            whitelist: ttl_cache(Duration::from_secs(10), 1),
            default_language: ttl_cache(Duration::from_secs(30), 1),
            server_ip: ttl_cache(Duration::from_secs(3600), 1),
            deferred_queue: ttl_cache(Duration::from_secs(120), 1),
            base_urls: ttl_cache(Duration::from_secs(300), 10_000),
            token_keys: ttl_cache(Duration::from_secs(300), 1),
            api_token: ttl_cache(Duration::from_secs(10), 1),
            compose_dir: ttl_cache(Duration::from_secs(3600), 1),
            relay_status: ttl_cache(Duration::from_secs(900), 10_000),
            spf_records: ttl_cache(Duration::from_secs(180), 10_000),
            acme_challenges: ttl_cache(Duration::from_secs(600), 1_000),
            dns_records: ttl_cache(Duration::from_secs(600), 10_000),
        }
    }
}

fn ttl_cache<K, V>(ttl: Duration, capacity: u64) -> Cache<K, V>
where
    K: std::hash::Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .time_to_live(ttl)
        .max_capacity(capacity)
        .build()
}

impl AppState {
    /// Must be called inside a Tokio runtime (it starts the access-log writer).
    pub fn new(config: Config, store: Store) -> Result<Self> {
        Self::with_access_log(
            config.clone(),
            store,
            AccessLog::start(config.access_log_dir.clone()),
        )
    }

    pub fn with_access_log(config: Config, store: Store, access_log: AccessLog) -> Result<Self> {
        let entrance_key = crate::edge::derive_entrance_key(&config.jwt_secret);
        let tracking_key = ferropost_domain::tracking::tracking_key(&config.jwt_secret);
        Ok(Self(Arc::new(Inner {
            i18n: Translator::new(config.root.join("languages")),
            jwt: JwtVerifier::new(&config.jwt_secret),
            upstream: Upstream::new(&config.go_upstream)?,
            rspamd: Upstream::new(&config.rspamd_url)?,
            access_log,
            caches: Caches::new(),
            entrance_key,
            tracking_key,
            api_mail_queued: tokio::sync::Notify::new(),
            config,
            store,
        })))
    }
}

impl Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    /// Secrets for unsubscribe/subscribe links: a random current secret
    /// (created on first use) and Go's stored secrets for its links.
    pub async fn token_keys(&self) -> Result<ferropost_sender::tokens::TokenKeys> {
        let pg = self.store.pg.clone();
        self.caches
            .token_keys
            .try_get_with((), async move {
                let current = ferropost_store::options::get_or_init(
                    &pg,
                    "ferropost_token_secret",
                    &ferropost_sender::tokens::new_secret(),
                )
                .await?;
                let mut legacy = Vec::new();
                for name in ["unsubscribe_jwt_secret", "subscribe_confirm_jwt_secret"] {
                    if let Some(secret) = ferropost_store::options::get(&pg, name).await? {
                        legacy.push(secret);
                    }
                }
                Ok::<_, anyhow::Error>(ferropost_sender::tokens::TokenKeys { current, legacy })
            })
            .await
            .map_err(|e| anyhow::anyhow!("{e:#}"))
    }
}
