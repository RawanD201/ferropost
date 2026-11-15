//! Shared application state.

use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bm_common::{Config, Translator};
use bm_domain::rbac::RouteInfo;
use bm_store::Store;
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
    pub access_log: AccessLog,
    pub caches: Caches,
    /// Key for signing the safe-entrance cookie.
    pub entrance_key: [u8; 32],
}

/// Short-lived caches in front of hot database lookups. TTLs bound how long a
/// change made through the Go admin UI takes to apply here.
pub struct Caches {
    /// Role names per account (Go cached these for 20 seconds as well).
    pub roles: Cache<i64, Arc<[String]>>,
    pub permissions: Cache<(i64, RouteInfo), bool>,
    pub whitelist: Cache<(), Arc<Vec<IpNet>>>,
    pub default_language: Cache<(), Option<String>>,
    pub server_ip: Cache<(), Option<IpAddr>>,
}

impl Caches {
    fn new() -> Self {
        Self {
            roles: ttl_cache(Duration::from_secs(20), 10_000),
            permissions: ttl_cache(Duration::from_secs(20), 100_000),
            whitelist: ttl_cache(Duration::from_secs(10), 1),
            default_language: ttl_cache(Duration::from_secs(30), 1),
            server_ip: ttl_cache(Duration::from_secs(3600), 1),
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
        Ok(Self(Arc::new(Inner {
            i18n: Translator::new(config.root.join("languages")),
            jwt: JwtVerifier::new(&config.jwt_secret),
            upstream: Upstream::new(&config.go_upstream)?,
            access_log,
            caches: Caches::new(),
            entrance_key,
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
