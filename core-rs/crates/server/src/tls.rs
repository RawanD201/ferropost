//! TLS certificate selection by SNI.
//!
//! Same rules as the Go server: a host that belongs to a configured sending
//! domain gets `<ssl_dir>/<mail hostname>/fullchain.pem`; everything else gets
//! `<ssl_dir>/cert.pem`. Improvements over Go: renewed certificates are
//! picked up without a restart (entries expire after a few minutes), and a
//! missing default certificate falls back to an in-memory self-signed one
//! instead of failing the handshake.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ferropost_domain::mail::is_safe_hostname;
use moka::future::Cache;
use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sqlx::PgPool;

const HOST_TTL: Duration = Duration::from_secs(300);
const DEFAULT_TTL: Duration = Duration::from_secs(60);

pub struct CertStore {
    dir: PathBuf,
    pg: PgPool,
    by_host: Cache<String, Option<Arc<ServerConfig>>>,
    default: Cache<(), Arc<ServerConfig>>,
    self_signed: Arc<ServerConfig>,
}

impl CertStore {
    pub fn new(dir: PathBuf, pg: PgPool) -> Result<Self> {
        Ok(Self {
            dir,
            pg,
            by_host: Cache::builder()
                .time_to_live(HOST_TTL)
                .max_capacity(10_000)
                .build(),
            default: Cache::builder()
                .time_to_live(DEFAULT_TTL)
                .max_capacity(1)
                .build(),
            self_signed: self_signed()?,
        })
    }

    pub async fn config_for(&self, sni: Option<&str>) -> Arc<ServerConfig> {
        let host = sni
            .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| is_safe_hostname(s));
        if let Some(host) = host {
            // Database errors are not cached, so a blip does not pin the
            // default certificate for minutes.
            match self
                .by_host
                .try_get_with(host.clone(), self.load_for_host(host))
                .await
            {
                Ok(Some(config)) => return config,
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(error = %format!("{err:#}"), "certificate lookup failed")
                }
            }
        }
        self.default_config().await
    }

    async fn load_for_host(&self, sni: String) -> Result<Option<Arc<ServerConfig>>> {
        let Some(host) = ferropost_store::domains::mail_hostname(&self.pg, &sni).await? else {
            return Ok(None);
        };
        if !is_safe_hostname(&host) {
            return Ok(None);
        }
        let dir = self.dir.join(&host);
        match load_pair(&dir.join("fullchain.pem"), &dir.join("privkey.pem")).await {
            Ok(config) => Ok(Some(config)),
            Err(err) => {
                tracing::debug!(%host, error = %format!("{err:#}"), "no usable certificate; using default");
                Ok(None)
            }
        }
    }

    async fn default_config(&self) -> Arc<ServerConfig> {
        self.default
            .get_with((), async {
                load_pair(&self.dir.join("cert.pem"), &self.dir.join("key.pem"))
                    .await
                    .unwrap_or_else(|err| {
                        tracing::warn!(error = %format!("{err:#}"), "default certificate unavailable; using self-signed");
                        self.self_signed.clone()
                    })
            })
            .await
    }
}

async fn load_pair(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("read {}", key_path.display()))?;
    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse {}", cert_path.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .with_context(|| format!("parse {}", key_path.display()))?;
    server_config(chain, key)
}

fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("certificate and key do not match")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn self_signed() -> Result<Arc<ServerConfig>> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .context("generate self-signed certificate")?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    server_config(vec![generated.cert.der().clone()], key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loads_pem_pair_and_rejects_garbage() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["mail.example.com".to_owned()]).expect("cert");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("fullchain.pem");
        let key = dir.path().join("privkey.pem");
        std::fs::write(&cert, generated.cert.pem()).expect("write");
        std::fs::write(&key, generated.signing_key.serialize_pem()).expect("write");

        let config = load_pair(&cert, &key).await.expect("valid pair");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        std::fs::write(&key, "not a key").expect("write");
        assert!(load_pair(&cert, &key).await.is_err());
        assert!(load_pair(&dir.path().join("missing"), &key).await.is_err());
    }

    #[test]
    fn self_signed_fallback_builds() {
        assert!(self_signed().is_ok());
    }
}
