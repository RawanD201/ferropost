//! Certificates of the mail hosts and the console (Go: `domains/ssl.go`,
//! `mail_service/certificate.go`), and the `ssl` job: renewals (Go's
//! `AutoRenewSSL`) and the start-up tidy of Dovecot's SNI blocks (Go's
//! `FixDovecotSSLConfig`).
//!
//! Differences from Go:
//! - Postfix's SNI table is built with `postmap -F`, which Postfix needs for
//!   a `hash:` SNI table (Go's plain `postmap` stored file names, so Postfix
//!   always presented the default certificate).
//! - Postfix and Dovecot are reloaded, not restarted, and the core is not
//!   restarted at all (Go restarted all three on every certificate); a new
//!   console certificate also reaches Postfix and Dovecot, which use it as
//!   their default (Go left them on the old one until their next restart).
//! - A key is only installed with its certificate; private keys are
//!   readable by their owner only (Go wrote them 0755).
//! - Certificates obtained here are renewed with a third of their lifetime
//!   left (Go: 3 days); a failed host is retried after a day (Go never
//!   retried it); a host without an address record fails before Let's
//!   Encrypt is asked, sparing its failed-validation limit.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferropost_domain::tls as rules;
use ferropost_store::certs::{self as store, NewCert};
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::postfix::write_if_changed;
use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "ssl";
const RENEW_EVERY: Duration = Duration::from_secs(12 * 3600);
/// A failed host is tried again after this long.
const RETRY_AFTER_SECS: i64 = 24 * 3600;

static CONFIG_FILES: Mutex<()> = Mutex::new(());

/// What the console shows of a certificate (Go's `CertInfo`); the key is
/// never sent.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub dns: Vec<String>,
    pub endtime: i64,
    pub key_pem: String,
    pub cert_pem: String,
    #[serde(skip)]
    pub starts_at: i64,
}

fn date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// Go's `GetCertInfo` for a PEM chain.
pub fn summary(chain: &str) -> Option<CertSummary> {
    let info = crate::certs::info(chain.as_bytes(), chrono::Utc::now().timestamp()).ok()?;
    Some(CertSummary {
        subject: info.subject_common_name,
        issuer: info.issuer_common_name,
        not_before: date(info.starts_at),
        not_after: date(info.expires_at),
        dns: info.dns_names,
        endtime: info.expires_at,
        key_pem: String::new(),
        cert_pem: chain.to_owned(),
        starts_at: info.starts_at,
    })
}

fn host_dir(state: &AppState, host: &str) -> PathBuf {
    state.config.ssl_dir.join(host)
}

/// The certificate a mail host uses: the latest valid one obtained here,
/// else the files in `ssl/<host>/` (Go's `GetSSLInfo`).
pub async fn current(state: &AppState, host: &str) -> Result<Option<CertSummary>> {
    let now = chrono::Utc::now().timestamp();
    if let Some(issued) = store::valid_for(&state.store.pg, host, now).await?
        && let Some(found) = summary(&issued.certificate)
    {
        return Ok(Some(found));
    }
    let path = host_dir(state, host).join("fullchain.pem");
    let key = host_dir(state, host).join("privkey.pem");
    if !key.exists() {
        return Ok(None);
    }
    Ok(tokio::fs::read_to_string(&path)
        .await
        .ok()
        .and_then(|chain| summary(&chain)))
}

/// Reloads Postfix and Dovecot so they read new certificates.
async fn reload_mail_services(state: &AppState) -> Result<()> {
    crate::postfix::run(
        state,
        &["postmap", "-F", "hash:/etc/postfix/conf/vmail_ssl.map"],
    )
    .await?;
    crate::postfix::run(state, &["postfix", "reload"]).await?;
    crate::docker::exec_ok(&state.config.dovecot_container, &["dovecot", "reload"]).await?;
    Ok(())
}

/// The console's certificate (`ssl/cert.pem`), also the default one of
/// Postfix and Dovecot.
pub async fn install_console(state: &AppState, chain: &str, key: &str) -> Result<()> {
    crate::certs::check_pair(chain.as_bytes(), key.as_bytes())?;
    let dir = state.config.ssl_dir.clone();
    let (chain, key) = (chain.to_owned(), key.to_owned());
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::create_dir_all(&dir)?;
        crate::fsio::write_atomic(&dir.join("key.pem"), key.as_bytes(), 0o600)?;
        crate::fsio::write_atomic(&dir.join("cert.pem"), chain.as_bytes(), 0o644)?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow!("write console certificate: {e}"))??;
    reload_mail_services(state).await
}

/// Puts a fresh self-signed certificate in place of the console's.
pub async fn reset_console(state: &AppState) -> Result<()> {
    let host = state
        .config
        .env
        .get("BILLIONMAIL_HOSTNAME")
        .filter(|h| h != "mail.example.com" && ferropost_domain::settings::is_valid_hostname(h))
        .unwrap_or_else(|| "localhost".to_owned());
    let generated = rcgen::generate_simple_self_signed(vec![host])
        .context("generate a self-signed certificate")?;
    install_console(
        state,
        &generated.cert.pem(),
        &generated.signing_key.serialize_pem(),
    )
    .await
}

/// Installs a mail host's certificate: its files, Postfix's SNI table,
/// Dovecot's SNI block, and the console's certificate when the console is
/// reached under the same name (Go: `ApplyCertToService`).
pub async fn install(state: &AppState, host: &str, chain: &str, key: &str) -> Result<()> {
    crate::certs::check_pair(chain.as_bytes(), key.as_bytes())?;
    let dir = host_dir(state, host);
    let cert_path = dir.join("fullchain.pem");
    let key_path = dir.join("privkey.pem");
    let sni_map = crate::postfix::conf(state, "conf/vmail_ssl.map");
    let dovecot = state.config.dovecot_conf_dir.join("conf.d/10-ssl.conf");
    let (host_owned, chain_owned, key_owned) = (host.to_owned(), chain.to_owned(), key.to_owned());
    tokio::task::spawn_blocking(move || -> Result<()> {
        let _one = CONFIG_FILES.lock().unwrap_or_else(|e| e.into_inner());
        std::fs::create_dir_all(&dir)?;
        crate::fsio::write_atomic(&key_path, key_owned.as_bytes(), 0o600)?;
        crate::fsio::write_atomic(&cert_path, chain_owned.as_bytes(), 0o644)?;
        let (key_text, cert_text) = (key_path.display().to_string(), cert_path.display().to_string());
        if let Some(conf) = sni_map.parent() {
            std::fs::create_dir_all(conf)?;
        }
        let map = std::fs::read_to_string(&sni_map).unwrap_or_default();
        write_if_changed(
            &sni_map,
            &rules::sni_map_put(&map, &host_owned, &key_text, &cert_text),
            Some(0o644),
        )?;
        match std::fs::read_to_string(&dovecot) {
            Ok(conf) => {
                write_if_changed(
                    &dovecot,
                    &rules::dovecot_sni_put(&conf, &host_owned, &cert_text, &key_text),
                    None,
                )?;
            }
            Err(_) => tracing::warn!(path = %dovecot.display(), "Dovecot SSL config missing; SNI block not written"),
        }
        Ok(())
    })
    .await
    .map_err(|e| anyhow!("install certificate: {e}"))??;

    // The console under the same name uses it too.
    let base = crate::base_url::global(state).await;
    let console_host = base
        .split_once("://")
        .map_or(base.as_str(), |(_, rest)| rest)
        .split(['/', ':'])
        .next()
        .unwrap_or_default()
        .to_owned();
    state.caches.base_urls.invalidate_all();
    if console_host.eq_ignore_ascii_case(host) {
        return install_console(state, chain, key).await;
    }
    reload_mail_services(state).await
}

/// Whether `host` has an address record (Let's Encrypt connects to it).
async fn resolves(host: &str) -> bool {
    match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 80))).await {
        Ok(Ok(mut addrs)) => addrs.next().is_some(),
        _ => false,
    }
}

/// Refuses an attempt while a recent one was rate limited.
fn rate_limited(latest: Option<&store::Issued>, now: i64) -> Option<String> {
    let latest = latest?;
    let recent = store::failed_at(&latest.progress).is_some_and(|t| now - t < RETRY_AFTER_SECS);
    let limited =
        latest.error_info.contains("rateLimited") || latest.error_info.contains("too many");
    (latest.status == -1 && recent && limited).then(|| latest.error_info.clone())
}

/// Obtains and stores a certificate for `host`, then installs it with
/// `install`.
async fn obtain_and_store(
    state: &AppState,
    host: &str,
    account_id: i64,
    email: &str,
) -> Result<store::Issued> {
    let pg = &state.store.pg;
    let now = chrono::Utc::now().timestamp();
    if let Some(limit) = rate_limited(store::latest(pg, host).await?.as_ref(), now) {
        bail!("Rate limited, please wait and try later. Last error: {limit}");
    }
    let outcome = async {
        if !resolves(host).await {
            bail!("A Record does not exist, please check DNS Settings: {host}");
        }
        crate::acme::obtain(state, host, email).await
    }
    .await;
    let obtained = match outcome {
        Ok(obtained) => obtained,
        Err(err) => {
            let message = format!("{err:#}");
            store::record_failure(pg, host, &message, now).await?;
            return Err(anyhow!(message));
        }
    };
    let info = summary(&obtained.chain).context("the issued certificate cannot be read")?;
    let dns = serde_json::to_string(&[host])?;
    store::save(
        pg,
        &NewCert {
            account_id,
            subject: &info.subject,
            issuer: &info.issuer,
            dns_json: &dns,
            not_before: &info.not_before,
            not_after: &info.not_after,
            endtime: info.endtime,
            certificate: &obtained.chain,
            private_key: &obtained.key,
        },
    )
    .await?;
    Ok(store::Issued {
        subject: info.subject,
        status: 1,
        certificate: obtained.chain,
        private_key: obtained.key,
        endtime: info.endtime,
        ..Default::default()
    })
}

/// A domain's mail host certificate from Let's Encrypt, reusing a stored
/// one that is not yet due (Go: `ApplyLetsEncryptCertWithHttp`).
pub async fn obtain_for_domain(
    state: &AppState,
    domain: &str,
    account_id: i64,
    email: &str,
) -> Result<()> {
    let host = ferropost_store::domains::format_mx(&state.store.pg, domain).await?;
    let now = chrono::Utc::now().timestamp();
    if let Some(stored) = store::latest(&state.store.pg, &host).await?
        && stored.status == 1
        && let Some(info) = summary(&stored.certificate)
        && !rules::needs_renewal(info.starts_at, info.endtime, true, now)
    {
        return install(state, &host, &stored.certificate, &stored.private_key).await;
    }
    let issued = obtain_and_store(state, &host, account_id, email).await?;
    install(state, &host, &issued.certificate, &issued.private_key).await
}

/// The console's certificate for `BILLIONMAIL_HOSTNAME` (Go:
/// `ApplyConsoleCert`).
pub async fn obtain_for_console(state: &AppState, account_id: i64, email: &str) -> Result<()> {
    let host = state
        .config
        .env
        .get("BILLIONMAIL_HOSTNAME")
        .filter(|h| h != "mail.example.com")
        .ok_or_else(|| anyhow!("BILLIONMAIL_HOSTNAME environment variable is not set"))?;
    let now = chrono::Utc::now().timestamp();
    if let Some(stored) = store::valid_for(&state.store.pg, &host, now).await?
        && let Some(info) = summary(&stored.certificate)
        && !rules::needs_renewal(info.starts_at, info.endtime, true, now)
    {
        return install_console(state, &stored.certificate, &stored.private_key).await;
    }
    let issued = obtain_and_store(state, &host, account_id, email).await?;
    install_console(state, &issued.certificate, &issued.private_key).await
}

/// The administrator whose address Let's Encrypt may write to.
async fn admin(state: &AppState) -> Result<(i64, String)> {
    let pg = &state.store.pg;
    let name = state.config.env.get("ADMIN_USERNAME").unwrap_or_default();
    let id = ferropost_store::rbac::admin_account_id(pg, &name)
        .await?
        .ok_or_else(|| anyhow!("no admin account"))?;
    let email = ferropost_store::rbac::email_of(pg, id)
        .await?
        .unwrap_or_default();
    Ok((id, email))
}

/// Whether a certificate is one this server obtained (it is stored).
async fn issued_here(state: &AppState, host: &str, chain: &str) -> bool {
    matches!(
        store::latest(&state.store.pg, host).await,
        Ok(Some(stored)) if stored.certificate.trim() == chain.trim()
    )
}

/// Renews what is due and obtains missing mail host certificates (Go's
/// `AutoRenewSSL`).
pub async fn renew_all(state: &AppState) -> Result<()> {
    let (account_id, email) = admin(state).await?;
    let now = chrono::Utc::now().timestamp();
    let pg = &state.store.pg;

    // The console certificate.
    let console = tokio::fs::read_to_string(state.config.ssl_dir.join("cert.pem"))
        .await
        .ok()
        .and_then(|chain| summary(&chain));
    if let (Some(info), Some(host)) = (&console, state.config.env.get("BILLIONMAIL_HOSTNAME")) {
        let ours = issued_here(state, &host, &info.cert_pem).await;
        if rules::needs_renewal(info.starts_at, info.endtime, ours, now) {
            match obtain_for_console(state, account_id, &email).await {
                Ok(()) => tracing::info!(%host, "console certificate renewed"),
                Err(err) => {
                    tracing::warn!(%host, error = %format!("{err:#}"), "console certificate renewal failed")
                }
            }
        }
    }

    for domain in ferropost_store::domains::names(pg).await? {
        let host = ferropost_store::domains::format_mx(pg, &domain).await?;
        let installed = host_dir(state, &host).join("fullchain.pem").exists();
        let due = match current(state, &host).await? {
            Some(info) => {
                let ours = issued_here(state, &host, &info.cert_pem).await;
                !installed || rules::needs_renewal(info.starts_at, info.endtime, ours, now)
            }
            None => {
                let latest = store::latest(pg, &host).await?;
                let recently_failed = latest.as_ref().is_some_and(|l| {
                    l.status == -1
                        && store::failed_at(&l.progress).is_some_and(|t| now - t < RETRY_AFTER_SECS)
                });
                !recently_failed
            }
        };
        if !due {
            continue;
        }
        match obtain_for_domain(state, &domain, account_id, &email).await {
            Ok(()) => tracing::info!(%host, "certificate obtained"),
            Err(err) => {
                tracing::warn!(%host, error = %format!("{err:#}"), "certificate not obtained")
            }
        }
    }
    Ok(())
}

/// Go's `FixDovecotSSLConfig`; reloads Dovecot when it changed something.
pub async fn fix_dovecot(state: &AppState) -> Result<bool> {
    let path = state.config.dovecot_conf_dir.join("conf.d/10-ssl.conf");
    let changed = tokio::task::spawn_blocking(move || -> Result<bool> {
        let _one = CONFIG_FILES.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Ok(false);
        };
        write_if_changed(&path, &rules::fix_dovecot_ssl(&content), None)
    })
    .await
    .map_err(|e| anyhow!("tidy Dovecot SSL config: {e}"))??;
    if changed {
        crate::docker::exec_ok(&state.config.dovecot_container, &["dovecot", "reload"]).await?;
    }
    Ok(changed)
}

pub fn spawn(state: &AppState, mut shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("ssl job started");
    let state = state.clone();
    vec![tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = shutdown.changed() => return,
        }
        if let Err(err) = fix_dovecot(&state).await {
            tracing::warn!(error = %format!("{err:#}"), "Dovecot SSL config not tidied");
        }
        let mut wait = Duration::from_secs(55);
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => return,
            }
            if let Err(err) = renew_all(&state).await {
                tracing::warn!(error = %format!("{err:#}"), "certificate renewal pass failed");
            }
            wait = RENEW_EVERY;
        }
    })]
}
