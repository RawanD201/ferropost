//! Sending domains (Go: `service/domains`): their DNS records, what a new
//! domain comes with, and the `domains` job, which checks every domain's
//! records every five minutes (Go's `FreshRecords`) and at start-up
//! repairs rspamd's DKIM keys and signing configuration
//! (`RepairDKIMSigningConfig`, `FixRspamdDKIMSigningConfig`).
//!
//! Differences from Go: records are checked by what they mean, not as text
//! (SPF is evaluated for the sending address, DKIM keys and DMARC policies
//! are read tag by tag); listing domains never makes keys or restarts
//! anything; a dedicated sending address is part of the SPF and PTR
//! records.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferropost_domain::domains::{self as rules, DnsRecords, Setup};
use ferropost_domain::mail::mx_hostname_fallback;
use ferropost_domain::settings::is_valid_hostname;
use ferropost_domain::spf::{self, SpfResult};
use ferropost_store::mailboxes::NewMailbox;
use futures_util::StreamExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "domains";
const REFRESH_EVERY: Duration = Duration::from_secs(300);
/// Domains whose records are checked at once.
pub const CHECKS_AT_ONCE: usize = 8;

/// A domain's mail host: its `a_record`, else `mail.<domain>`.
pub fn mail_host(domain: &str, a_record: &str) -> String {
    if a_record.is_empty() {
        mx_hostname_fallback(domain)
    } else {
        a_record.to_owned()
    }
}

async fn txt_holds(name: String, check: impl FnOnce(&[String]) -> bool) -> bool {
    crate::dns::txt(&name)
        .await
        .is_ok_and(|found| check(&found))
}

/// A domain's records, checked against DNS now.
pub async fn check(state: &AppState, domain: &str) -> DnsRecords {
    let pg = &state.store.pg;
    let host = ferropost_store::domains::format_mx(pg, domain)
        .await
        .unwrap_or_else(|_| mx_hostname_fallback(domain));
    let dedicated: Option<IpAddr> = ferropost_store::multi_ip::for_domain(pg, domain)
        .await
        .ok()
        .flatten()
        .and_then(|row| row.outbound_ip.parse().ok());
    let server_ip = crate::edge::server_public_ip(state).await;
    let (dkim, dkim_short) = tokio::join!(
        crate::dkim::record(state, domain, "default"),
        crate::dkim::record(state, domain, "short"),
    );
    let setup = Setup {
        domain,
        mail_host: &host,
        server_ip,
        dedicated_ip: dedicated,
        dkim: dkim.as_deref(),
        dkim_short: dkim_short.as_deref(),
    };
    let sending = setup.sending_ip().map(|ip| ip.to_canonical());
    let mut records = rules::expected(&setup);
    let (dkim_value, short_value) = (records.dkim.value.clone(), records.dkim_short.value.clone());
    let (a, mx, spf, dkim, dkim_short, dmarc, ptr) = tokio::join!(
        async {
            match sending {
                Some(ip) => crate::dns::addresses(&host)
                    .await
                    .is_ok_and(|found| found.iter().any(|a| a.to_canonical() == ip)),
                None => false,
            }
        },
        async {
            crate::dns::mx_hosts(domain)
                .await
                .is_ok_and(|found| found.iter().any(|mx| rules::same_host(mx, &host)))
        },
        async {
            match sending {
                Some(ip) => spf::check_host(&crate::dns::Dns, ip, domain).await == SpfResult::Pass,
                None => false,
            }
        },
        txt_holds(format!("default._domainkey.{domain}"), |found| {
            rules::dkim_published(found, &dkim_value)
        }),
        txt_holds(format!("short._domainkey.{domain}"), |found| {
            rules::dkim_published(found, &short_value)
        }),
        txt_holds(format!("_dmarc.{domain}"), rules::dmarc_published),
        async {
            match sending {
                Some(ip) => crate::dns::ptr_names(ip)
                    .await
                    .is_ok_and(|names| names.iter().any(|n| rules::same_host(n, &host))),
                None => false,
            }
        },
    );
    records.a.valid = a;
    records.mx.valid = mx;
    records.spf.valid = spf;
    records.dkim.valid = dkim;
    records.dkim_short.valid = dkim_short;
    records.dmarc.valid = dmarc;
    records.ptr.valid = ptr;
    records
}

/// A domain's records as last checked (at most ten minutes ago), checking
/// them now when they were not.
pub async fn records(state: &AppState, domain: &str) -> DnsRecords {
    let (st, name) = (state.clone(), domain.to_owned());
    state
        .caches
        .dns_records
        .get_with(domain.to_owned(), async move { check(&st, &name).await })
        .await
}

/// Checks a domain's records again now.
pub async fn refresh(state: &AppState, domain: &str) -> DnsRecords {
    let fresh = check(state, domain).await;
    state
        .caches
        .dns_records
        .insert(domain.to_owned(), fresh.clone())
        .await;
    fresh
}

/// Drops what is cached about a domain after it changed.
pub async fn forget(state: &AppState, domain: &str) {
    state.caches.dns_records.invalidate(domain).await;
    state.caches.base_urls.invalidate(domain).await;
}

/// Checks every domain's records (Go's `FreshRecords`).
pub async fn refresh_all(state: &AppState) -> Result<usize> {
    let names = ferropost_store::domains::names(&state.store.pg).await?;
    let count = names.len();
    futures_util::stream::iter(names)
        .map(|domain| async move {
            refresh(state, &domain).await;
        })
        .buffer_unordered(CHECKS_AT_ONCE)
        .collect::<Vec<()>>()
        .await;
    Ok(count)
}

/// The mailboxes every new domain gets (Go: abuse, postmaster, admin,
/// noreply and support), with random passwords. Returns those made.
pub async fn create_system_mailboxes(state: &AppState, domain: &str) -> Result<Vec<String>> {
    let domain_owned = domain.to_owned();
    let accounts =
        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String, String, String)>> {
            rules::SYSTEM_MAILBOXES
                .iter()
                .map(|local| {
                    let password = ferropost_sender::smtp::random_password();
                    let (hash, encoded) = ferropost_sender::smtp::mailbox_credentials(&password)?;
                    Ok((
                        (*local).to_owned(),
                        format!("{local}@{domain_owned}"),
                        hash,
                        encoded,
                    ))
                })
                .collect()
        })
        .await
        .map_err(|e| anyhow!("mailbox passwords: {e}"))??;
    let now = crate::routes::now();
    let rows: Vec<NewMailbox<'_>> = accounts
        .iter()
        .map(|(local, username, hash, encoded)| {
            NewMailbox::basic(
                username,
                local,
                domain,
                hash,
                encoded,
                rules::SYSTEM_MAILBOX_QUOTA,
                now,
            )
        })
        .collect();
    let created = ferropost_store::mailboxes::insert_many(&state.store.pg, &rows).await?;
    for username in &created {
        let local = username.split('@').next().unwrap_or_default();
        let dir = crate::maildir::dir(state, domain, local);
        match crate::maildir::ensure(&dir, rules::SYSTEM_MAILBOX_QUOTA, true) {
            Ok(true) => crate::maildir::recalc(state, username),
            Ok(false) => {}
            Err(err) => tracing::warn!(%username, %err, "maildir not prepared"),
        }
    }
    Ok(created)
}

/// Makes `host` the server's host name when none is set yet, as Go did
/// for the first domain. Returns whether it did; Postfix is told in the
/// background ([`tell_postfix_hostname`]).
pub async fn adopt_hostname(state: &AppState, host: &str) -> Result<bool> {
    let current = state
        .config
        .env
        .get("BILLIONMAIL_HOSTNAME")
        .unwrap_or_default();
    if !(current.is_empty() || current == "mail.example.com") {
        return Ok(false);
    }
    if !is_valid_hostname(host) {
        bail!("not a host name: {host:?}");
    }
    let (env, value) = (state.config.env.clone(), host.to_owned());
    tokio::task::spawn_blocking(move || env.update(&[("BILLIONMAIL_HOSTNAME", &value)]))
        .await
        .map_err(|e| anyhow!("update .env: {e}"))?
        .context("update BILLIONMAIL_HOSTNAME in .env")?;
    state.caches.base_urls.invalidate_all();
    Ok(true)
}

/// Postfix's container reads its host name from `/postfix.sh` when it
/// starts (its environment is fixed when the container is made): writes
/// it there and restarts Postfix (Go's `sed` through `bash -c`, here as
/// argument lists).
pub async fn tell_postfix_hostname(state: &AppState, host: &str) -> Result<()> {
    if !is_valid_hostname(host) {
        bail!("not a host name: {host:?}");
    }
    let container = &state.config.postfix_container;
    crate::docker::exec_ok(
        container,
        &["sed", "-i", "/^BILLIONMAIL_HOSTNAME=/d", "/postfix.sh"],
    )
    .await?;
    let line = format!("/^#!\\/bin\\/bash/a BILLIONMAIL_HOSTNAME={host}");
    crate::docker::exec_ok(container, &["sed", "-i", &line, "/postfix.sh"]).await?;
    crate::docker::restart_named(&state.config, container).await
}

/// Start-up repair, then the five-minute checks.
async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(1)) => {}
        _ = shutdown.changed() => return,
    }
    match crate::dkim::tighten_keys(&state).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(keys = n, "DKIM keys made readable by rspamd only"),
        Err(err) => tracing::warn!(error = %format!("{err:#}"), "DKIM keys not tightened"),
    }
    if let Err(err) = crate::dkim::sync_signing(&state).await {
        tracing::warn!(error = %format!("{err:#}"), "DKIM signing not repaired");
    }
    loop {
        if let Err(err) = refresh_all(&state).await {
            tracing::warn!(error = %format!("{err:#}"), "DNS records not checked");
        }
        tokio::select! {
            () = tokio::time::sleep(REFRESH_EVERY) => {}
            _ = shutdown.changed() => return,
        }
        // Keys lost since (Go made missing keys on every pass).
        if let Err(err) = ensure_all_keys(&state).await {
            tracing::warn!(error = %format!("{err:#}"), "DKIM keys not checked");
        }
    }
}

async fn ensure_all_keys(state: &AppState) -> Result<()> {
    let mut made = false;
    for domain in ferropost_store::domains::names(&state.store.pg).await? {
        if is_valid_hostname(&domain) {
            made |= crate::dkim::ensure_keys(state, &domain).await?;
        }
    }
    if made {
        crate::dkim::sync_signing(state).await?;
    }
    Ok(())
}

pub fn spawn(state: &AppState, shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("domains job started");
    vec![tokio::spawn(run(state.clone(), shutdown))]
}
