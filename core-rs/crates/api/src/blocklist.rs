//! DNS blocklist checks of the mail hosts (Go: `domains/blacklist.go`),
//! and the `blacklist` job (Go's `CheckDomainsBlacklist`).
//!
//! Differences from Go:
//! - Lists are queried 16 at a time through the system resolver, and "no
//!   record" is a definite answer: Go asked Google's resolver one list after
//!   another, retrying and sleeping on every clean list, so a check took
//!   minutes, and Spamhaus refuses public resolvers (its refusal counted as
//!   passed, so a Spamhaus listing never showed).
//! - The log route reads check logs only (Go returned any file named in the
//!   request, `.env` and its passwords included).
//! - The daily scan remembers when it last ran, so restarts neither skip
//!   nor repeat it.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferropost_domain::blocklist::{self as rules, Answer, CheckResult, Listing, Verdict, ZONES};
use ferropost_domain::settings::AlertSettings;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "blacklist";
const QUERIES_AT_ONCE: usize = 16;
const LAST_SCAN_OPTION: &str = "ferropost_blocklist_last_scan";
const DAY: i64 = 86_400;

static RESULTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn data_dir(state: &AppState) -> PathBuf {
    state.config.root.join("data")
}

fn now_text() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// The address to check for a mail host: its first IPv4 address, or the
/// server's own when it resolves to loopback.
pub async fn address_of(state: &AppState, host: &str) -> Result<Ipv4Addr> {
    let ip = crate::dns::first_ipv4(host)
        .await
        .ok_or_else(|| anyhow!("resolve failed: {host} has no address record"))?;
    if ip.is_loopback()
        && let Some(IpAddr::V4(public)) = crate::edge::server_public_ip(state).await
    {
        return Ok(public);
    }
    Ok(ip)
}

/// Checks `ip` on every list, writing the log as answers arrive and the
/// result where the domain list reads it.
pub async fn check(state: &AppState, host: &str, ip: Ipv4Addr) -> Result<CheckResult> {
    check_on(state, host, ip, ZONES).await
}

/// [`check`] on the given lists.
pub async fn check_on(
    state: &AppState,
    host: &str,
    ip: Ipv4Addr,
    lists: &[&str],
) -> Result<CheckResult> {
    let dir = data_dir(state);
    tokio::fs::create_dir_all(&dir).await?;
    let log_path = dir.join(rules::log_file(host));
    let mut log = tokio::fs::File::create(&log_path)
        .await
        .with_context(|| format!("create {}", log_path.display()))?;
    log.write_all(format!("{}:  Start checking... \n", now_text()).as_bytes())
        .await?;
    let mut result = CheckResult {
        domain: host.to_owned(),
        ip: ip.to_string(),
        time: chrono::Utc::now().timestamp(),
        tested: lists.len() as i64,
        ..CheckResult::default()
    };
    let zones: Vec<String> = lists.iter().map(|z| (*z).to_owned()).collect();
    let mut answers = futures_util::stream::iter(zones)
        .map(move |zone| query(ip, zone))
        .buffer_unordered(QUERIES_AT_ONCE);
    while let Some((zone, answer)) = answers.next().await {
        let verdict = rules::classify(&answer);
        match verdict {
            Verdict::Clear => result.passed += 1,
            Verdict::Invalid => result.invalid += 1,
            Verdict::Listed => {
                result.blacklisted += 1;
                let response = match &answer {
                    Answer::Address(a) => a.to_string(),
                    _ => String::new(),
                };
                result.black_list.push(Listing {
                    blacklist: zone.clone(),
                    response,
                    time: chrono::Utc::now().timestamp(),
                });
            }
        }
        log.write_all(rules::log_line(&now_text(), &zone, &answer, verdict).as_bytes())
            .await?;
    }
    log.write_all(rules::log_summary(&now_text(), &result).as_bytes())
        .await?;
    log.flush().await?;
    store_result(state, &result).await?;
    if result.blacklisted > 0 {
        let (state, result) = (state.clone(), result.clone());
        tokio::spawn(async move {
            if let Err(err) = alert(&state, &result).await {
                tracing::warn!(error = %format!("{err:#}"), "blocklist alert not sent");
            }
        });
    }
    Ok(result)
}

async fn query(ip: Ipv4Addr, zone: String) -> (String, Answer) {
    let answer = crate::dns::dnsbl(&rules::query_name(ip, &zone)).await;
    (zone, answer)
}

/// `data/blcheck_count.json`: the latest result per mail host.
async fn store_result(state: &AppState, result: &CheckResult) -> Result<()> {
    let _one = RESULTS.lock().await;
    let path = data_dir(state).join("blcheck_count.json");
    let mut all: serde_json::Map<String, serde_json::Value> = tokio::fs::read(&path)
        .await
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default();
    all.insert(result.domain.clone(), serde_json::to_value(result)?);
    let json = serde_json::to_vec(&all)?;
    tokio::task::spawn_blocking(move || crate::fsio::write_atomic(&path, &json, 0o644))
        .await
        .map_err(|e| anyhow!("save blocklist result: {e}"))??;
    Ok(())
}

/// The latest result for a mail host.
pub async fn result_for(state: &AppState, host: &str) -> Option<CheckResult> {
    let raw = tokio::fs::read(data_dir(state).join("blcheck_count.json"))
        .await
        .ok()?;
    let mut all: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&raw).ok()?;
    serde_json::from_value(all.remove(host)?).ok()
}

/// The path of a mail host's check log, as the domain list shows it.
pub fn log_path(state: &AppState, host: &str) -> String {
    data_dir(state)
        .join(rules::log_file(host))
        .display()
        .to_string()
}

/// A check log by the path the console got from the domain list; only
/// files of this module are served. Empty when there is none yet.
pub async fn read_log(state: &AppState, path: &str) -> Result<String> {
    let name = std::path::Path::new(path.trim())
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("not a check log"))?;
    let host = rules::host_of_log(name).ok_or_else(|| anyhow!("not a check log"))?;
    let dir = data_dir(state);
    let parent = std::path::Path::new(path.trim()).parent();
    if let Some(parent) = parent.filter(|p| !p.as_os_str().is_empty()) {
        let wanted = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if parent.canonicalize().ok().as_deref() != Some(wanted.as_path()) {
            bail!("not a check log");
        }
    }
    Ok(tokio::fs::read_to_string(dir.join(rules::log_file(host)))
        .await
        .unwrap_or_default())
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Mails the alert recipients about a listing (Go: `sendBlacklistAlert`).
pub async fn alert(state: &AppState, result: &CheckResult) -> Result<()> {
    let pg = &state.store.pg;
    if !ferropost_store::options::get_bool(pg, "blacklist_alert_enabled")
        .await?
        .unwrap_or(false)
    {
        return Ok(());
    }
    let raw = tokio::fs::read(data_dir(state).join("blacklist_alert_settings.json"))
        .await
        .context("alert settings file not found")?;
    let settings: AlertSettings = serde_json::from_slice(&raw).context("alert settings")?;
    if settings.sender_email.is_empty()
        || settings.smtp_server.is_empty()
        || settings.recipient_list.is_empty()
    {
        bail!("alert settings incomplete");
    }
    let mailer = ferropost_sender::smtp::Mailer::external(&ferropost_sender::smtp::SmtpConfig {
        host: settings.smtp_server.clone(),
        port: u16::try_from(settings.smtp_port).unwrap_or(587),
        username: settings.sender_email.clone(),
        password: settings.smtp_password.clone(),
    })?;
    let items: String = result
        .black_list
        .iter()
        .enumerate()
        .map(|(i, l)| {
            format!(
                "<li><strong>{}. {}</strong> (Response: {})</li>",
                i + 1,
                escape(&l.blacklist),
                escape(&l.response)
            )
        })
        .collect();
    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Blacklist Detection Alert</title></head>
<body style="background:#f5f5f5;margin:0;font-family:Arial,sans-serif;color:#1f2937">
<div style="max-width:620px;margin:24px auto;background:#fff;border-radius:8px;padding:28px">
<h2 style="margin:0 0 16px;color:#dc2626">Blacklist alert: {host}</h2>
<p>The address {ip} of {host} is listed on {count} of {tested} blocklists:</p>
<ul>{items}</ul>
<p style="color:#6b7280">Checked {time}.</p>
</div></body></html>"#,
        host = escape(&result.domain),
        ip = escape(&result.ip),
        count = result.blacklisted,
        tested = result.tested,
        time = now_text(),
    );
    let mut failed = Vec::new();
    for to in &settings.recipient_list {
        let mail = ferropost_sender::smtp::Outgoing {
            from_email: settings.sender_email.clone(),
            from_name: Some(settings.name.clone()),
            to: vec![to.clone()],
            subject: format!("⚠️ Blacklist Alert - {}", result.domain),
            html: html.clone(),
            headers: Vec::new(),
            message_id: ferropost_sender::smtp::message_id(&settings.sender_email),
        };
        if mailer.send(&mail).await.is_err() {
            failed.push(to.as_str());
        }
    }
    if !failed.is_empty() {
        bail!("failed to send the alert to {}", failed.join(", "));
    }
    Ok(())
}

/// One pass over every mail host, spread over the day as Go did (three
/// hours apart for up to eight domains).
async fn scan_all(state: &AppState, shutdown: &mut watch::Receiver<bool>) -> Result<()> {
    let pg = &state.store.pg;
    if !ferropost_store::options::get_bool(pg, "blacklist_auto_scan_enabled")
        .await?
        .unwrap_or(true)
    {
        return Ok(());
    }
    let domains = ferropost_store::domains::names(pg).await?;
    let gap = if domains.len() <= 8 {
        Duration::from_secs(3 * 3600)
    } else {
        Duration::from_secs((DAY as u64) / domains.len() as u64)
    };
    for (i, domain) in domains.iter().enumerate() {
        let host = ferropost_store::domains::format_mx(pg, domain).await?;
        match address_of(state, &host).await {
            Ok(ip) => {
                if let Err(err) = check(state, &host, ip).await {
                    tracing::warn!(%host, error = %format!("{err:#}"), "blocklist check failed");
                }
            }
            Err(err) => {
                tracing::debug!(%host, error = %format!("{err:#}"), "blocklist check skipped")
            }
        }
        if i + 1 < domains.len() {
            tokio::select! {
                () = tokio::time::sleep(gap) => {}
                _ = shutdown.changed() => return Ok(()),
            }
        }
    }
    Ok(())
}

pub fn spawn(state: &AppState, mut shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("blacklist job started");
    let state = state.clone();
    vec![tokio::spawn(async move {
        loop {
            let pg = &state.store.pg;
            let now = chrono::Utc::now().timestamp();
            let last = ferropost_store::options::get(pg, LAST_SCAN_OPTION)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            // First pass ten minutes after start when one is due.
            let due_in = (last + DAY - now).max(600);
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(due_in as u64)) => {}
                _ = shutdown.changed() => return,
            }
            let started = chrono::Utc::now().timestamp();
            let _ = ferropost_store::options::set(pg, LAST_SCAN_OPTION, &started.to_string()).await;
            if let Err(err) = scan_all(&state, &mut shutdown).await {
                tracing::warn!(error = %format!("{err:#}"), "blocklist scan failed");
            }
            if *shutdown.borrow() {
                return;
            }
        }
    })]
}
