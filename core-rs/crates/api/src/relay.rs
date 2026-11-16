//! SMTP relays in Postfix (Go: `service/relay`), and the `relay` job: the
//! one-off migration and sync at start-up (Go's `CheckRelayFirstSync`,
//! `EnsurePostfixConfExists`) and the connection checks every five
//! minutes (`UpdateRelayStatus`).
//!
//! Differences from Go: files are rewritten and Postfix reloaded only when
//! something changed (Go reloaded Postfix and restarted rspamd on every
//! edit); `sasl_passwd`, which holds the relay passwords in clear, is
//! readable by its owner only (Go: by everyone); the relay maps stay on
//! while dedicated-IP transports use them (Go removed them with the last
//! relay); the connection checks run (Go's read a table that no longer
//! exists, so every relay stayed "unknown" while the list said "Connected").

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferropost_domain::relay::{self as rules, Login, Relay};
use ferropost_store::relay::{self as store, RelayRow};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "relay";
const KEY_OPTION: &str = "relay_encryption_key";
const CHECK_EVERY: Duration = Duration::from_secs(300);
const CHECKS_AT_ONCE: usize = 5;

/// One sync at a time: it rewrites shared files.
static SYNC: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A relay's last connection check, as the console shows it.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub status: bool,
    pub msg: String,
}

// ---- passwords -----------------------------------------------------------------

/// The key relay passwords are encrypted with (created on first use, as
/// Go did). A stored key that is not valid is an error rather than being
/// replaced, which would make every stored password unreadable.
async fn key(state: &AppState) -> Result<[u8; 16]> {
    let fresh = {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let stored = ferropost_store::options::get_or_init(&state.store.pg, KEY_OPTION, &fresh).await?;
    rules::password_key(&stored).ok_or_else(|| anyhow!("{KEY_OPTION} is not a valid key"))
}

pub async fn encrypt(state: &AppState, password: &str) -> Result<String> {
    Ok(rules::encrypt_password(&key(state).await?, password))
}

pub async fn decrypt(state: &AppState, stored: &str) -> Result<String> {
    rules::decrypt_password(&key(state).await?, stored)
        .ok_or_else(|| anyhow!("the stored relay password cannot be decrypted"))
}

fn as_relay(row: &RelayRow) -> Relay {
    Relay {
        id: row.id,
        relay_host: row.relay_host.clone(),
        relay_port: row.relay_port.clone(),
        auth_user: row.auth_user.clone(),
        auth_method: row.auth_method.clone(),
        helo_name: row.helo_name.clone(),
        smtp_name: row.smtp_name.clone(),
        skip_tls_verify: row.skip_tls_verify == 1,
    }
}

// ---- files ---------------------------------------------------------------------

/// Writes `content` when it differs. `main.cf` and `master.cf` are mounted
/// into the Postfix container as single files, so they are rewritten in
/// place (a rename would leave Postfix on the old file); the others are
/// replaced atomically.
fn write_if_changed(path: &Path, content: &str, mode: Option<u32>) -> Result<bool> {
    if std::fs::read_to_string(path).is_ok_and(|current| current == content) {
        return Ok(false);
    }
    match mode {
        Some(mode) => crate::fsio::write_atomic(path, content.as_bytes(), mode),
        None => std::fs::write(path, content),
    }
    .with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

fn create_if_missing(path: &Path, content: &str, mode: u32) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    crate::fsio::write_atomic(path, content.as_bytes(), mode)
        .with_context(|| format!("create {}", path.display()))?;
    Ok(true)
}

fn conf(state: &AppState, name: &str) -> PathBuf {
    state.config.postfix_conf_dir.join(name)
}

/// Writes the relay settings to Postfix and rspamd and reloads what
/// changed (Go's `SyncRelayConfigsToPostfix`).
pub async fn sync(state: &AppState) -> Result<()> {
    let _one = SYNC.lock().await;
    let pg = &state.store.pg;
    let rows = store::active(pg).await?;
    let relays: Vec<Relay> = rows.iter().map(as_relay).collect();
    let names = rules::service_names(&relays);

    // Which transport each bound sender domain uses (read live by Postfix).
    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    let routes: Vec<(String, String)> = store::domains_of(pg, &ids)
        .await?
        .into_iter()
        .filter_map(|(id, domain)| {
            let at = ids.iter().position(|i| *i == id)?;
            Some((format!("@{domain}"), names[at].clone()))
        })
        .collect();
    store::replace_relay_transports(pg, &routes).await?;
    let enabled = !rows.is_empty() || store::other_transports(pg).await?;

    let mut logins: Vec<(String, String, String, String)> = Vec::new();
    for row in rows.iter().filter(|r| !r.auth_user.is_empty()) {
        match decrypt(state, &row.auth_password).await {
            Ok(password) => logins.push((
                row.relay_host.clone(),
                row.relay_port.clone(),
                row.auth_user.clone(),
                password,
            )),
            Err(err) => {
                tracing::warn!(relay = row.id, error = %format!("{err:#}"), "relay skipped")
            }
        }
    }
    let env = &state.config.env;
    let (db_user, db_pass, db_name) = (
        env.get("DBUSER")
            .unwrap_or_else(|| state.config.database.user.clone()),
        env.get("DBPASS").unwrap_or_default(),
        env.get("DBNAME")
            .unwrap_or_else(|| state.config.database.name.clone()),
    );

    let state2 = state.clone();
    let changed = tokio::task::spawn_blocking(move || -> Result<bool> {
        let state = &state2;
        let dir = &state.config.postfix_conf_dir;
        if !dir.is_dir() {
            bail!("Postfix configuration directory does not exist: {}", dir.display());
        }
        std::fs::create_dir_all(dir.join("conf"))?;
        std::fs::create_dir_all(dir.join("sql"))?;
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let mut changed = false;

        let login_refs: Vec<Login<'_>> = logins
            .iter()
            .map(|(host, port, user, password)| Login {
                host,
                port,
                user,
                password,
            })
            .collect();
        let sasl = rules::sasl_passwd(!relays.is_empty(), &login_refs);
        changed |= write_if_changed(&conf(state, "conf/sasl_passwd"), &sasl, Some(0o600))?;
        changed |= create_if_missing(
            &conf(state, "conf/sender_relay_maps_primary"),
            &format!("# Created on {now}\n# This file maps sender domains to relay hosts\n"),
            0o644,
        )?;
        changed |= create_if_missing(
            &conf(state, "conf/sasl_passwd_primary"),
            &format!(
                "# Created on {now}\n# This file contains SASL authentication credentials for relay hosts\n"
            ),
            0o600,
        )?;
        for (file, content) in rules::sql_maps(&db_user, &db_pass, &db_name) {
            changed |= create_if_missing(&dir.join("sql").join(file), &content, 0o644)?;
        }

        let master = conf(state, "master.cf");
        match std::fs::read_to_string(&master) {
            Ok(current) => {
                changed |= write_if_changed(&master, &rules::apply_master(&current, &relays), None)?;
            }
            Err(_) => tracing::warn!(path = %master.display(), "master.cf missing; relay transports not written"),
        }
        let main = conf(state, "main.cf");
        let current = std::fs::read_to_string(&main).unwrap_or_default();
        changed |= write_if_changed(&main, &rules::apply_main(&current, enabled), None)?;

        // Postfix needs the compiled maps too.
        for map in ["sasl_passwd", "sasl_passwd_primary", "sender_relay_maps_primary"] {
            changed |= !conf(state, &format!("conf/{map}.db")).exists();
        }
        Ok(changed)
    })
    .await
    .map_err(|e| anyhow!("relay sync: {e}"))??;

    if changed {
        reload_postfix(state).await?;
    }
    if let Err(err) = sync_dkim_signing(state).await {
        tracing::warn!(error = %format!("{err:#}"), "DKIM signing config not updated");
    }
    Ok(())
}

async fn reload_postfix(state: &AppState) -> Result<()> {
    let container = &state.config.postfix_container;
    for cmd in [
        &["postmap", "/etc/postfix/conf/sender_relay_maps_primary"][..],
        &["postmap", "/etc/postfix/conf/sasl_passwd_primary"],
        &["postmap", "/etc/postfix/conf/sasl_passwd"],
        &["postfix", "reload"],
    ] {
        crate::docker::exec_ok(container, cmd).await?;
    }
    Ok(())
}

/// rspamd signs every domain except those sent through an active relay,
/// whose provider signs them (Go's `RepairDKIMSigningConfig`; generating
/// missing keys stays with the domains service). Restarts rspamd only when
/// the file changed. Returns whether it did.
pub async fn sync_dkim_signing(state: &AppState) -> Result<bool> {
    let dir = state.config.rspamd_local_d.clone();
    if !dir.is_dir() {
        tracing::debug!(path = %dir.display(), "rspamd local.d missing; DKIM signing not written");
        return Ok(false);
    }
    let pg = &state.store.pg;
    let relayed = store::relayed_domains(pg).await?;
    let domains: Vec<String> = store::all_domains(pg)
        .await?
        .into_iter()
        .filter(|d| !relayed.contains(&d.to_ascii_lowercase()))
        .collect();
    let keys = state.config.rspamd_data_dir.join("dkim");
    for domain in &domains {
        for selector in ["default", "short"] {
            if !keys
                .join(domain)
                .join(format!("{selector}.private"))
                .exists()
            {
                tracing::warn!(%domain, selector, "DKIM key missing");
            }
        }
    }
    let path = dir.join("dkim_signing.conf");
    // Go writes the same file in its own domain order: the same domains in
    // another order is no change (rewriting would restart rspamd each time
    // either core wrote it).
    let mut wanted = domains.clone();
    wanted.sort();
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    if current.starts_with("sign_headers") && rules::dkim_signed_domains(&current) == wanted {
        return Ok(false);
    }
    let content = rules::dkim_signing_conf(&domains);
    let changed = tokio::task::spawn_blocking(move || write_if_changed(&path, &content, None))
        .await
        .map_err(|e| anyhow!("write DKIM signing config: {e}"))??;
    if changed {
        crate::docker::restart_named(&state.config, &state.config.rspamd_container).await?;
    }
    Ok(changed)
}

/// Go's one-off migration of hand-written transport maps, then a sync.
/// Shares Go's marker file, so it runs once whichever core did it.
async fn first_sync(state: &AppState) -> Result<()> {
    let marker = state
        .config
        .root
        .join("data/SMTP_relay_sync_config_mark2.pl");
    if !marker.exists() {
        let main = conf(state, "main.cf");
        if let Ok(current) = std::fs::read_to_string(&main) {
            write_if_changed(&main, &rules::migrate_main(&current), None)?;
        }
    }
    sync(state).await?;
    if !marker.exists() {
        if let Some(dir) = marker.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(
            &marker,
            format!(
                "First sync completed at {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            ),
        )?;
    }
    Ok(())
}

// ---- connection checks --------------------------------------------------------

/// HELO name for tests: the console's host name.
fn hello(state: &AppState) -> String {
    state
        .config
        .env
        .get("BILLIONMAIL_HOSTNAME")
        .filter(|h| rules::valid_host(h))
        .unwrap_or_else(|| "localhost".to_owned())
}

/// Tests a relay with a login in clear. The error is the console message.
pub async fn test(
    state: &AppState,
    host: &str,
    port: &str,
    user: &str,
    password: &str,
) -> std::result::Result<ferropost_sender::smtp::Probe, String> {
    let (host, port) = (host.trim(), port.trim());
    if host.is_empty() || port.is_empty() {
        return Err("SMTP host and port are required.".to_owned());
    }
    if !user.is_empty() && password.is_empty() {
        return Err("Password is required when username is provided.".to_owned());
    }
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| "SMTP port must be between 1 and 65535".to_owned())?;
    let login = (!user.is_empty()).then_some((user, password));
    ferropost_sender::smtp::probe(host, port, login, &hello(state))
        .await
        .map_err(|e| format!("SMTP connection failed: {e:#}"))
}

/// Checks one relay and remembers the result.
pub async fn check(state: &AppState, row: &RelayRow) -> Status {
    let password = if row.auth_user.is_empty() {
        Ok(String::new())
    } else {
        decrypt(state, &row.auth_password)
            .await
            .map_err(|e| format!("{e:#}"))
    };
    let status = match password {
        Ok(password) => match test(
            state,
            &row.relay_host,
            &row.relay_port,
            &row.auth_user,
            &password,
        )
        .await
        {
            Ok(_) => Status {
                status: true,
                msg: "Connection normal".to_owned(),
            },
            Err(msg) => Status { status: false, msg },
        },
        Err(msg) => Status { status: false, msg },
    };
    state
        .caches
        .relay_status
        .insert(row.id, status.clone())
        .await;
    status
}

/// Checks a relay in the background (after it is created or changed).
pub fn check_soon(state: &AppState, id: i64) {
    let state = state.clone();
    tokio::spawn(async move {
        state.caches.relay_status.invalidate(&id).await;
        if let Ok(Some(row)) = store::get(&state.store.pg, id).await
            && row.active == 1
        {
            check(&state, &row).await;
        }
    });
}

/// The status the console shows for a relay.
pub async fn status_of(state: &AppState, row: &RelayRow) -> Status {
    if row.active != 1 {
        return Status {
            status: false,
            msg: "Relay is disabled".to_owned(),
        };
    }
    state
        .caches
        .relay_status
        .get(&row.id)
        .await
        .unwrap_or_else(|| Status {
            status: false,
            msg: "Status unknown (under check)".to_owned(),
        })
}

async fn check_all(state: &AppState) -> Result<()> {
    let rows = store::active(&state.store.pg).await?;
    futures_util::stream::iter(rows)
        .for_each_concurrent(CHECKS_AT_ONCE, |row| {
            let state = state.clone();
            async move {
                let status = check(&state, &row).await;
                tracing::debug!(relay = row.id, ok = status.status, msg = %status.msg, "relay checked");
            }
        })
        .await;
    Ok(())
}

pub fn spawn(state: &AppState, mut shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("relay job started");
    let start = state.clone();
    let checks = state.clone();
    vec![
        tokio::spawn(async move {
            if let Err(err) = first_sync(&start).await {
                tracing::warn!(error = %format!("{err:#}"), "relay start-up sync failed");
            }
        }),
        tokio::spawn(async move {
            let mut wait = Duration::from_secs(10);
            loop {
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    _ = shutdown.changed() => return,
                }
                if let Err(err) = check_all(&checks).await {
                    tracing::warn!(error = %format!("{err:#}"), "relay checks failed");
                }
                wait = CHECK_EVERY;
            }
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_only_changes() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("main.cf");
        assert!(write_if_changed(&path, "a\n", None).expect("write"));
        assert!(!write_if_changed(&path, "a\n", None).expect("same"));
        assert!(write_if_changed(&path, "b\n", Some(0o600)).expect("change"));
        assert!(!create_if_missing(&path, "c\n", 0o600).expect("exists"));
    }
}
