//! Postfix's shared files and commands (Go: `service/mail_service`), and
//! the `mail_services` job: the start-up repair of `main.cf` (Go's
//! `FixPostfixMainConfig`).
//!
//! Every edit of `main.cf` from this process goes through one lock (relays,
//! BCC maps, queue settings, the editor, the repair), and Postfix is only
//! reloaded when a file actually changed (Go reloaded on every request).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use ferropost_domain::postfix as rules;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "mail_services";

static MAIN_CF: Mutex<()> = Mutex::new(());

/// Writes `content` when it differs. `main.cf` and `master.cf` are mounted
/// into the Postfix container as single files, so they are rewritten in
/// place (`mode: None`; a rename would leave Postfix on the old file); the
/// others are replaced atomically with `mode`.
pub fn write_if_changed(path: &Path, content: &str, mode: Option<u32>) -> Result<bool> {
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

pub fn create_if_missing(path: &Path, content: &str, mode: u32) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    crate::fsio::write_atomic(path, content.as_bytes(), mode)
        .with_context(|| format!("create {}", path.display()))?;
    Ok(true)
}

/// A file under Postfix's configuration directory.
pub fn conf(state: &AppState, name: &str) -> PathBuf {
    state.config.postfix_conf_dir.join(name)
}

/// Applies `edit` to `main.cf` under the lock and writes the result in
/// place when it changed. Blocking: call it from blocking code.
pub fn edit_main_cf_at(path: &Path, edit: impl FnOnce(&str) -> String) -> Result<bool> {
    let _one = MAIN_CF.lock().unwrap_or_else(|e| e.into_inner());
    let current = std::fs::read_to_string(path).unwrap_or_default();
    let next = edit(&current);
    write_if_changed(path, &next, None)
}

/// [`edit_main_cf_at`] for the shared `main.cf`, off the async runtime.
pub async fn edit_main_cf(
    state: &AppState,
    edit: impl FnOnce(&str) -> String + Send + 'static,
) -> Result<bool> {
    let path = conf(state, "main.cf");
    tokio::task::spawn_blocking(move || edit_main_cf_at(&path, edit))
        .await
        .map_err(|e| anyhow!("edit main.cf: {e}"))?
}

/// Runs a command in the Postfix container and fails unless it succeeds.
pub async fn run(state: &AppState, cmd: &[&str]) -> Result<String> {
    crate::docker::exec_ok(&state.config.postfix_container, cmd).await
}

/// Compiles the given maps (`conf/<name>`) and reloads Postfix.
pub async fn reload(state: &AppState, maps: &[&str]) -> Result<()> {
    for map in maps {
        let path = format!("/etc/postfix/conf/{map}");
        run(state, &["postmap", &path]).await?;
    }
    run(state, &["postfix", "reload"]).await?;
    Ok(())
}

/// Writes the BCC maps and declares them in `main.cf` (Go's
/// `SyncBccToPostfix`); reloads Postfix when something changed.
pub async fn sync_bcc(state: &AppState) -> Result<()> {
    let pg = &state.store.pg;
    let sender = rules::bcc_map(&ferropost_store::mail_services::bcc_active(pg, "sender").await?);
    let recipient =
        rules::bcc_map(&ferropost_store::mail_services::bcc_active(pg, "recipient").await?);
    let dir = state.config.postfix_conf_dir.clone();
    let main = conf(state, "main.cf");
    let changed = tokio::task::spawn_blocking(move || -> Result<bool> {
        if !dir.is_dir() {
            anyhow::bail!(
                "Postfix configuration directory does not exist: {}",
                dir.display()
            );
        }
        std::fs::create_dir_all(dir.join("conf"))?;
        let mut changed = false;
        for (name, content) in [("sender_bcc", &sender), ("recipient_bcc", &recipient)] {
            let path = dir.join("conf").join(name);
            changed |= write_if_changed(&path, content, Some(0o644))?;
            changed |= !dir.join("conf").join(format!("{name}.db")).exists();
        }
        changed |= edit_main_cf_at(&main, rules::ensure_bcc_maps)?;
        Ok(changed)
    })
    .await
    .map_err(|e| anyhow!("BCC sync: {e}"))??;
    if changed {
        reload(state, &["sender_bcc", "recipient_bcc"]).await?;
    }
    Ok(())
}

/// The host name Postfix should announce: the console's mail host name,
/// else the oldest domain's mail host (Go used the domain itself).
async fn mail_host_name(state: &AppState) -> Result<String> {
    if let Some(name) = state
        .config
        .env
        .get("BILLIONMAIL_HOSTNAME")
        .filter(|h| h != "mail.example.com" && ferropost_domain::settings::is_valid_hostname(h))
    {
        return Ok(name);
    }
    let pg = &state.store.pg;
    match ferropost_store::domains::first_active(pg).await? {
        Some(domain) => Ok(ferropost_store::domains::mail_hostname(pg, &domain)
            .await?
            .unwrap_or_else(|| ferropost_domain::mail::mx_hostname_fallback(&domain))),
        None => Ok("localhost".to_owned()),
    }
}

/// Go's `FixPostfixMainConfig`: header checks, the server name and a real
/// `myhostname`; reloads Postfix only when a file changed.
pub async fn fix_main_config(state: &AppState) -> Result<bool> {
    let hostname = mail_host_name(state).await?;
    let checks = conf(state, "conf/header_checks");
    let main = conf(state, "main.cf");
    let changed = tokio::task::spawn_blocking(move || -> Result<bool> {
        if !main.exists() {
            return Ok(false);
        }
        let mut changed = false;
        let existing = std::fs::read_to_string(&checks).ok();
        if let Some(content) = rules::fix_header_checks(existing.as_deref()) {
            if let Some(dir) = checks.parent() {
                std::fs::create_dir_all(dir)?;
            }
            changed |= write_if_changed(&checks, &content, Some(0o644))?;
        }
        changed |= edit_main_cf_at(&main, |c| rules::fix_main_cf(c, &hostname))?;
        Ok(changed)
    })
    .await
    .map_err(|e| anyhow!("main.cf repair: {e}"))??;
    if changed {
        run(state, &["postfix", "reload"]).await?;
    }
    Ok(changed)
}

/// Runs `command <id>` for each queue ID in one `docker exec`; returns the
/// IDs that failed. IDs must have passed [`rules::valid_queue_id`].
pub async fn per_queue_id(state: &AppState, command: &str, ids: &[String]) -> Result<Vec<String>> {
    let container = &state.config.postfix_container;
    let mut failed = Vec::new();
    for chunk in ids.chunks(500) {
        let script = rules::per_id_script(command);
        let mut cmd: Vec<&str> = vec!["sh", "-c", &script, "sh"];
        cmd.extend(chunk.iter().map(String::as_str));
        let (stdout, stderr, code) = crate::docker::exec_status(container, &cmd).await?;
        match code {
            Some(0) => {}
            Some(1) => failed.extend(
                stdout
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned),
            ),
            other => anyhow::bail!("{command} failed (exit {other:?}): {}", stderr.trim()),
        }
    }
    Ok(failed)
}

pub fn spawn(state: &AppState, mut shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("mail services job started");
    let state = state.clone();
    vec![tokio::spawn(async move {
        // Go ran it five seconds after start, once.
        tokio::select! {
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            _ = shutdown.changed() => return,
        }
        match fix_main_config(&state).await {
            Ok(true) => tracing::info!("main.cf repaired"),
            Ok(false) => {}
            Err(err) => tracing::warn!(error = %format!("{err:#}"), "main.cf repair failed"),
        }
    })]
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
        assert!(edit_main_cf_at(&path, |c| format!("{c}x = 1\n")).expect("edit"));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "b\nx = 1\n");
        assert!(!edit_main_cf_at(&path, str::to_owned).expect("same"));
    }
}
