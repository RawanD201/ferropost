//! The mail services' main configuration files in the console's editor
//! (Go: `services/get_config`, `services/save_config`).
//!
//! Differences from Go: a saved file is checked by the service itself
//! (`postfix check`, `doveconf -n`, `rspamadm configtest`) and the previous
//! version is put back when the check fails, so a typo no longer stops mail
//! at the next restart; only the last ten backups are kept (Go kept one
//! more on every save); files over 3 MB are refused instead of truncated.

use std::future::Future;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ferropost_domain::mail_services::{KEEP_BACKUPS, MAX_CONFIG_BYTES, Service};
use serde::Serialize;

use crate::state::AppState;

/// The file behind a service, under the shared `conf/` directory.
pub fn path(state: &AppState, service: Service) -> PathBuf {
    let base = state.config.root.parent().unwrap_or(&state.config.root);
    base.join("conf").join(service.config_file())
}

/// What the editor shows (Go's `GetConfigFileRes`).
#[derive(Debug, Clone, Serialize)]
pub struct ConfigFile {
    pub config_path: String,
    pub content: String,
    pub encoding: &'static str,
    pub last_modified: i64,
    pub size: u64,
    pub only_read: bool,
}

/// Reads a configuration file; a very large one shows only its end and
/// cannot be saved. `None` when it does not exist.
pub fn read(path: &Path) -> Result<Option<ConfigFile>> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let only_read = meta.len() > MAX_CONFIG_BYTES;
    let content = if only_read {
        let start = bytes.len().saturating_sub(1_000_000);
        format!(
            "... (file too large, only show the last part) ...\n{}",
            String::from_utf8_lossy(&bytes[start..])
        )
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    Ok(Some(ConfigFile {
        config_path: path.display().to_string(),
        content,
        encoding: "utf-8",
        last_modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64),
        size: meta.len(),
        only_read,
    }))
}

/// A service's verdict on a saved file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Passed,
    /// The service rejected it: its output.
    Failed(String),
    /// The check could not run (container down, Docker unreachable).
    Unavailable(String),
}

/// The outcome of a save that went through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Saved {
    Checked,
    /// Saved, but the service could not check it: why.
    Unchecked(String),
}

/// A save that did not go through.
#[derive(Debug)]
pub enum SaveError {
    /// The service rejected the file; the previous one is back.
    Rejected(String),
    Failed(anyhow::Error),
}

fn backups(path: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Vec::new();
    };
    let prefix = format!("{}.bak.", name.to_string_lossy());
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect();
    // Timestamps sort as text: newest last.
    found.sort();
    found
}

/// Writes `content` in place (the files are mounted into the services'
/// containers one by one), keeping a timestamped backup, then asks
/// `check`; a rejected file is replaced by the previous one.
pub async fn save_checked<F, Fut>(path: &Path, content: &str, check: F) -> Result<Saved, SaveError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Check>,
{
    let previous = std::fs::read(path).ok();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create {}", dir.display()))
            .map_err(SaveError::Failed)?;
    }
    if let Some(previous) = &previous {
        let stamp = chrono::Local::now().format("%Y%m%d%H%M%S");
        let backup = PathBuf::from(format!("{}.bak.{stamp}", path.display()));
        std::fs::write(&backup, previous)
            .with_context(|| format!("back up {}", path.display()))
            .map_err(SaveError::Failed)?;
        let all = backups(path);
        for old in all.iter().take(all.len().saturating_sub(KEEP_BACKUPS)) {
            let _ = std::fs::remove_file(old);
        }
    }
    write(path, content.as_bytes()).map_err(SaveError::Failed)?;
    match check().await {
        Check::Passed => Ok(Saved::Checked),
        Check::Unavailable(why) => Ok(Saved::Unchecked(why)),
        Check::Failed(output) => {
            let restored = match &previous {
                Some(previous) => write(path, previous),
                None => std::fs::remove_file(path).map_err(anyhow::Error::from),
            };
            if let Err(err) = restored {
                tracing::error!(path = %path.display(), error = %format!("{err:#}"), "restoring the previous configuration failed");
            }
            Err(SaveError::Rejected(output))
        }
    }
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

/// Runs the service's own check in its container.
pub async fn check(state: &AppState, service: Service) -> Check {
    let container = match service {
        Service::Postfix => &state.config.postfix_container,
        Service::Dovecot => &state.config.dovecot_container,
        Service::Rspamd => &state.config.rspamd_container,
    };
    match crate::docker::exec_status(container, service.check_command()).await {
        Ok((_, _, Some(0))) => Check::Passed,
        Ok((stdout, stderr, _)) => {
            let mut output = format!("{}\n{}", stderr.trim(), stdout.trim())
                .trim()
                .to_owned();
            if output.len() > 2000 {
                let mut cut = 2000;
                while !output.is_char_boundary(cut) {
                    cut -= 1;
                }
                output.truncate(cut);
            }
            Check::Failed(output)
        }
        Err(err) => Check::Unavailable(format!("{err:#}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn restores_a_rejected_file() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("main.cf");
        std::fs::write(&path, "good = 1\n").expect("seed");
        let result = save_checked(&path, "bad", || async {
            Check::Failed("postfix: fatal: bad".into())
        })
        .await;
        assert!(matches!(result, Err(SaveError::Rejected(ref m)) if m.contains("fatal")));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "good = 1\n");

        let saved = save_checked(&path, "better = 2\n", || async { Check::Passed }).await;
        assert!(matches!(saved, Ok(Saved::Checked)));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "better = 2\n"
        );
        assert!(!backups(&path).is_empty());

        let fresh = dir.path().join("new.conf");
        let result = save_checked(&fresh, "x", || async { Check::Failed("no".into()) }).await;
        assert!(
            result.is_err() && !fresh.exists(),
            "a new rejected file is removed"
        );
    }

    #[test]
    fn prunes_backups() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("rspamd.conf");
        for i in 0..15 {
            std::fs::write(
                dir.path().join(format!("rspamd.conf.bak.2026010100{i:04}")),
                "",
            )
            .expect("backup");
        }
        let all = backups(&path);
        assert_eq!(all.len(), 15);
        assert!(all[0].to_string_lossy().ends_with("0000"));
    }
}
