//! Maildir files the core keeps for Dovecot (Go: `ensureMaildirAndQuotaFile`,
//! `updateMaildirQuotaHeader`, `recalcQuotaAsync`): the directory and the
//! `maildirsize` file whose first line is the quota.

use std::io;
use std::path::{Path, PathBuf};

use ferropost_domain::mailboxes::{new_maildirsize, used_bytes, with_quota};

use crate::state::AppState;

/// Dovecot's `vmail` user and `mail` group.
const OWNER: (u32, u32) = (150, 8);

/// `<vmail>/<domain>/<local part>`, Dovecot's `/var/vmail/%d/%n`.
pub fn dir(state: &AppState, domain: &str, local_part: &str) -> PathBuf {
    state.config.vmail_dir.join(domain).join(local_part)
}

fn chown(path: &Path) {
    // Possible only as root (the container); ignored in development.
    let _ = std::os::unix::fs::chown(path, Some(OWNER.0), Some(OWNER.1));
}

fn write_atomically(path: &Path, content: &str) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)?;
    chown(&tmp);
    std::fs::rename(tmp, path)
}

/// Creates the maildir and `maildirsize` with the quota, or updates the
/// quota line of an existing file. Returns whether usage needs counting.
pub fn ensure(dir: &Path, quota: i64, quota_active: bool) -> io::Result<bool> {
    std::fs::create_dir_all(dir)?;
    chown(dir);
    let file = dir.join("maildirsize");
    match std::fs::read_to_string(&file) {
        Ok(existing) => {
            let updated = with_quota(&existing, quota, quota_active);
            if updated != existing {
                write_atomically(&file, &updated)?;
            }
            Ok(updated != existing)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            write_atomically(&file, &new_maildirsize(quota, quota_active))?;
            Ok(true)
        }
        Err(err) => Err(err),
    }
}

/// Bytes in use according to `maildirsize`, if readable.
pub fn used(dir: &Path) -> Option<i64> {
    used_bytes(&std::fs::read_to_string(dir.join("maildirsize")).ok()?)
}

/// Has Dovecot recount a mailbox's usage, in the background.
pub fn recalc(state: &AppState, username: &str) {
    let container = state.config.dovecot_container.clone();
    let username = username.to_owned();
    tokio::spawn(async move {
        if let Err(err) = recalc_now(&container, &username).await {
            tracing::debug!(%username, error = %format!("{err:#}"), "doveadm quota recalc failed");
        }
    });
}

pub async fn recalc_now(container: &str, username: &str) -> anyhow::Result<()> {
    crate::docker::exec(container, &["doveadm", "quota", "recalc", "-u", username]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_updates_quota_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("x.com").join("a");
        assert!(ensure(&dir, 100, true).expect("create"));
        assert_eq!(
            std::fs::read_to_string(dir.join("maildirsize")).expect("read"),
            "100S\n0 0\n"
        );
        std::fs::write(dir.join("maildirsize"), "100S\n2048 3\n").expect("usage");
        assert!(!ensure(&dir, 100, true).expect("unchanged"));
        assert!(ensure(&dir, 900, true).expect("update"));
        assert_eq!(
            std::fs::read_to_string(dir.join("maildirsize")).expect("read"),
            "900S\n2048 3\n"
        );
        assert_eq!(used(&dir), Some(2048));
        assert_eq!(used(&root.path().join("missing")), None);
    }
}
