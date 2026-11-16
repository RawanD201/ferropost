//! Log housekeeping (Go: `log_maintenance.CompressAndCleanupLogs`): once a
//! day the core's logs from before today are gzipped and the newest thirty
//! of each kind kept, and operation-log days older than a month are packed
//! into `<day>.tar.gz`.
//!
//! Differences from Go: the first pass runs ten minutes after start-up (Go
//! waited a day, so a core restarted daily never tidied), and a file whose
//! compressed copy cannot be written is kept.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Local, NaiveDate, TimeZone};
use tokio::sync::watch;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "log_maintenance";
const KEEP: usize = 30;
const EVERY: Duration = Duration::from_secs(24 * 3600);

/// What a pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tidied {
    pub compressed: usize,
    pub removed: usize,
    pub archived: usize,
}

fn kind(name: &str) -> Option<&'static str> {
    if !name.ends_with(".log") {
        return None;
    }
    if name.starts_with("access-") {
        Some("access")
    } else if name.starts_with("error-") {
        Some("error")
    } else if NaiveDate::parse_from_str(name.trim_end_matches(".log"), "%Y-%m-%d").is_ok() {
        Some("date")
    } else {
        None
    }
}

fn gzip(path: &Path) -> io::Result<()> {
    let target = PathBuf::from(format!("{}.gz", path.display()));
    let result = (|| {
        let mut source = File::open(path)?;
        let mut encoder =
            flate2::write::GzEncoder::new(File::create(&target)?, flate2::Compression::default());
        io::copy(&mut source, &mut encoder)?;
        encoder.finish()?.sync_all()
    })();
    match result {
        Ok(()) => std::fs::remove_file(path),
        Err(err) => {
            let _ = std::fs::remove_file(&target);
            Err(err)
        }
    }
}

fn tar_gz(dir: &Path, target: &Path) -> io::Result<()> {
    let result = (|| {
        let encoder =
            flate2::write::GzEncoder::new(File::create(target)?, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let name = dir.file_name().unwrap_or_default();
        archive.append_dir_all(name, dir)?;
        archive.into_inner()?.finish()?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(target);
    }
    result
}

/// Gzips a folder's logs from before `today` and keeps the newest thirty
/// of each kind (Go's `processStandardLogs`).
fn standard_logs(dir: &Path, today: SystemTime, done: &mut Tidied) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut groups: BTreeMap<&'static str, Vec<(SystemTime, PathBuf)>> = BTreeMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(kind) = kind(&name) else {
            continue;
        };
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_file() {
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            groups
                .entry(kind)
                .or_default()
                .push((modified, entry.path()));
        }
    }
    for files in groups.values_mut() {
        files.sort();
        let extra = files.len().saturating_sub(KEEP);
        for (i, (modified, path)) in files.iter().enumerate() {
            if i < extra {
                if std::fs::remove_file(path).is_ok() {
                    done.removed += 1;
                }
            } else if *modified < today {
                match gzip(path) {
                    Ok(()) => done.compressed += 1,
                    Err(err) => tracing::warn!(path = %path.display(), %err, "log not compressed"),
                }
            }
        }
    }
}

/// Packs operation-log days older than `before` (Go's
/// `processOperationLogs`).
fn operation_logs(dir: &Path, before: NaiveDate, done: &mut Tidied) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(day) = NaiveDate::parse_from_str(&name, "%Y-%m-%d") else {
            continue;
        };
        if day >= before || !entry.path().is_dir() {
            continue;
        }
        let target = dir.join(format!("{name}.tar.gz"));
        if target.exists() {
            continue;
        }
        match tar_gz(&entry.path(), &target) {
            Ok(()) => {
                if std::fs::remove_dir_all(entry.path()).is_ok() {
                    done.archived += 1;
                }
            }
            Err(err) => {
                tracing::warn!(dir = %entry.path().display(), %err, "operation log not archived")
            }
        }
    }
}

/// One pass over `logs/core` as it is at `now`.
pub fn tidy(core_logs: &Path, now: DateTime<Local>) -> Tidied {
    let mut done = Tidied::default();
    let midnight = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|t| Local.from_local_datetime(&t).earliest())
        .map_or(SystemTime::UNIX_EPOCH, SystemTime::from);
    for dir in [core_logs.to_path_buf(), core_logs.join("out")] {
        standard_logs(&dir, midnight, &mut done);
    }
    let month_ago = now
        .date_naive()
        .checked_sub_months(chrono::Months::new(1))
        .unwrap_or_else(|| now.date_naive());
    operation_logs(&core_logs.join("operation_log"), month_ago, &mut done);
    done
}

pub async fn run(core_logs: PathBuf, mut shutdown: watch::Receiver<bool>) {
    let mut wait = Duration::from_secs(600);
    loop {
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
        wait = EVERY;
        let dir = core_logs.clone();
        match tokio::task::spawn_blocking(move || tidy(&dir, Local::now())).await {
            Ok(done) if done != Tidied::default() => tracing::info!(
                compressed = done.compressed,
                removed = done.removed,
                archived = done.archived,
                "logs tidied"
            ),
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "log housekeeping failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn age(path: &Path, days: u64) {
        let when = SystemTime::now() - Duration::from_secs(days * 24 * 3600);
        File::options()
            .write(true)
            .open(path)
            .and_then(|f| f.set_modified(when))
            .expect("age");
    }

    #[test]
    fn tidies_like_go() {
        let root = tempfile::tempdir().expect("tempdir");
        let logs = root.path();
        std::fs::create_dir_all(logs.join("out")).expect("out");
        for day in 0..33u64 {
            let path = logs.join(format!("access-{:08}.log", 20260000 + day));
            std::fs::write(&path, "line\n").expect("write");
            age(&path, 40 - day);
        }
        let today = logs.join("access-today.log");
        std::fs::write(&today, "now\n").expect("write");
        std::fs::write(logs.join("out/2026-01-01.log"), "old\n").expect("write");
        age(&logs.join("out/2026-01-01.log"), 3);
        std::fs::write(logs.join("notes.txt"), "keep\n").expect("write");
        let ops = logs.join("operation_log");
        std::fs::create_dir_all(ops.join("2020-01-01")).expect("old day");
        std::fs::write(ops.join("2020-01-01/1.log"), "op\n").expect("write");
        let recent = Local::now().date_naive().format("%Y-%m-%d").to_string();
        std::fs::create_dir_all(ops.join(&recent)).expect("today");

        let done = tidy(logs, Local::now());
        assert_eq!(done.removed, 4, "34 access logs: the oldest 4 go");
        assert_eq!(
            done.compressed,
            29 + 1,
            "the older kept ones and the old output log"
        );
        assert_eq!(done.archived, 1);
        assert!(today.exists(), "today's log is left alone");
        assert!(logs.join("out/2026-01-01.log.gz").exists());
        assert!(logs.join("notes.txt").exists());
        assert!(ops.join("2020-01-01.tar.gz").exists() && !ops.join("2020-01-01").exists());
        assert!(ops.join(&recent).exists());

        let mut text = String::new();
        io::Read::read_to_string(
            &mut flate2::read::GzDecoder::new(
                File::open(logs.join("out/2026-01-01.log.gz")).expect("gz"),
            ),
            &mut text,
        )
        .expect("gunzip");
        assert_eq!(text, "old\n");
        assert_eq!(
            tidy(logs, Local::now()),
            Tidied::default(),
            "nothing left to do"
        );
    }
}
