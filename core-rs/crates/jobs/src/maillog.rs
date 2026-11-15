//! Follows Postfix's `mail.log` and stores what it reports.
//!
//! Go re-read the log backwards from the end to a timestamp watermark on
//! every file change. Here a cursor (inode and byte offset) is advanced in
//! the same transaction as the parsed rows, so each line is stored exactly
//! once, partial lines wait for the rest, and a rotated file is finished
//! before moving on to the new one.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use ferropost_domain::maillog::{Event, Ignored, parse_line};
use ferropost_store::maillog::Cursor;
use sqlx::PgPool;
use tokio::sync::watch;

const POLL_EVERY: Duration = Duration::from_secs(2);
/// Bytes read per batch; big backlogs are worked through in steps.
const CHUNK: u64 = 8 * 1024 * 1024;

pub struct Tailer {
    path: PathBuf,
    main_cf: PathBuf,
    pg: PgPool,
}

impl Tailer {
    pub fn new(path: PathBuf, main_cf: PathBuf, pg: PgPool) -> Self {
        Self { path, main_cf, pg }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            let more = match self.tick().await {
                Ok(more) => more,
                Err(err) => {
                    tracing::warn!(error = %format!("{err:#}"), "maillog ingestion failed");
                    false
                }
            };
            if more {
                continue;
            }
            tokio::select! {
                () = tokio::time::sleep(POLL_EVERY) => {}
                _ = shutdown.changed() => return,
            }
        }
    }

    /// Stores the next batch of lines. Returns `true` when more are waiting.
    pub async fn tick(&self) -> Result<bool> {
        let Some((inode, len)) = file_identity(&self.path) else {
            return Ok(false);
        };
        let cursor = match ferropost_store::maillog::cursor(&self.pg).await? {
            None => Cursor {
                inode,
                offset: 0,
                skip_until: ferropost_store::maillog::go_watermark(&self.pg).await?,
            },
            Some(saved) if saved.inode != inode => {
                // Rotated: finish the previous file if it is still there.
                if let Some(old) = rotated_file(&self.path, saved.inode)
                    && file_identity(&old).is_some_and(|(_, old_len)| saved.offset < old_len)
                {
                    // Nothing is appended to it any more; come straight back
                    // to continue or switch to the new file.
                    self.ingest(old, saved, true).await?;
                    return Ok(true);
                }
                Cursor {
                    inode,
                    offset: 0,
                    skip_until: 0,
                }
            }
            // Truncated in place (copytruncate rotation).
            Some(saved) if len < saved.offset => Cursor {
                inode,
                offset: 0,
                skip_until: 0,
            },
            Some(saved) => saved,
        };
        self.ingest(self.path.clone(), cursor, false).await
    }

    /// `finished`: the file is rotated away, so an unterminated last line is
    /// complete.
    async fn ingest(&self, path: PathBuf, cursor: Cursor, finished: bool) -> Result<bool> {
        let main_cf = self.main_cf.clone();
        let (events, next, more) =
            tokio::task::spawn_blocking(move || read_events(&path, &main_cf, cursor, finished))
                .await
                .context("maillog reader panicked")??;
        if next == cursor {
            return Ok(false);
        }
        let stored = ferropost_store::maillog::store_batch(&self.pg, &events, next).await?;
        if stored && !events.is_empty() {
            tracing::debug!(
                events = events.len(),
                offset = next.offset,
                "maillog batch stored"
            );
        }
        Ok(stored && more)
    }
}

/// `(inode, length)` of a file, or `None` when it does not exist.
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| (m.ino(), m.len()))
}

/// A sibling such as `mail.log.1` that is the file the cursor points into.
fn rotated_file(path: &Path, inode: u64) -> Option<PathBuf> {
    let dir = path.parent()?;
    let name = path.file_name()?.to_str()?;
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n != name && n.starts_with(name))
        })
        .find(|e| e.metadata().is_ok_and(|m| m.ino() == inode))
        .map(|e| e.path())
}

/// Parsed events, the cursor after them, and whether unread data remains.
type Batch = (Vec<(i64, Event)>, Cursor, bool);

/// Reads complete lines from `cursor.offset` (at most [`CHUNK`] bytes) and
/// parses them. Returns the events, the cursor after the last complete
/// line, and whether unread data remains.
fn read_events(path: &Path, main_cf: &Path, cursor: Cursor, finished: bool) -> Result<Batch> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    if meta.ino() != cursor.inode || meta.len() <= cursor.offset {
        return Ok((Vec::new(), cursor, false));
    }
    file.seek(SeekFrom::Start(cursor.offset))?;
    let mut buf = Vec::new();
    file.take(CHUNK).read_to_end(&mut buf)?;

    let consumed = match buf.iter().rposition(|b| *b == b'\n') {
        Some(_) if finished && (buf.len() as u64) < CHUNK => buf.len(),
        Some(last) => last + 1,
        // A single line longer than the chunk is skipped rather than
        // blocking ingestion forever; a rotated file's last line is final.
        None if finished || buf.len() as u64 >= CHUNK => buf.len(),
        // An unfinished line: wait for the rest.
        None => return Ok((Vec::new(), cursor, false)),
    };
    buf.truncate(consumed);

    let ignored = Ignored::from_main_cf(&std::fs::read_to_string(main_cf).unwrap_or_default());
    let now = chrono::Utc::now().timestamp();
    let events = String::from_utf8_lossy(&buf)
        .lines()
        .filter_map(|line| parse_line(line, &ignored, now))
        .filter(|(time, _)| *time > cursor.skip_until)
        .collect();

    let next = Cursor {
        offset: cursor.offset + consumed as u64,
        ..cursor
    };
    Ok((events, next, next.offset < meta.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cursor_for(path: &Path, offset: u64) -> Cursor {
        Cursor {
            inode: file_identity(path).expect("file").0,
            offset,
            skip_until: 0,
        }
    }

    #[test]
    fn reads_only_complete_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("mail.log");
        let cf = dir.path().join("main.cf");
        let line = "Nov 15 10:00:04 mail postfix/qmgr[1]: Q1: removed\n";
        std::fs::write(
            &log,
            format!("{line}Nov 15 10:00:05 mail postfix/qmgr[1]: Q2: rem"),
        )
        .expect("write");

        let (events, next, more) =
            read_events(&log, &cf, cursor_for(&log, 0), false).expect("read");
        assert_eq!(events.len(), 1);
        assert_eq!(next.offset, line.len() as u64);
        assert!(more, "the partial line is still unread");

        let (events, again, _) = read_events(&log, &cf, next, false).expect("read");
        assert!(events.is_empty());
        assert_eq!(again, next, "waits for the rest of the line");

        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .and_then(|mut f| f.write_all(b"oved\n"))
            .expect("append");
        let (events, _, more) = read_events(&log, &cf, next, false).expect("read");
        assert_eq!(events.len(), 1);
        assert!(!more);
    }

    #[test]
    fn skips_lines_before_the_bootstrap_watermark() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("mail.log");
        std::fs::write(
            &log,
            "2025-11-15T10:00:00Z mail postfix/qmgr[1]: OLD: removed\n\
             2025-11-15T10:00:05Z mail postfix/qmgr[1]: NEW: removed\n",
        )
        .expect("write");
        let mut cursor = cursor_for(&log, 0);
        cursor.skip_until = 1_763_200_800_000; // 10:00:00
        let (events, next, _) =
            read_events(&log, &dir.path().join("main.cf"), cursor, false).expect("read");
        assert_eq!(events.len(), 1);
        assert_eq!(next.skip_until, cursor.skip_until, "kept until rotation");
    }

    #[test]
    fn rotated_files_are_read_to_the_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("mail.log.1");
        std::fs::write(&log, "Nov 15 10:00:04 mail postfix/qmgr[1]: Q1: removed").expect("write");
        let (events, next, more) =
            read_events(&log, &dir.path().join("main.cf"), cursor_for(&log, 0), true)
                .expect("read");
        assert_eq!(events.len(), 1, "unterminated last line counts");
        assert!(!more);
        assert_eq!(next.offset, std::fs::metadata(&log).expect("meta").len());
    }

    #[test]
    fn finds_the_rotated_file_by_inode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("mail.log");
        std::fs::write(&log, "x\n").expect("write");
        let inode = file_identity(&log).expect("file").0;
        std::fs::rename(&log, dir.path().join("mail.log.1")).expect("rotate");
        std::fs::write(&log, "y\n").expect("write");
        assert_eq!(
            rotated_file(&log, inode),
            Some(dir.path().join("mail.log.1"))
        );
        assert_eq!(rotated_file(&log, 1), None);
    }
}
