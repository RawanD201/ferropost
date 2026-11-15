//! Reader for the shared BillionMail `.env` file.
//!
//! The Go core, docker-compose and the settings UI all read and write this
//! file, so it stays the source of truth for runtime settings such as
//! `SafePath` and `IP_WHITELIST_ENABLE`. Go re-read it on every request;
//! here it is reloaded only when its modification time changes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// How often the file's mtime is checked at most.
const RECHECK_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct EnvFile {
    path: PathBuf,
    state: RwLock<State>,
}

#[derive(Debug)]
struct State {
    values: Arc<HashMap<String, String>>,
    mtime: Option<SystemTime>,
    checked_at: Instant,
}

impl EnvFile {
    /// Loads the file. A missing file yields an empty set, so the process can
    /// still start outside the container.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let (values, mtime) = read(&path);
        if mtime.is_none() {
            tracing::warn!(path = %path.display(), "env file not found; using empty settings");
        }
        Self {
            path,
            state: RwLock::new(State {
                values: Arc::new(values),
                mtime,
                checked_at: Instant::now(),
            }),
        }
    }

    pub fn from_map(values: HashMap<String, String>) -> Self {
        Self {
            path: PathBuf::new(),
            state: RwLock::new(State {
                values: Arc::new(values),
                mtime: None,
                checked_at: Instant::now(),
            }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a value, or `None` when the key is absent or empty.
    pub fn get(&self, key: &str) -> Option<String> {
        self.snapshot().get(key).filter(|v| !v.is_empty()).cloned()
    }

    /// Interprets `1`/`true` (any case) as enabled, like Go's
    /// `isIPWhitelistEnabled`.
    pub fn flag(&self, key: &str) -> bool {
        self.get(key)
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    }

    fn snapshot(&self) -> Arc<HashMap<String, String>> {
        if let Some(values) = self.fresh_values() {
            return values;
        }
        self.reload_if_changed()
    }

    fn fresh_values(&self) -> Option<Arc<HashMap<String, String>>> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        (self.path.as_os_str().is_empty() || state.checked_at.elapsed() < RECHECK_INTERVAL)
            .then(|| state.values.clone())
    }

    fn reload_if_changed(&self) -> Arc<HashMap<String, String>> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.checked_at = Instant::now();
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if mtime != state.mtime {
            let (values, mtime) = read(&self.path);
            state.values = Arc::new(values);
            state.mtime = mtime;
            tracing::debug!(path = %self.path.display(), "env file reloaded");
        }
        state.values.clone()
    }
}

fn read(path: &Path) -> (HashMap<String, String>, Option<SystemTime>) {
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let content = std::fs::read_to_string(path).unwrap_or_default();
    (parse(&content), mtime)
}

/// Parses `KEY=VALUE` lines. Blank lines and `#` comments are skipped, keys
/// and values are trimmed and the first occurrence of a key wins (as in Go).
pub fn parse(content: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values
                .entry(key.trim().to_owned())
                .or_insert_with(|| value.trim().to_owned());
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_like_go() {
        let values = parse("# comment\n\nDBPASS = secret \nSafePath=/abc\nDBPASS=second\nBROKEN\n");
        assert_eq!(values.get("DBPASS").map(String::as_str), Some("secret"));
        assert_eq!(values.get("SafePath").map(String::as_str), Some("/abc"));
        assert!(!values.contains_key("BROKEN"));
    }

    #[test]
    fn flags() {
        let env = EnvFile::from_map(HashMap::from([
            ("A".into(), "true".into()),
            ("B".into(), "1".into()),
            ("C".into(), "false".into()),
            ("D".into(), "".into()),
        ]));
        assert!(env.flag("A"));
        assert!(env.flag("B"));
        assert!(!env.flag("C"));
        assert!(!env.flag("D"));
        assert!(!env.flag("MISSING"));
        assert_eq!(env.get("D"), None);
    }

    #[test]
    fn reloads_after_modification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".env");
        std::fs::write(&path, "SafePath=one\n").expect("write");
        let env = EnvFile::load(&path);
        assert_eq!(env.get("SafePath").as_deref(), Some("one"));

        // Make sure the mtime moves even on coarse filesystems.
        std::thread::sleep(Duration::from_millis(20));
        let mut file = std::fs::File::create(&path).expect("create");
        writeln!(file, "SafePath=two").expect("write");
        drop(file);
        let later = SystemTime::now() + Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(later))
            .expect("touch");

        env.state.write().expect("lock").checked_at = Instant::now() - RECHECK_INTERVAL;
        assert_eq!(env.get("SafePath").as_deref(), Some("two"));
    }
}
