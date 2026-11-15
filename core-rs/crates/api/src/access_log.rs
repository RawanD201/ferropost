//! Access log in the GoFrame format that fail2ban parses.
//!
//! `conf/core/fail2ban_init/filter.d/core-limit-filter.conf` bans clients by
//! scanning `logs/access-YYYYMMDD.log`. Requests proxied to Go are already
//! logged by Go, so only requests answered here are written, which keeps
//! every request counted exactly once.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::http::{Method, StatusCode, Version};
use chrono::{DateTime, Local};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

const QUEUE_CAPACITY: usize = 8192;

#[derive(Debug, Clone)]
pub struct AccessEntry {
    pub method: Method,
    pub scheme: &'static str,
    pub host: String,
    pub uri: String,
    pub version: Version,
    pub client_ip: IpAddr,
    pub referer: String,
    pub user_agent: String,
}

struct Line {
    file_date: String,
    text: String,
}

/// Non-blocking handle; lines are written by a background task.
#[derive(Clone)]
pub struct AccessLog {
    tx: Option<mpsc::Sender<Line>>,
}

impl AccessLog {
    /// Starts the writer task. Must be called inside a Tokio runtime.
    pub fn start(dir: PathBuf) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(write_lines(dir, rx));
        Self { tx: Some(tx) }
    }

    pub fn disabled() -> Self {
        Self { tx: None }
    }

    pub fn record(&self, entry: &AccessEntry, status: StatusCode, elapsed: Duration) {
        let Some(tx) = &self.tx else { return };
        let now = Local::now();
        let line = Line {
            file_date: now.format("%Y%m%d").to_string(),
            text: format_line(now, entry, status, elapsed),
        };
        if tx.try_send(line).is_err() {
            tracing::warn!("access log queue full; entry dropped");
        }
    }
}

/// `<time> <status> "<method> <scheme> <host> <uri> <proto>" <secs>, <ip>, "<referer>", "<ua>"`
pub fn format_line(
    now: DateTime<Local>,
    e: &AccessEntry,
    status: StatusCode,
    elapsed: Duration,
) -> String {
    format!(
        "{} {} \"{} {} {} {} {}\" {:.3}, {}, \"{}\", \"{}\"\n",
        now.format("%Y-%m-%d %H:%M:%S%.3f"),
        status.as_u16(),
        e.method,
        e.scheme,
        token(&e.host),
        token(&e.uri),
        protocol(e.version),
        elapsed.as_secs_f64(),
        e.client_ip,
        quoted(&e.referer),
        quoted(&e.user_agent),
    )
}

fn protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

/// Space-free field; never empty so the fail2ban regex still matches.
fn token(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| {
            if c.is_whitespace() || c.is_control() || c == '"' {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() {
        "-".to_owned()
    } else {
        cleaned
    }
}

/// Client-controlled text inside quotes. Quotes and control characters are
/// replaced so a crafted User-Agent cannot forge an extra log line or shift
/// the IP field fail2ban reads.
fn quoted(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() || c == '"' { '\'' } else { c })
        .collect()
}

async fn write_lines(dir: PathBuf, mut rx: mpsc::Receiver<Line>) {
    if let Err(err) = tokio::fs::create_dir_all(&dir).await {
        tracing::warn!(dir = %dir.display(), %err, "cannot create access log directory");
    }
    let mut current: Option<(String, tokio::fs::File)> = None;

    while let Some(line) = rx.recv().await {
        if current
            .as_ref()
            .is_none_or(|(date, _)| *date != line.file_date)
        {
            let path = dir.join(format!("access-{}.log", line.file_date));
            current = match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(file) => Some((line.file_date.clone(), file)),
                Err(err) => {
                    tracing::warn!(path = %path.display(), %err, "cannot open access log");
                    None
                }
            };
        }
        if let Some((_, file)) = current.as_mut()
            && let Err(err) = file.write_all(line.text.as_bytes()).await
        {
            tracing::warn!(%err, "access log write failed");
            current = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn entry(user_agent: &str) -> AccessEntry {
        AccessEntry {
            method: Method::GET,
            scheme: "https",
            host: "mail.example.com".into(),
            uri: "/api/tags/list?page=1".into(),
            version: Version::HTTP_11,
            client_ip: "203.0.113.5".parse().expect("ip"),
            referer: String::new(),
            user_agent: user_agent.into(),
        }
    }

    fn now() -> DateTime<Local> {
        Local
            .with_ymd_and_hms(2026, 11, 15, 10, 0, 0)
            .single()
            .expect("time")
    }

    #[test]
    fn format_matches_fail2ban_filter_shape() {
        let line = format_line(
            now(),
            &entry("curl/8.0"),
            StatusCode::OK,
            Duration::from_millis(12),
        );
        assert_eq!(
            line,
            "2026-11-15 10:00:00.000 200 \"GET https mail.example.com /api/tags/list?page=1 HTTP/1.1\" 0.012, 203.0.113.5, \"\", \"curl/8.0\"\n"
        );
    }

    #[test]
    fn hostile_user_agent_cannot_forge_fields() {
        let line = format_line(
            now(),
            &entry("x\", 1.2.3.4, \"\"\n2026-11-15 10:00:00 200 \"GET"),
            StatusCode::OK,
            Duration::ZERO,
        );
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.contains(", 203.0.113.5, "));
        assert_eq!(line.matches('"').count(), 6);
    }

    #[tokio::test]
    async fn writes_daily_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AccessLog::start(dir.path().to_path_buf());
        log.record(&entry("ua"), StatusCode::NOT_FOUND, Duration::ZERO);
        let path = dir
            .path()
            .join(format!("access-{}.log", Local::now().format("%Y%m%d")));
        for _ in 0..50 {
            if tokio::fs::metadata(&path).await.is_ok_and(|m| m.len() > 0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let content = tokio::fs::read_to_string(&path).await.expect("log written");
        assert!(content.contains(" 404 \"GET https "));
    }
}
