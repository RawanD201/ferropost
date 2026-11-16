//! Mailboxes (Go: `mail_boxes`): addresses Dovecot serves, their quota and
//! the `maildirsize` file Dovecot's maildir quota keeps.

use serde::{Deserialize, Serialize};

/// Quota given to a new mailbox when none is chosen (Go's default).
pub const DEFAULT_QUOTA: i64 = 5_242_880;

/// A row of `mailbox`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[serde(default)]
pub struct Mailbox {
    pub username: String,
    /// The Dovecot hash, or the plaintext in list responses (the console
    /// shows it, as with Go).
    pub password: String,
    /// Reversible copy (hex of base64) the core logs in with.
    pub password_encode: String,
    pub full_name: String,
    pub is_admin: i32,
    pub maildir: String,
    pub quota: i64,
    pub local_part: String,
    pub domain: String,
    pub create_time: i64,
    pub update_time: i64,
    pub active: i32,
    pub used_quota: i64,
    pub quota_active: i32,
}

/// Local parts the console may create: letters, digits, `.`, `_`, `-`
/// and `+`, not starting or ending with a dot. Go's unanchored pattern let
/// anything with one word character through.
pub fn local_part_valid(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// The quota line of `maildirsize`: the limit when the quota is on, else 0.
pub fn quota_header(quota: i64, quota_active: bool) -> String {
    let limit = if quota_active && quota > 0 { quota } else { 0 };
    format!("{limit}S\n")
}

/// A new `maildirsize`.
pub fn new_maildirsize(quota: i64, quota_active: bool) -> String {
    format!("{}0 0\n", quota_header(quota, quota_active))
}

/// `maildirsize` with a new quota line and the usage lines kept.
pub fn with_quota(existing: &str, quota: i64, quota_active: bool) -> String {
    let usage: Vec<&str> = existing
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let usage = if usage.is_empty() { vec!["0 0"] } else { usage };
    format!(
        "{}{}\n",
        quota_header(quota, quota_active),
        usage.join("\n")
    )
}

/// Bytes used according to `maildirsize`: the sum of the first field of
/// each usage line.
pub fn used_bytes(maildirsize: &str) -> Option<i64> {
    let mut total = 0i64;
    for line in maildirsize.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let size = line.split_whitespace().next()?.trim_end_matches('S');
        total = total.checked_add(size.parse().ok()?)?;
    }
    Some(total)
}

/// Alert levels, highest first.
const ALERT_LEVELS: [i32; 2] = [95, 90];

/// The alert level crossed and the usage percentage, if any.
pub fn quota_alert(used: i64, quota: i64) -> Option<(i32, f64)> {
    if quota <= 0 {
        return None;
    }
    let pct = used as f64 / quota as f64 * 100.0;
    ALERT_LEVELS
        .into_iter()
        .find(|level| pct >= f64::from(*level))
        .map(|level| (level, pct))
}

/// Human-readable size (Go: `formatSize`).
pub fn format_size(bytes: i64) -> String {
    if bytes < 1024 {
        return format!("{bytes}B");
    }
    let mut value = bytes as f64 / 1024.0;
    for unit in ["KB", "MB"] {
        if value < 1024.0 {
            return format!("{value:.2}{unit}");
        }
        value /= 1024.0;
    }
    format!("{value:.2}GB")
}

/// Subject and text of a quota alert (Go's wording).
pub fn quota_alert_mail(
    kind: &str,
    target: &str,
    used: i64,
    quota: i64,
    level: i32,
    pct: f64,
) -> (String, String) {
    let subject = if pct >= 100.0 {
        format!("[Quota EXCEEDED] {target} {pct:.1}%")
    } else {
        format!("[Quota {level}% Alert] {target} usage {pct:.1}%")
    };
    let what = if kind == "mailbox" {
        "Mailbox"
    } else {
        "Domain"
    };
    let status = if pct >= 100.0 {
        "Status: EXCEEDED LIMIT, new mails may be rejected."
    } else {
        "Status: Approaching limit."
    };
    let body = format!(
        "Hello,\n\n{what}: {target}\nQuota: {}\nUsed: {} ({pct:.2}%)\nThreshold: {level}%\n\n{status}\n\n\
         Suggested actions:\n - Delete large or old mails\n - Empty Trash/Spam folders\n - Request quota increase if necessary\n\n\
         This is an automated notification.\n",
        format_size(quota),
        format_size(used),
    );
    (subject, body)
}

/// A mailbox read from an import file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ImportEntry {
    pub username: String,
    pub full_name: String,
    pub is_admin: i32,
    pub quota: i64,
    pub local_part: String,
    pub domain: String,
    pub active: i32,
    /// A hash when `password_encode` is also given (Go's export), else the
    /// plaintext.
    pub password: String,
    pub password_encode: String,
}

/// Reads an import file (`csv`, `json` or one address per line in `txt`).
pub fn parse_import(file_type: &str, content: &str) -> Result<Vec<ImportEntry>, &'static str> {
    match file_type {
        "json" => serde_json::from_str(content).map_err(|_| "JSON parsing failed"),
        "csv" => {
            let mut reader = csv::ReaderBuilder::new()
                .flexible(true)
                .from_reader(content.as_bytes());
            let header: Vec<String> = reader
                .headers()
                .map_err(|_| "CSV parsing failed")?
                .iter()
                .map(|h| h.trim().to_owned())
                .collect();
            let mut out = Vec::new();
            for record in reader.records() {
                let record = record.map_err(|_| "CSV parsing failed")?;
                let mut e = ImportEntry::default();
                for (col, value) in header.iter().zip(record.iter()) {
                    let int = || value.trim().parse().unwrap_or(0);
                    match col.as_str() {
                        "username" => e.username = value.to_owned(),
                        "full_name" => e.full_name = value.to_owned(),
                        "is_admin" => e.is_admin = int() as i32,
                        "quota" => e.quota = int(),
                        "local_part" => e.local_part = value.to_owned(),
                        "domain" => e.domain = value.to_owned(),
                        "active" => e.active = int() as i32,
                        "password" => e.password = value.to_owned(),
                        "password_encode" => e.password_encode = value.to_owned(),
                        _ => {}
                    }
                }
                out.push(e);
            }
            if out.is_empty() {
                return Err("CSV parsing failed");
            }
            Ok(out)
        }
        "txt" => Ok(content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| ImportEntry {
                username: l.to_owned(),
                ..ImportEntry::default()
            })
            .collect()),
        _ => Err("Unsupported file type"),
    }
}

impl ImportEntry {
    /// Fills the parts Go derived: address parts and defaults. The quota
    /// defaults to that of a new mailbox (Go used 1000 bytes).
    pub fn normalise(mut self) -> Self {
        self.username = self.username.trim().to_ascii_lowercase();
        if let Some((local, domain)) = self.username.split_once('@') {
            if self.local_part.is_empty() {
                self.local_part = local.to_owned();
            }
            if self.domain.is_empty() {
                self.domain = domain.to_owned();
            }
        }
        self.local_part = self.local_part.trim().to_ascii_lowercase();
        self.domain = self.domain.trim().to_ascii_lowercase();
        if self.username.is_empty() && !self.local_part.is_empty() && !self.domain.is_empty() {
            self.username = format!("{}@{}", self.local_part, self.domain);
        }
        if self.full_name.is_empty() {
            self.full_name = self.local_part.clone();
        }
        if self.quota <= 0 {
            self.quota = DEFAULT_QUOTA;
        }
        if self.active == 0 {
            self.active = 1;
        }
        self
    }
}

/// An export file: content, content type and file name (Go's formats).
pub fn export(
    file_type: &str,
    mailboxes: &[Mailbox],
) -> Option<(Vec<u8>, &'static str, &'static str)> {
    match file_type {
        "txt" => Some((
            mailboxes
                .iter()
                .map(|m| m.username.as_str())
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes(),
            "text/plain",
            "mailboxes.txt",
        )),
        "json" => Some((
            serde_json::to_vec_pretty(mailboxes).unwrap_or_default(),
            "application/json",
            "mailboxes.json",
        )),
        "csv" => {
            let mut writer = csv::Writer::from_writer(Vec::new());
            let _ = writer.write_record([
                "username",
                "full_name",
                "is_admin",
                "quota",
                "quota_active",
                "local_part",
                "domain",
                "active",
                "password",
                "password_encode",
            ]);
            for m in mailboxes {
                let _ = writer.write_record([
                    m.username.clone(),
                    m.full_name.clone(),
                    m.is_admin.to_string(),
                    m.quota.to_string(),
                    m.quota_active.to_string(),
                    m.local_part.clone(),
                    m.domain.clone(),
                    m.active.to_string(),
                    m.password.clone(),
                    m.password_encode.clone(),
                ]);
            }
            Some((
                writer.into_inner().unwrap_or_default(),
                "text/csv",
                "mailboxes.csv",
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_parts() {
        for ok in ["john", "john.doe", "a_b-c", "news+1"] {
            assert!(local_part_valid(ok), "{ok}");
        }
        for bad in ["", ".x", "x.", "a..b", "a b", "a@b", "ü"] {
            assert!(!local_part_valid(bad), "{bad}");
        }
    }

    #[test]
    fn maildirsize() {
        assert_eq!(new_maildirsize(5000, true), "5000S\n0 0\n");
        assert_eq!(new_maildirsize(5000, false), "0S\n0 0\n");
        let existing = "100S\n2048 3\n-24 -1\n";
        assert_eq!(with_quota(existing, 900, true), "900S\n2048 3\n-24 -1\n");
        assert_eq!(with_quota("", 900, true), "900S\n0 0\n");
        assert_eq!(used_bytes(existing), Some(2024));
        assert_eq!(used_bytes("0S\n"), Some(0));
        assert_eq!(used_bytes("0S\nx y\n"), None);
    }

    #[test]
    fn alerts() {
        assert_eq!(quota_alert(89, 100), None);
        assert_eq!(quota_alert(90, 100).map(|a| a.0), Some(90));
        assert_eq!(quota_alert(120, 100).map(|a| a.0), Some(95));
        assert_eq!(quota_alert(5, 0), None);
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(1536), "1.50KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.00MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.00GB");
        let (subject, body) = quota_alert_mail("mailbox", "a@x.com", 95, 100, 95, 95.0);
        assert_eq!(subject, "[Quota 95% Alert] a@x.com usage 95.0%");
        assert!(body.contains("Mailbox: a@x.com\nQuota: 100B\nUsed: 95B (95.00%)"));
        assert!(
            quota_alert_mail("domain", "x.com", 2, 1, 95, 200.0)
                .0
                .starts_with("[Quota EXCEEDED]")
        );
    }

    #[test]
    fn imports() {
        let csv = "username,full_name,quota,password,password_encode\nA@X.com,,10,hash,enc\nb@x.com,Bee,,pw,\n";
        let entries: Vec<ImportEntry> = parse_import("csv", csv)
            .expect("csv")
            .into_iter()
            .map(ImportEntry::normalise)
            .collect();
        assert_eq!(entries[0].username, "a@x.com");
        assert_eq!(
            (entries[0].local_part.as_str(), entries[0].domain.as_str()),
            ("a", "x.com")
        );
        assert_eq!((entries[0].full_name.as_str(), entries[0].quota), ("a", 10));
        assert_eq!(
            (entries[1].full_name.as_str(), entries[1].quota),
            ("Bee", DEFAULT_QUOTA)
        );
        assert_eq!(
            parse_import("txt", " a@x.com \n\nb@x.com")
                .expect("txt")
                .len(),
            2
        );
        let json = r#"[{"username": "c@x.com", "create_time": 5, "password": "h", "password_encode": "e"}]"#;
        assert_eq!(
            parse_import("json", json).expect("json")[0].password_encode,
            "e"
        );
        assert_eq!(parse_import("csv", "username\n"), Err("CSV parsing failed"));
        assert_eq!(parse_import("xml", ""), Err("Unsupported file type"));
    }

    #[test]
    fn exports() {
        let m = Mailbox {
            username: "a@x.com".into(),
            full_name: "A, Jr".into(),
            ..Mailbox::default()
        };
        let (csv, kind, name) = export("csv", std::slice::from_ref(&m)).expect("csv");
        assert_eq!((kind, name), ("text/csv", "mailboxes.csv"));
        assert!(
            String::from_utf8(csv)
                .expect("utf8")
                .contains("a@x.com,\"A, Jr\",0,0")
        );
        assert_eq!(
            export("txt", &[m.clone(), m]).expect("txt").0,
            b"a@x.com\na@x.com"
        );
        assert!(export("pdf", &[]).is_none());
    }
}
