//! Contact rules: address checks and parsing of imported lists.

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

/// Parses a pasted list of addresses (Go's `parseEmailList`): split on new
/// lines, commas and semicolons, trim, lowercase, keep entries containing
/// `@` and `.`, and drop duplicates while keeping the first-seen order.
pub fn parse_email_list(data: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    data.split(['\n', '\r', ',', ';'])
        .map(|line| line.trim().to_lowercase())
        .filter(|email| !email.is_empty() && email.contains('@') && email.contains('.'))
        .filter(|email| seen.insert(email.clone()))
        .collect()
}

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9_\-.+]+@[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)+$").expect("static pattern")
});

/// GoFrame's `email` rule, plus `+` in the local part (Go rejected
/// `user+tag@example.com`).
pub fn is_valid_email(email: &str) -> bool {
    email.len() <= 320 && EMAIL.is_match(email)
}

/// A contact read from an import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedContact {
    pub email: String,
    /// 1 subscribed, 0 unsubscribed.
    pub active: i32,
    pub attribs: BTreeMap<String, String>,
}

/// How the import text was provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportSource {
    /// File contents: CSV with headers is detected automatically.
    File,
    /// Pasted text: always `email[,{json attributes}]` per line.
    Paste,
}

/// Parses an import (Go's `parseEmailContent`). Invalid addresses are
/// skipped; Go only checked them for CSV input.
pub fn parse_contacts(content: &str, source: ImportSource) -> Vec<ImportedContact> {
    let content = content.trim();
    let first_line = content.lines().next().unwrap_or_default();
    let contacts = if source == ImportSource::File && is_csv_header(first_line) {
        parse_csv(content)
    } else {
        parse_lines(content)
    };
    contacts
        .into_iter()
        .filter(|c| is_valid_email(&c.email))
        .collect()
}

/// Go's `isCSVFormat`: a header mentioning "email", or several columns
/// whose first is not an address.
fn is_csv_header(line: &str) -> bool {
    if line.to_lowercase().contains("email") {
        return true;
    }
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(line.as_bytes());
    match reader.records().next() {
        Some(Ok(record)) => record.len() > 1 && !record.get(0).unwrap_or_default().contains('@'),
        _ => false,
    }
}

fn parse_csv(content: &str) -> Vec<ImportedContact> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());
    let Ok(headers) = reader.headers().cloned() else {
        return Vec::new();
    };
    let column = |name: &str| {
        headers
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(name))
    };
    let Some(email_col) = column("email") else {
        return Vec::new();
    };
    let active_col = column("active");
    let attribs_col = column("attributes");

    reader
        .records()
        .filter_map(Result::ok)
        .filter_map(|record| {
            // Go indexed the row without a bounds check and crashed on
            // short rows.
            let email = record.get(email_col)?.trim().to_owned();
            if email.is_empty() {
                return None;
            }
            let active = match active_col.and_then(|i| record.get(i)).map(str::trim) {
                Some("0") => 0,
                _ => 1,
            };
            let attribs = attribs_col
                .and_then(|i| record.get(i))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(parse_attributes)
                .unwrap_or_default();
            Some(ImportedContact {
                email,
                active,
                attribs,
            })
        })
        .collect()
}

fn parse_lines(content: &str) -> Vec<ImportedContact> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let (email, rest) = match line.split_once(',') {
                Some((email, rest)) => (email.trim(), Some(rest.trim())),
                None => (line, None),
            };
            if email.is_empty() {
                return None;
            }
            let attribs = rest
                .filter(|s| !s.is_empty() && *s != "null")
                .and_then(parse_attributes)
                .unwrap_or_default();
            Some(ImportedContact {
                email: email.to_owned(),
                active: 1,
                attribs,
            })
        })
        .collect()
}

/// Go's `parseJSONAttributes`: undoes CSV quote doubling, then flattens a
/// JSON object to string values. Not an object → `None`.
pub fn parse_attributes(raw: &str) -> Option<BTreeMap<String, String>> {
    let cleaned = raw.replace("\"\"", "\"");
    let cleaned = cleaned.trim_matches('"');
    if cleaned == "{}" {
        return Some(BTreeMap::new());
    }
    let value: serde_json::Value = serde_json::from_str(cleaned).ok()?;
    let object = value.as_object()?;
    Some(
        object
            .iter()
            .map(|(key, value)| {
                let text = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => String::new(),
                    serde_json::Value::Number(n) => match n.as_f64() {
                        Some(f) if f.fract() == 0.0 && f.abs() < 9.0e15 => format!("{}", f as i64),
                        _ => n.to_string(),
                    },
                    other => other.to_string(),
                };
                (key.clone(), text)
            })
            .collect(),
    )
}

/// Keeps one entry per address (the constraint is `UNIQUE(group_id, email)`,
/// case-sensitive like Go). `keep_last` mirrors Go's overwrite import, where
/// the last row for an address wins; otherwise the first wins.
pub fn dedupe(contacts: Vec<ImportedContact>, keep_last: bool) -> Vec<ImportedContact> {
    let mut seen = HashSet::new();
    let mut out: Vec<ImportedContact> = if keep_last {
        let mut reversed: Vec<_> = contacts
            .into_iter()
            .rev()
            .filter(|c| seen.insert(c.email.clone()))
            .collect();
        reversed.reverse();
        reversed
    } else {
        contacts
            .into_iter()
            .filter(|c| seen.insert(c.email.clone()))
            .collect()
    };
    out.shrink_to_fit();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_email_lists_like_go() {
        let parsed = parse_email_list(
            " A@Example.com\r\nb@example.com;c@example.com, a@example.com\nnot-an-email\n\n",
        );
        assert_eq!(parsed, ["a@example.com", "b@example.com", "c@example.com"]);
        assert!(parse_email_list("").is_empty());
        assert!(parse_email_list("nobody@localhost").is_empty());
    }

    #[test]
    fn email_rule() {
        assert!(is_valid_email("a.b-c_d@mail.example.co"));
        assert!(is_valid_email("user+tag@example.com"));
        assert!(!is_valid_email("no-at.example.com"));
        assert!(!is_valid_email("a@localhost"));
        assert!(!is_valid_email("a b@example.com"));
    }

    #[test]
    fn csv_files_use_headers() {
        let csv = "Email,Active,Attributes\n\
                   a@x.com,1,\"{\"\"name\"\":\"\"Ann\"\",\"\"age\"\":30}\"\n\
                   b@x.com,0,\n\
                   bad-address,1,\n\
                   ,1,\n\
                   short\n";
        let got = parse_contacts(csv, ImportSource::File);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].email, "a@x.com");
        assert_eq!(got[0].attribs.get("name").map(String::as_str), Some("Ann"));
        assert_eq!(got[0].attribs.get("age").map(String::as_str), Some("30"));
        assert_eq!(got[1].active, 0);
    }

    #[test]
    fn plain_lines_and_pastes() {
        let text = "a@x.com, {\"city\": \"Erbil\", \"vip\": true}\nb@x.com\n\nc@x.com,null\nnope\n";
        for source in [ImportSource::File, ImportSource::Paste] {
            let got = parse_contacts(text, source);
            let emails: Vec<&str> = got.iter().map(|c| c.email.as_str()).collect();
            assert_eq!(emails, ["a@x.com", "b@x.com", "c@x.com"]);
            assert_eq!(got[0].attribs.get("vip").map(String::as_str), Some("true"));
        }
        // A paste starting with a header-like line is still read line by line.
        let got = parse_contacts("email\na@x.com", ImportSource::Paste);
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn attribute_values() {
        let a = parse_attributes(r#"{"n": 1.5, "z": null, "l": [1,2]}"#).expect("object");
        assert_eq!(a["n"], "1.5");
        assert_eq!(a["z"], "");
        assert_eq!(a["l"], "[1,2]");
        assert_eq!(parse_attributes("{}"), Some(BTreeMap::new()));
        assert_eq!(parse_attributes("[1]"), None);
    }

    #[test]
    fn dedupe_keeps_first_or_last() {
        let c = |email: &str, active| ImportedContact {
            email: email.into(),
            active,
            attribs: BTreeMap::new(),
        };
        let input = vec![c("a@x.com", 1), c("b@x.com", 1), c("a@x.com", 0)];
        let first = dedupe(input.clone(), false);
        assert_eq!(first, [c("a@x.com", 1), c("b@x.com", 1)]);
        let last = dedupe(input, true);
        assert_eq!(last, [c("b@x.com", 1), c("a@x.com", 0)]);
    }
}

/// A group a contact belongs to (`{id, name}`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GroupRef {
    pub id: i32,
    pub name: String,
}

/// A tag on a contact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContactTag {
    pub id: i32,
    pub name: String,
    pub create_time: i32,
}

/// A contact as the console lists it (Go's `v1.Contact`). `groups` and
/// `tags` are always arrays (Go sent `null` for whichever it did not fill).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Contact {
    pub id: i32,
    pub email: String,
    pub group_id: i32,
    pub active: i32,
    pub task_id: i32,
    pub create_time: i32,
    #[cfg_attr(feature = "sqlx", sqlx(skip))]
    pub groups: Vec<GroupRef>,
    pub status: i32,
    pub group_name: String,
    #[cfg_attr(feature = "sqlx", sqlx(json))]
    pub attribs: serde_json::Value,
    pub last_active_at: i32,
    #[cfg_attr(feature = "sqlx", sqlx(skip))]
    pub tags: Vec<ContactTag>,
}

/// Start of a "last active" window offered by the console (`days` is 7,
/// 30, 90, 180 or 365), as Unix time. Months are calendar months, clamped
/// at month end (Go rolled over: Mar 31 − 1 month gave Mar 3).
pub fn active_window_start(now: i64, days: i64) -> Option<i64> {
    use chrono::{DateTime, Months, TimeDelta};
    let now = DateTime::from_timestamp(now, 0)?;
    let start = match days {
        7 => now.checked_sub_signed(TimeDelta::days(7)),
        30 => now.checked_sub_months(Months::new(1)),
        90 => now.checked_sub_months(Months::new(3)),
        180 => now.checked_sub_months(Months::new(6)),
        365 => now.checked_sub_months(Months::new(12)),
        _ => None,
    }?;
    Some(start.timestamp())
}

/// Bucket size of the subscriber trend chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Daily,
    Monthly,
}

impl Granularity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Monthly => "monthly",
        }
    }

    /// `to_char` format of a bucket label.
    pub fn sql_format(self) -> &'static str {
        match self {
            Self::Daily => "YYYY-MM-DD",
            Self::Monthly => "YYYY-MM",
        }
    }
}

/// Time span and bucket size of the trend chart, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrendWindow {
    pub granularity: Granularity,
    /// Midnight of the first day.
    pub start: i64,
    /// Last second of today.
    pub end: i64,
}

/// Go's windows: 7/30/90/180 → daily buckets back that many days; anything
/// else → monthly buckets over the last 11 months plus this one.
pub fn trend_window(now: i64, interval: i64) -> TrendWindow {
    use chrono::{DateTime, Months, TimeDelta};
    let now_dt = DateTime::from_timestamp(now, 0).unwrap_or_default();
    let day_start = |t: i64| t - t.rem_euclid(86_400);
    let end = day_start(now) + 86_399;
    let (granularity, start) = match interval {
        7 | 30 | 90 | 180 => (
            Granularity::Daily,
            now_dt.checked_sub_signed(TimeDelta::days(interval)),
        ),
        _ => (
            Granularity::Monthly,
            now_dt.checked_sub_months(Months::new(11)),
        ),
    };
    TrendWindow {
        granularity,
        start: day_start(start.map_or(now, |s| s.timestamp())),
        end,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrendPoint {
    pub date: String,
    pub count: i64,
}

/// Every bucket of the window in order, zero where `counts` has nothing.
/// Months are walked by calendar month; Go stepped with `AddDate` and
/// skipped February when the window started on the 29th to 31st.
pub fn fill_trend(window: &TrendWindow, counts: &[(String, i64)]) -> Vec<TrendPoint> {
    use chrono::{DateTime, Datelike, Months, NaiveDate, TimeDelta};
    let count_of = |label: &str| {
        counts
            .iter()
            .find(|(l, _)| l == label)
            .map_or(0, |(_, c)| *c)
    };
    let (Some(start), Some(end)) = (
        DateTime::from_timestamp(window.start, 0).map(|d| d.date_naive()),
        DateTime::from_timestamp(window.end, 0).map(|d| d.date_naive()),
    ) else {
        return Vec::new();
    };

    let mut points = Vec::new();
    match window.granularity {
        Granularity::Daily => {
            let mut day = start;
            while day <= end {
                let label = day.format("%Y-%m-%d").to_string();
                points.push(TrendPoint {
                    count: count_of(&label),
                    date: label,
                });
                day += TimeDelta::days(1);
            }
        }
        Granularity::Monthly => {
            let first = |d: NaiveDate| NaiveDate::from_ymd_opt(d.year(), d.month(), 1);
            let (Some(mut month), Some(last)) = (first(start), first(end)) else {
                return points;
            };
            while month <= last {
                let label = month.format("%Y-%m").to_string();
                points.push(TrendPoint {
                    count: count_of(&label),
                    date: label,
                });
                let Some(next) = month.checked_add_months(Months::new(1)) else {
                    break;
                };
                month = next;
            }
        }
    }
    points
}

#[cfg(test)]
mod window_tests {
    use super::active_window_start;

    #[test]
    fn windows_follow_calendar_months() {
        // 2026-03-31T12:00:00Z
        let now = 1_774_958_400;
        assert_eq!(active_window_start(now, 7), Some(now - 7 * 86_400));
        // 2026-02-28T12:00:00Z (clamped)
        assert_eq!(active_window_start(now, 30), Some(1_772_280_000));
        // 2025-03-31T12:00:00Z
        assert_eq!(active_window_start(now, 365), Some(1_743_422_400));
        assert_eq!(active_window_start(now, 14), None);
    }

    #[test]
    fn trend_windows_and_fill() {
        use super::{Granularity, fill_trend, trend_window};
        // 2026-03-31T12:00:00Z
        let now = 1_774_958_400;
        let daily = trend_window(now, 7);
        assert_eq!(daily.granularity, Granularity::Daily);
        let points = fill_trend(&daily, &[("2026-03-30".into(), 4)]);
        assert_eq!(points.len(), 8, "seven days back plus today");
        assert_eq!(points[0].date, "2026-03-24");
        assert_eq!(points[6].count, 4);

        let monthly = trend_window(now, 0);
        assert_eq!(monthly.granularity, Granularity::Monthly);
        let points = fill_trend(&monthly, &[]);
        let labels: Vec<&str> = points.iter().map(|p| p.date.as_str()).collect();
        assert_eq!(labels.len(), 12);
        assert_eq!(labels[0], "2025-04");
        assert_eq!(labels[11], "2026-03");
        // A window starting on Jan 30 must not skip February (Go did).
        let window = trend_window(1_767_096_000, 365); // 2025-12-30T12:00Z
        let labels: Vec<String> = fill_trend(&window, &[])
            .into_iter()
            .map(|p| p.date)
            .collect();
        assert_eq!(labels.first().map(String::as_str), Some("2025-01"));
        assert_eq!(labels.get(1).map(String::as_str), Some("2025-02"));
        assert_eq!(labels.len(), 12);
    }
}
