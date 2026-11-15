//! Postfix `mail.log` parsing (Go: `service/maillog_stat`).
//!
//! The same patterns and rules as Go, so the `mailstat_*` tables fill the
//! same way. Each line yields at most one [`Event`]; the caller decides
//! which lines to read (Rust tracks a file position instead of Go's
//! timestamp watermark).

use std::collections::HashSet;
use std::sync::LazyLock;

use chrono::{DateTime, Local, NaiveDate, TimeZone};
use regex::Regex;

/// A delivery attempt (`smtp`, `local`, `virtual`, ... or `lmtp`).
#[derive(Debug, Clone, PartialEq)]
pub struct Delivery {
    pub queue_id: String,
    pub recipient: String,
    pub status: String,
    pub delay: f64,
    pub delays: String,
    pub dsn: String,
    pub relay: String,
    pub description: String,
    /// Provider group of the recipient (outgoing mail only).
    pub provider: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Outgoing delivery result → `mailstat_send_mails` (and
    /// `mailstat_deferred_mails` when deferred).
    Sent(Delivery),
    /// Local delivery to a mailbox over LMTP → `mailstat_receive_mails`.
    Received(Delivery),
    MessageId {
        queue_id: String,
        message_id: String,
    },
    Sender {
        queue_id: String,
        sender: String,
        size: i64,
    },
    Removed {
        queue_id: String,
    },
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static pattern")
}

static STATUS: LazyLock<Regex> = LazyLock::new(|| re(r"status=(\S+) "));
static RECIPIENT: LazyLock<Regex> = LazyLock::new(|| re(r"to=<([^>]+)>"));
static DELAY: LazyLock<Regex> = LazyLock::new(|| re(r"delay=(\d+(?:\.\d+)?),"));
static DELAYS: LazyLock<Regex> =
    LazyLock::new(|| re(r"delays=(\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?){3}),"));
static DSN: LazyLock<Regex> = LazyLock::new(|| re(r"dsn=([^,]+),"));
static RELAY: LazyLock<Regex> = LazyLock::new(|| re(r"relay=([^,]+),"));
static DESCRIPTION: LazyLock<Regex> = LazyLock::new(|| re(r"\((.*?)\)$"));
static QUEUE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"postfix/[^\[]+\[\d+]: *([^:]+):"));
static REMOVED: LazyLock<Regex> = LazyLock::new(|| re(r"postfix/qmgr\[\d+]: *([^:]+): *removed$"));
static SENDER: LazyLock<Regex> =
    LazyLock::new(|| re(r"postfix/qmgr\[\d+]: *([^:]+): *from=<([^>]+)>, +size=(\d+),"));
static MESSAGE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"message-id=<([^>]+)>"));
static MYHOSTNAME: LazyLock<Regex> = LazyLock::new(|| re(r"myhostname *= *([^\r\n]+)"));
static VIRTUAL_TRANSPORT: LazyLock<Regex> =
    LazyLock::new(|| re(r"virtual_transport *= *([^\r\n]+)"));

/// Deliveries the statistics leave out: the local LMTP hand-off and mail
/// to root.
#[derive(Debug, Clone, Default)]
pub struct Ignored {
    relays: HashSet<String>,
    recipients: HashSet<String>,
}

impl Ignored {
    /// Built from Postfix's `main.cf` like Go's `initIgnoreRelays`: the
    /// relay `myhostname[<last part of virtual_transport>]` and root's
    /// addresses.
    pub fn from_main_cf(main_cf: &str) -> Self {
        let mut hostname = None;
        let mut transport = None;
        for line in main_cf.lines().map(str::trim) {
            if hostname.is_none()
                && let Some(c) = MYHOSTNAME.captures(line)
            {
                hostname = Some(c[1].to_owned());
                continue;
            }
            if transport.is_none()
                && let Some(c) = VIRTUAL_TRANSPORT.captures(line)
            {
                transport = Some(c[1].to_owned());
            }
        }
        let mut ignored = Self::default();
        ignored.recipients.insert("root@localhost".to_owned());
        if let (Some(host), Some(transport)) = (hostname, transport) {
            let last = transport.rsplit(':').next().unwrap_or_default();
            ignored.relays.insert(format!("{host}[{last}]"));
            ignored.recipients.insert(format!("root@{host}"));
        }
        ignored
    }
}

/// Parses one line. Returns its time (Unix milliseconds) and event, or
/// `None` for lines the statistics do not use.
pub fn parse_line(line: &str, ignored: &Ignored, now: i64) -> Option<(i64, Event)> {
    let line = line.trim();
    let time = line_time_millis(line, now)?;
    let event = if line.contains("postfix/lmtp[") {
        delivery(line, ignored, false).map(Event::Received)
    } else if line.contains("postfix/qmgr[") && line.contains("from=<") {
        SENDER.captures(line).and_then(|c| {
            Some(Event::Sender {
                queue_id: c[1].to_owned(),
                sender: c[2].to_owned(),
                size: c[3].parse().ok()?,
            })
        })
    } else if line.contains("postfix/qmgr[") && line.contains("removed") {
        REMOVED.captures(line).map(|c| Event::Removed {
            queue_id: c[1].to_owned(),
        })
    } else if line.contains("postfix/cleanup[") && line.contains("message-id=<") {
        let queue_id = QUEUE_ID.captures(line)?[1].to_owned();
        MESSAGE_ID.captures(line).map(|c| Event::MessageId {
            queue_id,
            message_id: c[1].to_owned(),
        })
    } else if line.contains("to=<") && line.contains("status=") && line.contains("dsn=") {
        delivery(line, ignored, true).map(Event::Sent)
    } else {
        None
    };
    Some((time, event?))
}

fn delivery(line: &str, ignored: &Ignored, outgoing: bool) -> Option<Delivery> {
    let queue_id = QUEUE_ID.captures(line)?[1].to_owned();
    let recipient = RECIPIENT.captures(line)?[1].to_owned();
    let status = STATUS.captures(line)?[1].to_owned();
    if ignored.recipients.contains(&recipient) {
        return None;
    }
    let relay = RELAY
        .captures(line)
        .map(|c| c[1].to_owned())
        .unwrap_or_default();
    if outgoing && ignored.relays.contains(&relay) {
        return None;
    }
    let capture = |re: &Regex| re.captures(line).map(|c| clean(&c[1])).unwrap_or_default();
    Some(Delivery {
        provider: if outgoing {
            provider_group(&recipient)
        } else {
            ""
        },
        queue_id,
        recipient,
        status,
        delay: DELAY
            .captures(line)
            .and_then(|c| c[1].parse().ok())
            .unwrap_or(0.0),
        delays: capture(&DELAYS),
        dsn: capture(&DSN),
        relay: clean(&relay),
        description: capture(&DESCRIPTION),
    })
}

/// PostgreSQL text cannot hold NUL; Go's `SanitizeUTF8` did not need this
/// because lines were already UTF-8-checked.
fn clean(s: &str) -> String {
    s.replace('\0', "")
}

/// Line time in Unix milliseconds. RFC 3339 timestamps are used as is.
/// Classic syslog timestamps have no year: the current year is assumed and
/// a date more than a day in the future is moved back a year (Go used the
/// log file's modification year, which breaks across New Year).
pub fn line_time_millis(line: &str, now: i64) -> Option<i64> {
    let first = line.split_whitespace().next()?;
    if first.len() >= 4 && first.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
        return DateTime::parse_from_rfc3339(first)
            .ok()
            .map(|t| t.timestamp_millis());
    }

    let mut parts = line.split_whitespace();
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: u32 = parts.next()?.parse().ok()?;
    let mut hms = parts.next()?.split(':').map(|p| p.parse::<u32>().ok());
    let (h, m, s) = (hms.next()??, hms.next()??, hms.next()??);
    parts.next()?; // host: syslog lines always have one

    let year_of_now = Local
        .timestamp_opt(now, 0)
        .single()?
        .format("%Y")
        .to_string()
        .parse::<i32>()
        .ok()?;
    let at = |year: i32| {
        NaiveDate::from_ymd_opt(year, month, day)?
            .and_hms_opt(h, m, s)
            .and_then(|t| Local.from_local_datetime(&t).earliest())
            .map(|t| t.timestamp_millis())
    };
    let guess = at(year_of_now)?;
    if guess > (now + 86_400) * 1000 {
        at(year_of_now - 1)
    } else {
        Some(guess)
    }
}

/// Provider group of an address or host (Go's `GetMailProviderGroup`).
pub fn provider_group(email_or_host: &str) -> &'static str {
    let lower = email_or_host.trim().to_lowercase();
    let host = lower.split_once('@').map_or(lower.as_str(), |(_, h)| h);
    let has = |needle: &str| host.contains(needle);
    match () {
        _ if host.is_empty() => "other",
        _ if has("gmail.com") || has("googlemail.com") || host == "google.com" => "google",
        _ if has("outlook.com")
            || has("hotmail.com")
            || has("live.com")
            || has("msn.com")
            || host.starts_with("outlook.") =>
        {
            "outlook"
        }
        _ if has("yahoo.com")
            || has("ymail.com")
            || has("rocketmail.com")
            || host.starts_with("yahoo.")
            || has("aol.com")
            || has("verizonmedia.com") =>
        {
            "yahoo"
        }
        _ if has("icloud.com") || has("me.com") || has("mac.com") || has("apple.com") => "apple",
        _ if has("protonmail.com") || has("proton.me") || has("pm.me") => "proton",
        _ if has("zoho.com")
            || has("zohomail.com")
            || has("zohocorp.com")
            || has("zmail.com")
            || host.starts_with("zoho.") =>
        {
            "zoho"
        }
        _ if has("kindle.com") || has("amazon.com") || has("awsapps.com") => "amazon",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_763_200_000; // 2025-11-15

    fn ignored() -> Ignored {
        Ignored::from_main_cf(
            "# comment\nmyhostname = mail.example.com\nvirtual_transport = lmtp:inet:dovecot:24\n",
        )
    }

    fn event(line: &str) -> Option<Event> {
        parse_line(line, &ignored(), NOW).map(|(_, e)| e)
    }

    #[test]
    fn outgoing_delivery() {
        let line = "Nov 15 10:00:02 mail postfix/smtp[789]: 4ABC123: to=<Bob@Gmail.com>, \
                    relay=gmail-smtp-in.l.google.com[142.250.1.1]:25, delay=1.2, \
                    delays=0.1/0/0.5/0.6, dsn=2.0.0, status=sent (250 2.0.0 OK  1700000000 x)";
        let Some(Event::Sent(d)) = event(line) else {
            panic!("expected a delivery");
        };
        assert_eq!(d.queue_id, "4ABC123");
        assert_eq!(d.recipient, "Bob@Gmail.com");
        assert_eq!(d.status, "sent");
        assert_eq!(d.delay, 1.2);
        assert_eq!(d.delays, "0.1/0/0.5/0.6");
        assert_eq!(d.dsn, "2.0.0");
        assert_eq!(d.relay, "gmail-smtp-in.l.google.com[142.250.1.1]:25");
        assert_eq!(d.description, "250 2.0.0 OK  1700000000 x");
        assert_eq!(d.provider, "google");
    }

    #[test]
    fn other_line_kinds() {
        assert_eq!(
            event("Nov 15 10:00:01 mail postfix/cleanup[123]: 4ABC123: message-id=<abc@x.com>"),
            Some(Event::MessageId {
                queue_id: "4ABC123".into(),
                message_id: "abc@x.com".into()
            })
        );
        assert_eq!(
            event(
                "Nov 15 10:00:01 mail postfix/qmgr[456]: 4ABC123: from=<news@ex.com>, size=2048, nrcpt=1 (queue active)"
            ),
            Some(Event::Sender {
                queue_id: "4ABC123".into(),
                sender: "news@ex.com".into(),
                size: 2048
            })
        );
        assert_eq!(
            event("Nov 15 10:00:04 mail postfix/qmgr[456]: 4ABC123: removed"),
            Some(Event::Removed {
                queue_id: "4ABC123".into()
            })
        );
        let lmtp = "Nov 15 10:00:03 mail postfix/lmtp[790]: 5DEF: to=<alice@ex.com>, \
                    relay=mail.example.com[private/dovecot-lmtp], delay=0.1, delays=0/0/0/0.1, \
                    dsn=2.0.0, status=sent (250 2.0.0 <alice@ex.com> OK)";
        assert!(
            matches!(event(lmtp), Some(Event::Received(d)) if d.recipient == "alice@ex.com" && d.provider.is_empty())
        );
        // Bounce notices have an empty sender, which Go also skipped.
        assert_eq!(
            event("Nov 15 10:00:05 mail postfix/qmgr[456]: 9XYZ: from=<>, size=10, nrcpt=1"),
            None
        );
        assert_eq!(
            event("Nov 15 10:00:05 mail postfix/smtpd[1]: connect from unknown[1.2.3.4]"),
            None
        );
        assert_eq!(event("not a log line"), None);
    }

    #[test]
    fn ignores_local_handoff_and_root() {
        let to_dovecot = "Nov 15 10:00:02 mail postfix/smtp[1]: Q1: to=<a@ex.com>, relay=mail.example.com[24], \
                          delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, status=sent (ok)";
        assert_eq!(event(to_dovecot), None);
        let to_root = "Nov 15 10:00:02 mail postfix/local[1]: Q2: to=<root@localhost>, relay=local, \
                       delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, status=sent (delivered)";
        assert_eq!(event(to_root), None);
    }

    #[test]
    fn timestamps() {
        let rfc = "2025-11-15T10:00:02.123456+00:00 mail postfix/qmgr[1]: Q: removed";
        assert_eq!(line_time_millis(rfc, NOW), Some(1_763_200_802_123));
        // A December line read in mid-November is from last year.
        let dec = line_time_millis("Dec 31 23:59:59 mail postfix/qmgr[1]: Q: removed", NOW)
            .expect("time");
        assert!(dec < NOW * 1000);
        assert!(line_time_millis("Foo 15 10:00:00 mail x", NOW).is_none());
        assert!(line_time_millis("Nov 15 10:00 mail x", NOW).is_none());
    }

    #[test]
    fn provider_groups_match_go() {
        assert_eq!(provider_group("x@googlemail.com"), "google");
        assert_eq!(provider_group("x@outlook.de"), "outlook");
        assert_eq!(provider_group("yahoo.co.jp"), "yahoo");
        assert_eq!(provider_group("x@pm.me"), "proton");
        assert_eq!(provider_group("x@example.org"), "other");
        assert_eq!(provider_group(""), "other");
    }
}
