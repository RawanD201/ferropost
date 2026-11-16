//! Postfix's `main.cf`, mail queue and lookup maps as text (Go:
//! `service/mail_service`, `controller/mail_services`).

use std::collections::HashMap;

use serde::Serialize;

/// `main.cf` as logical lines: a line starting with whitespace continues
/// the previous one, `#` lines are comments.
fn logical_lines(content: &str) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let continues = line.starts_with([' ', '\t'])
            && !line.trim().is_empty()
            && !line.trim_start().starts_with('#');
        match spans.last_mut() {
            Some((_, end)) if continues && *end == offset => *end = offset + line.len(),
            _ => spans.push((offset, offset + line.len())),
        }
        offset += line.len();
    }
    spans
}

/// `name = value` of a logical line, unless it is a comment or blank.
fn definition(text: &str) -> Option<(&str, String)> {
    let first = text.trim_start();
    if first.is_empty() || first.starts_with('#') {
        return None;
    }
    let (name, value) = first.split_once('=')?;
    let value = value
        .split('\n')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Some((name.trim(), value))
}

/// Parameter values; the last definition wins, as in Postfix.
pub fn main_cf_values(content: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for (start, end) in logical_lines(content) {
        if let Some((name, value)) = definition(&content[start..end]) {
            values.insert(name.to_owned(), value);
        }
    }
    values
}

/// Sets parameters: every definition of a name is replaced (Go replaced
/// the first, which Postfix ignores when a later one exists), missing ones
/// are appended.
pub fn set_main_cf(content: &str, changes: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(content.len());
    let mut seen: Vec<&str> = Vec::new();
    for (start, end) in logical_lines(content) {
        let text = &content[start..end];
        match definition(text).and_then(|(name, _)| changes.iter().find(|(n, _)| *n == name)) {
            Some((name, value)) => {
                out.push_str(&format!("{name} = {value}\n"));
                seen.push(name);
            }
            None => out.push_str(text),
        }
    }
    for (name, value) in changes {
        if !seen.contains(name) {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("{name} = {value}\n"));
        }
    }
    out
}

/// Whether `name` has a definition (comments do not count; Go matched the
/// name anywhere in the file).
pub fn main_cf_defines(content: &str, name: &str) -> bool {
    logical_lines(content)
        .into_iter()
        .any(|(start, end)| definition(&content[start..end]).is_some_and(|(n, _)| n == name))
}

/// Queue parameters the console edits, with Postfix's defaults as Go
/// reported them.
pub const QUEUE_PARAMETERS: [(&str, &str); 6] = [
    ("bounce_queue_lifetime", "5d"),
    ("maximal_queue_lifetime", "5d"),
    ("minimal_backoff_time", "300s"),
    ("maximal_backoff_time", "4000s"),
    ("queue_run_delay", "300s"),
    ("trigger_timeout", "10s"),
];

/// A Postfix time value: a number with an optional unit (`s`, `m`, `h`,
/// `d`, `w`). Go wrote any text, so a line break added other settings.
pub fn valid_time(value: &str) -> bool {
    let digits = value.trim_end_matches(['s', 'm', 'h', 'd', 'w']);
    let unit_len = value.len() - digits.len();
    !digits.is_empty()
        && digits.len() <= 9
        && unit_len <= 1
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// A deferred message as the console lists it: one entry per recipient
/// (Go's `QueueMailItem`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueEntry {
    pub queue_id: String,
    pub sender: String,
    /// Always `null`; the recipient is in `recipient` (as in Go).
    pub recipients: Option<()>,
    pub arrival_time: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub delay_reason: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub message_size: i64,
    pub queue_name: String,
    pub forced_expire: bool,
    pub recipient: String,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map_or("", |(_, d)| d)
}

/// The deferred queue from `postqueue -j` (one JSON object per message),
/// optionally only mail from or to `domain`. Go filtered by running the
/// domain through `sh -c "... | grep -i '<domain>'"`, which let the
/// request run any command in the Postfix container.
pub fn deferred_entries(output: &str, domain: Option<&str>) -> Vec<QueueEntry> {
    let domain = domain.map(str::to_ascii_lowercase);
    let text = |v: &serde_json::Value, key: &str| v[key].as_str().unwrap_or_default().to_owned();
    let mut entries = Vec::new();
    for line in output.lines() {
        let Ok(item) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        if item["queue_name"] != "deferred" {
            continue;
        }
        let sender = text(&item, "sender");
        for recipient in item["recipients"].as_array().into_iter().flatten() {
            let address = text(recipient, "address");
            if let Some(domain) = &domain
                && !domain_of(&sender).eq_ignore_ascii_case(domain)
                && !domain_of(&address).eq_ignore_ascii_case(domain)
            {
                continue;
            }
            entries.push(QueueEntry {
                queue_id: text(&item, "queue_id"),
                sender: sender.clone(),
                recipients: None,
                arrival_time: item["arrival_time"].as_i64().unwrap_or_default(),
                delay_reason: text(recipient, "delay_reason"),
                message_size: item["message_size"].as_i64().unwrap_or_default(),
                queue_name: text(&item, "queue_name"),
                forced_expire: item["forced_expire"].as_bool().unwrap_or_default(),
                recipient: address,
            });
        }
    }
    entries
}

/// A Postfix queue ID (short hex or long format). Go passed any text to
/// `postsuper -d`, where `ALL` deletes the whole queue.
pub fn valid_queue_id(id: &str) -> bool {
    (5..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric())
        && !id.eq_ignore_ascii_case("ALL")
}

/// Runs a command once per queue ID in a single `docker exec`, the IDs as
/// arguments (never parsed by the shell); prints the IDs that failed.
pub fn per_id_script(command: &str) -> String {
    format!(
        "rc=0; for id do {command} \"$id\" >/dev/null 2>&1 || {{ echo \"$id\"; rc=1; }}; done; exit $rc"
    )
}

// ---- start-up repair (Go: FixPostfixMainConfig) ---------------------------------

/// Rewrites the `Received:` header of authenticated submissions so the
/// sender's own IP address does not travel with the mail.
pub const HEADER_CHECKS: &str = r"if /^\s*Received:.*Authenticated sender.*\(PostBillionMail\)/
/^Received: from .*? \([\w\-.]* \[.*?\]\)(.*|\n.*)\(Authenticated sender: (.+)\)\s+by.+\(PostBillionMail\) with (.*)/
  REPLACE Received: from [127.0.0.1] (localhost [127.0.0.1]) by localhost (Mailerdaemon) with $3
endif

/^\s*X-Enigmail/        IGNORE
/^\s*X-Originating-IP/  IGNORE
/^\s*X-Forward/         IGNORE
";

/// `conf/header_checks` with the rules above, or `None` when it has them.
pub fn fix_header_checks(existing: Option<&str>) -> Option<String> {
    match existing {
        None => Some(HEADER_CHECKS.to_owned()),
        Some(text)
            if !text.contains(
                "REPLACE Received: from [127.0.0.1] (localhost [127.0.0.1]) by localhost (Mailerdaemon) with $3",
            ) =>
        {
            Some(format!("{text}\n{HEADER_CHECKS}"))
        }
        Some(_) => None,
    }
}

/// Go's `FixPostfixMainConfig`: the server name and header checks follow
/// `compatibility_level`; a placeholder `myhostname` is replaced by
/// `hostname`. Unlike Go, which used the first domain itself, `hostname` is
/// a mail host name (`mail.<domain>`), the name the DNS records point at.
pub fn fix_main_cf(content: &str, hostname: &str) -> String {
    let mut out = String::with_capacity(content.len() + 256);
    let mut skip_blank = false;
    let mut has_hostname = false;
    for row in content.split_inclusive('\n') {
        let text = row.trim();
        if text.starts_with("smtp_header_checks")
            || text.starts_with("lmtp_header_checks")
            || text.starts_with("mail_name")
        {
            skip_blank = true;
            continue;
        }
        if skip_blank {
            skip_blank = false;
            if text.is_empty() {
                continue;
            }
        }
        if text.starts_with("compatibility_level") {
            out.push_str(
                "compatibility_level = 3.7\nmail_name = PostBillionMail\n\n\
                 smtp_header_checks = pcre:/etc/postfix/conf/header_checks\n\
                 lmtp_header_checks = pcre:/etc/postfix/conf/header_checks\n\n",
            );
            continue;
        }
        if !has_hostname && text.starts_with("myhostname") {
            match text.split_once('=').map(|(_, v)| v.trim()) {
                None | Some("" | "mail.example.com" | "localhost.localdomain" | "localhost") => {
                    skip_blank = true;
                    continue;
                }
                Some(_) => has_hostname = true,
            }
        }
        out.push_str(row);
    }
    if !has_hostname {
        if out.is_empty() || !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("myhostname = {hostname}\n"));
    }
    out
}

// ---- BCC maps (Go: SyncBccToPostfix) ------------------------------------------------

/// The lookup key of a BCC rule: `@domain` for a whole domain.
pub fn bcc_key(address: &str) -> String {
    if address.contains('@') {
        address.to_owned()
    } else {
        format!("@{address}")
    }
}

/// `conf/sender_bcc` or `conf/recipient_bcc` for the active rules
/// (`(address, goto)`). Postfix keeps one copy address per key, so a
/// repeated key keeps its first rule, as `postmap` would.
pub fn bcc_map(rules: &[(String, String)]) -> String {
    let mut keys: Vec<String> = Vec::new();
    let mut out = String::new();
    for (address, goto) in rules {
        let key = bcc_key(address);
        if keys.contains(&key) {
            continue;
        }
        out.push_str(&format!("{key} {goto}\n"));
        keys.push(key);
    }
    out
}

/// `main.cf` with the two BCC maps declared.
pub fn ensure_bcc_maps(main_cf: &str) -> String {
    let mut changes = Vec::new();
    if !main_cf_defines(main_cf, "sender_bcc_maps") {
        changes.push(("sender_bcc_maps", "hash:/etc/postfix/conf/sender_bcc"));
    }
    if !main_cf_defines(main_cf, "recipient_bcc_maps") {
        changes.push(("recipient_bcc_maps", "hash:/etc/postfix/conf/recipient_bcc"));
    }
    if changes.is_empty() {
        main_cf.to_owned()
    } else {
        set_main_cf(main_cf, &changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_sets_parameters() {
        let content = "# queue_run_delay = 1s\nqueue_run_delay = 100s\nsmtpd_banner = a\n  b\nqueue_run_delay = 200s\n";
        let values = main_cf_values(content);
        assert_eq!(
            values["queue_run_delay"], "200s",
            "the last definition wins"
        );
        assert_eq!(values["smtpd_banner"], "a b");
        let set = set_main_cf(
            content,
            &[("queue_run_delay", "60s"), ("trigger_timeout", "5s")],
        );
        assert_eq!(
            set,
            "# queue_run_delay = 1s\nqueue_run_delay = 60s\nsmtpd_banner = a\n  b\nqueue_run_delay = 60s\ntrigger_timeout = 5s\n"
        );
        assert_eq!(main_cf_values(&set)["queue_run_delay"], "60s");
        assert!(main_cf_defines(content, "smtpd_banner"));
        assert!(!main_cf_defines(
            "# sender_bcc_maps = x\n",
            "sender_bcc_maps"
        ));
    }

    #[test]
    fn times() {
        for ok in ["5d", "300s", "10", "4000s", "2w"] {
            assert!(valid_time(ok), "{ok}");
        }
        for bad in ["", "5x", "5dd", "d", "5d\nx = y", "-5s", "1234567890s"] {
            assert!(!valid_time(bad), "{bad:?}");
        }
    }

    #[test]
    fn queue() {
        let out = r#"{"queue_name":"deferred","queue_id":"4AB12C","arrival_time":10,"message_size":99,"forced_expire":false,"sender":"a@ex.test","recipients":[{"address":"x@far.test","delay_reason":"timeout"},{"address":"y@other.test"}]}
{"queue_name":"active","queue_id":"B","sender":"a@ex.test","recipients":[{"address":"z@far.test"}]}
not json"#;
        let all = deferred_entries(out, None);
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].recipient.as_str(), all[0].delay_reason.as_str()),
            ("x@far.test", "timeout")
        );
        assert_eq!(deferred_entries(out, Some("OTHER.test")).len(), 1);
        assert_eq!(deferred_entries(out, Some("ex.test")).len(), 2);
        let json = serde_json::to_value(&all[1]).expect("json");
        assert!(json.get("delay_reason").is_none() && json["recipients"].is_null());
        assert!(valid_queue_id("4AB12C") && valid_queue_id("4BtHgL3ZCVz9vQ"));
        for bad in ["ALL", "all", "-x", "a b", "1234", "4AB12C;rm"] {
            assert!(!valid_queue_id(bad), "{bad}");
        }
    }

    #[test]
    fn fixes_main_cf_like_go() {
        let content = "smtpd_banner = $myhostname ESMTP $mail_name\ncompatibility_level = 3.6\nmail_name = Old\n\nsmtp_header_checks = x\nmyhostname = mail.example.com\n\nqueue_directory = /q\n";
        let fixed = fix_main_cf(content, "mail.ex.test");
        assert_eq!(
            fixed,
            "smtpd_banner = $myhostname ESMTP $mail_name\ncompatibility_level = 3.7\nmail_name = PostBillionMail\n\nsmtp_header_checks = pcre:/etc/postfix/conf/header_checks\nlmtp_header_checks = pcre:/etc/postfix/conf/header_checks\n\nqueue_directory = /q\nmyhostname = mail.ex.test\n"
        );
        assert_eq!(fix_main_cf(&fixed, "other"), fixed, "idempotent");
        let kept = "myhostname = real.host\n";
        assert_eq!(fix_main_cf(kept, "x"), kept);
        assert_eq!(fix_header_checks(None).as_deref(), Some(HEADER_CHECKS));
        assert_eq!(fix_header_checks(Some(HEADER_CHECKS)), None);
        assert!(
            fix_header_checks(Some("/x/ IGNORE\n"))
                .is_some_and(|t| t.starts_with("/x/ IGNORE\n\nif "))
        );
    }

    #[test]
    fn bcc() {
        let rules = [
            ("ex.test".to_owned(), "archive@ex.test".to_owned()),
            ("boss@ex.test".to_owned(), "copy@ex.test".to_owned()),
            ("ex.test".to_owned(), "second@ex.test".to_owned()),
        ];
        assert_eq!(
            bcc_map(&rules),
            "@ex.test archive@ex.test\nboss@ex.test copy@ex.test\n"
        );
        let main = ensure_bcc_maps("a = 1\n");
        assert_eq!(
            main,
            "a = 1\nsender_bcc_maps = hash:/etc/postfix/conf/sender_bcc\nrecipient_bcc_maps = hash:/etc/postfix/conf/recipient_bcc\n"
        );
        assert_eq!(ensure_bcc_maps(&main), main);
    }
}
