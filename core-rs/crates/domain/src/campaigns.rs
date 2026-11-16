//! Campaigns (Go: `batch_mail`): a task sends one template to the
//! recipients chosen from a contact group when it was created.

use std::sync::LazyLock;

use regex::Regex;

/// `email_tasks.task_process`.
pub mod status {
    pub const NOT_STARTED: i32 = 0;
    pub const RUNNING: i32 = 1;
    pub const COMPLETED: i32 = 2;
    pub const PAUSED: i32 = 3;
}

/// `recipient_info.is_sent`.
pub mod recipient {
    /// Waiting; `sent_time` holds the earliest send time when a warmup
    /// limit postponed it.
    pub const PENDING: i32 = 0;
    pub const SENT: i32 = 1;
    /// Claimed by the sender, not yet submitted.
    pub const CLAIMED: i32 = 2;
    pub const FAILED: i32 = 3;
}

/// Consecutive submission failures that pause a campaign (Go's circuit
/// breaker; Go only paused it in memory, so the console kept showing it as
/// running).
pub const CIRCUIT_BREAKER: u32 = 10;

/// A row of `email_tasks`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Task {
    pub id: i32,
    pub task_name: String,
    pub addresser: String,
    pub subject: String,
    pub full_name: String,
    pub recipient_count: i32,
    pub task_process: i32,
    pub pause: i32,
    pub template_id: i32,
    pub is_record: i32,
    pub unsubscribe: i32,
    pub threads: i32,
    pub track_open: i32,
    pub track_click: i32,
    pub start_time: i32,
    pub create_time: i32,
    pub update_time: i32,
    pub remark: String,
    pub active: i32,
    pub add_type: i32,
    pub sends_count: i32,
    pub delivered_count: i32,
    pub bounced_count: i32,
    pub deferred_count: i32,
    pub stats_update_time: i32,
    pub group_id: i32,
    /// JSON array as Go stored it (`[1,2]`), or empty.
    pub tag_ids: String,
    pub tag_logic: String,
}

impl Task {
    pub fn tag_ids(&self) -> Vec<i32> {
        parse_tag_ids(&self.tag_ids)
    }

    /// Concurrent submissions (Go defaulted to 6 when unset).
    pub fn concurrency(&self) -> usize {
        if self.threads > 0 {
            self.threads.min(100) as usize
        } else {
            6
        }
    }

    pub fn is_running(&self) -> bool {
        self.task_process == status::RUNNING && self.pause == 0
    }
}

pub fn parse_tag_ids(raw: &str) -> Vec<i32> {
    serde_json::from_str(raw).unwrap_or_default()
}

/// How Go stored tag IDs: `[1,2]`, or empty for none.
pub fn format_tag_ids(ids: &[i32]) -> String {
    if ids.is_empty() {
        String::new()
    } else {
        serde_json::to_string(ids).unwrap_or_default()
    }
}

/// Go's send rate: 20 messages per second per thread.
pub fn emails_per_minute(threads: i32) -> i64 {
    i64::from(threads.max(1)) * 20 * 60
}

/// Progress shown in the task list from the delivery count (Go rounded 98%
/// and up to 100).
pub fn list_progress(sent: i32, recipients: i32) -> i32 {
    if recipients <= 0 {
        return 0;
    }
    let progress = (f64::from(sent) / f64::from(recipients) * 100.0) as i32;
    if progress >= 98 { 100 } else { progress }
}

const UNSUBSCRIBE_BUTTON: &str = r#"<div style="padding: 16px 0; text-align: center"><a href="{{ UnsubscribeURL . }}" style="color: #ccc; font-size: 12px">Unsubscribe</a></div>"#;

/// Adds an unsubscribe link before `</body>` (or `</html>`), or wraps a
/// fragment in a page with one, unless it already has the link (Go:
/// `public.AddUnsubscribeButton`).
pub fn add_unsubscribe_button(content: &str) -> String {
    if content.contains("{{ UnsubscribeURL . }}") {
        return content.to_owned();
    }
    for close in ["</body>", "</html>"] {
        if content.contains(close) {
            return content.replacen(close, &format!("{UNSUBSCRIBE_BUTTON}{close}"), 1);
        }
    }
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body><div style="width: 100%; max-width: 600px; margin: 0 auto;">{content}{UNSUBSCRIBE_BUTTON}</div></body></html>"#
    )
}

/// The template as a campaign sends it: with an unsubscribe link when the
/// campaign offers one (Go: `processEmailContent`).
pub fn prepare_content(content: &str, unsubscribe: bool) -> String {
    if !unsubscribe {
        return content.to_owned();
    }
    let content = if content.contains("__UNSUBSCRIBE_URL__") {
        content.to_owned()
    } else {
        add_unsubscribe_button(content)
    };
    content.replace("__UNSUBSCRIBE_URL__", "{{ UnsubscribeURL . }}")
}

/// Puts back tags the renderer could not resolve (`[__x__]` becomes
/// `{{x}}`), as Go did after rendering.
pub fn restore_unknown_tags(content: &str) -> String {
    static TAG: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\[__([^_]+)__\]").expect("pattern"));
    TAG.replace_all(content, "{{$1}}").into_owned()
}

/// The unsubscribe page a campaign links to: one-click for the campaign's
/// group, or the page listing the address's groups.
pub fn unsubscribe_page_url(base: &str, jwt: &str, email: &str, group_id: i32) -> String {
    if group_id > 0 {
        format!("{base}/unsubscribe_new.html?jwt={jwt}")
    } else {
        format!(
            "{base}/unsubscribe.html?jwt={jwt}&email={email}&url_type={base}/api/unsubscribe/user_group&url_unsubscribe={base}/api/unsubscribe"
        )
    }
}

/// Target of the `List-Unsubscribe` header (RFC 8058 one-click), which
/// mailbox providers POST to directly.
pub fn one_click_url(base: &str, jwt: &str) -> String {
    format!("{base}/api/unsubscribe/one_click?jwt={jwt}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_ids_round_trip() {
        assert_eq!(parse_tag_ids("[1,2]"), [1, 2]);
        assert_eq!(parse_tag_ids(""), Vec::<i32>::new());
        assert_eq!(parse_tag_ids("garbage"), Vec::<i32>::new());
        assert_eq!(format_tag_ids(&[3, 4]), "[3,4]");
        assert_eq!(format_tag_ids(&[]), "");
    }

    #[test]
    fn unsubscribe_button_like_go() {
        let body = "<html><body><p>Hi</p></body></html>";
        assert_eq!(
            add_unsubscribe_button(body),
            format!("<html><body><p>Hi</p>{UNSUBSCRIBE_BUTTON}</body></html>")
        );
        assert_eq!(
            add_unsubscribe_button("<html>x</html>"),
            format!("<html>x{UNSUBSCRIBE_BUTTON}</html>")
        );
        let fragment = add_unsubscribe_button("<p>Hi</p>");
        assert!(fragment.starts_with("<!DOCTYPE html>") && fragment.contains("<p>Hi</p><div"));
        let has = "<a href=\"{{ UnsubscribeURL . }}\">x</a>";
        assert_eq!(add_unsubscribe_button(has), has);
    }

    #[test]
    fn content_preparation() {
        assert_eq!(prepare_content("<p>x</p>", false), "<p>x</p>");
        assert_eq!(
            prepare_content("<a href=\"__UNSUBSCRIBE_URL__\">u</a>", true),
            "<a href=\"{{ UnsubscribeURL . }}\">u</a>"
        );
        assert!(prepare_content("<body>x</body>", true).contains("{{ UnsubscribeURL . }}"));
        assert_eq!(
            restore_unknown_tags("Hi [__.Foo__] and [__x_y__]"),
            "Hi {{.Foo}} and [__x_y__]"
        );
    }

    #[test]
    fn links() {
        assert_eq!(
            unsubscribe_page_url("https://m.x", "J", "a@x.com", 2),
            "https://m.x/unsubscribe_new.html?jwt=J"
        );
        assert_eq!(
            unsubscribe_page_url("https://m.x", "J", "a@x.com", 0),
            "https://m.x/unsubscribe.html?jwt=J&email=a@x.com&url_type=https://m.x/api/unsubscribe/user_group&url_unsubscribe=https://m.x/api/unsubscribe"
        );
        assert_eq!(
            one_click_url("https://m.x", "J"),
            "https://m.x/api/unsubscribe/one_click?jwt=J"
        );
    }

    #[test]
    fn progress_and_rate() {
        assert_eq!(list_progress(50, 100), 50);
        assert_eq!(list_progress(98, 100), 100);
        assert_eq!(list_progress(150, 100), 100);
        assert_eq!(list_progress(5, 0), 0);
        assert_eq!(emails_per_minute(5), 6000);
        let task = Task {
            threads: 0,
            ..Task::default()
        };
        assert_eq!(task.concurrency(), 6);
        assert_eq!(
            Task {
                threads: 500,
                ..task
            }
            .concurrency(),
            100
        );
    }
}
