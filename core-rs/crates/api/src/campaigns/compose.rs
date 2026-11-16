//! One campaign message for one recipient (Go: `personalizeEmail` and
//! `sendEmail`).
//!
//! Differences from Go: each message is rendered once. Go rendered the
//! personalised result a second time, so template syntax inside a
//! subscriber's own attributes (which the public subscribe form accepts)
//! was executed. Messages carry `List-Unsubscribe` and
//! `List-Unsubscribe-Post` (RFC 8058 one-click), which Gmail and Yahoo
//! require of bulk senders; Go sent neither. Unsubscribe links are not
//! click-tracked: Go counted every unsubscribe as a click, and the link
//! only worked while tracking did.

use ferropost_domain::campaigns::{
    Task, one_click_url, restore_unknown_tags, unsubscribe_page_url,
};
use ferropost_sender::smtp::{Outgoing, message_id};
use ferropost_sender::spintax;
use ferropost_sender::template::{RenderData, Subscriber, TaskInfo, render};
use ferropost_sender::tokens::{TokenKeys, UnsubscribeClaims, issue_unsubscribe};
use ferropost_sender::tracking::Tracker;

/// Contact row used for personalising: attributes, active, status.
pub type ContactData = (serde_json::Value, i32, i32);

pub struct Composer<'a> {
    pub task: &'a Task,
    /// The template prepared for the campaign (unsubscribe link added).
    pub content: &'a str,
    /// Public URL for links, from the sender's domain.
    pub base_url: &'a str,
    pub keys: &'a TokenKeys,
    pub tracking_key: &'a [u8; 32],
    pub now: i64,
}

fn task_info(t: &Task) -> TaskInfo {
    TaskInfo {
        id: t.id.into(),
        task_name: t.task_name.clone(),
        addresser: t.addresser.clone(),
        subject: t.subject.clone(),
        full_name: t.full_name.clone(),
        recipient_count: t.recipient_count.into(),
        task_process: t.task_process.into(),
        pause: t.pause.into(),
        template_id: t.template_id.into(),
        is_record: t.is_record.into(),
        unsubscribe: t.unsubscribe.into(),
        threads: t.threads.into(),
        track_open: t.track_open.into(),
        track_click: t.track_click.into(),
        start_time: t.start_time.into(),
        create_time: t.create_time.into(),
        update_time: t.update_time.into(),
        remark: t.remark.clone(),
        active: t.active.into(),
    }
}

/// Renders, applies spintax, then restores unknown tags, as Go did for both
/// the body and the subject.
pub fn personalise(content: &str, data: &RenderData, rng: &mut impl rand::Rng) -> String {
    let out = render(content, data);
    let out = if spintax::has_spintax(&out) {
        spintax::spin(&out, rng)
    } else {
        out
    };
    restore_unknown_tags(&out)
}

/// Click tracking (sparing the unsubscribe links) and the open pixel.
pub fn apply_tracking(
    tracker: &Tracker,
    html: String,
    base_url: &str,
    click: bool,
    open: bool,
) -> String {
    let html = if click {
        let unsubscribe = [
            format!("{base_url}/unsubscribe"),
            format!("{base_url}/api/unsubscribe"),
        ];
        tracker.track_links_except(&html, &[&unsubscribe[0], &unsubscribe[1]])
    } else {
        html
    };
    if open { tracker.add_pixel(&html) } else { html }
}

/// The RFC 8058 headers for mail with an unsubscribe token for a group.
pub fn list_unsubscribe(base_url: &str, jwt: &str) -> Vec<(String, String)> {
    vec![
        (
            "List-Unsubscribe".to_owned(),
            format!("<{}>", one_click_url(base_url, jwt)),
        ),
        (
            "List-Unsubscribe-Post".to_owned(),
            "List-Unsubscribe=One-Click".to_owned(),
        ),
    ]
}

impl Composer<'_> {
    pub fn compose(
        &self,
        recipient: &str,
        contact: Option<&ContactData>,
        rng: &mut impl rand::Rng,
    ) -> Outgoing {
        let t = self.task;
        let subscriber = match contact {
            Some((attribs, active, status)) => {
                Subscriber::from_contact(recipient, attribs, *active, *status)
            }
            None => Subscriber {
                email: recipient.to_owned(),
                ..Subscriber::default()
            },
        };
        let jwt = (t.unsubscribe == 1).then(|| {
            issue_unsubscribe(
                self.keys,
                UnsubscribeClaims {
                    email: recipient.to_owned(),
                    template_id: t.template_id.into(),
                    task_id: t.id.into(),
                    group_id: t.group_id.into(),
                },
                self.now,
            )
        });
        let data = RenderData {
            subscriber: Some(subscriber),
            task: Some(task_info(t)),
            unsubscribe_url: jwt
                .as_deref()
                .map(|jwt| unsubscribe_page_url(self.base_url, jwt, recipient, t.group_id))
                .unwrap_or_default(),
            ..RenderData::default()
        };
        let html = personalise(self.content, &data, rng);
        let subject = personalise(&t.subject, &data, rng);

        let id = message_id(&t.addresser);
        let tracker = Tracker::new(
            self.base_url,
            t.id.into(),
            recipient,
            &id,
            self.tracking_key,
        );
        let html = apply_tracking(
            &tracker,
            html,
            self.base_url,
            t.track_click == 1,
            t.track_open == 1,
        );

        let headers = match &jwt {
            Some(jwt) if t.group_id > 0 => list_unsubscribe(self.base_url, jwt),
            _ => Vec::new(),
        };
        Outgoing {
            from_email: t.addresser.clone(),
            from_name: Some(t.full_name.clone()),
            to: vec![recipient.to_owned()],
            subject,
            html,
            headers,
            message_id: id,
        }
    }
}
