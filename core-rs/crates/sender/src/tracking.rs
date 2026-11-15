//! Open/click tracking in outgoing HTML (Go: `maillog_stat.MailTracker`),
//! with signed links (`ferropost_domain::tracking::encode_signed`).

use std::sync::LazyLock;

use ferropost_domain::tracking::{EventKind, TrackingEvent, encode_signed};
use regex::Regex;

static HREF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"href\s*=\s*"([^"]+)""#).expect("pattern"));

pub struct Tracker<'a> {
    base: String,
    campaign_id: i64,
    recipient: &'a str,
    message_id: String,
    key: &'a [u8; 32],
}

impl<'a> Tracker<'a> {
    /// `base_url` is the public console URL; links go to `<base>/pmta/...`.
    /// `message_id` may include angle brackets.
    pub fn new(
        base_url: &str,
        campaign_id: i64,
        recipient: &'a str,
        message_id: &str,
        key: &'a [u8; 32],
    ) -> Self {
        Self {
            base: format!("{}/pmta", base_url.trim_end_matches('/')),
            campaign_id,
            recipient,
            message_id: message_id.trim_matches(['<', '>']).to_owned(),
            key,
        }
    }

    fn url(&self, kind: EventKind, url: &str) -> String {
        let event = TrackingEvent {
            kind,
            campaign_id: self.campaign_id,
            recipient: self.recipient.to_owned(),
            message_id: self.message_id.clone(),
            url: url.to_owned(),
        };
        format!("{}/{}", self.base, encode_signed(&event, self.key))
    }

    /// Points every absolute `http(s)` link at the click tracker. Relative,
    /// `mailto:` and other links are left as they are (as in Go, which
    /// required a scheme and a host).
    pub fn track_links(&self, html: &str) -> String {
        HREF.replace_all(html, |caps: &regex::Captures| {
            let target = &caps[1];
            if is_absolute_web_url(target) {
                format!(r#"href="{}""#, self.url(EventKind::Click, target))
            } else {
                caps[0].to_owned()
            }
        })
        .into_owned()
    }

    /// Adds the open pixel before `</body>`, else before `</html>`, else at
    /// the end.
    pub fn add_pixel(&self, html: &str) -> String {
        let pixel = format!(
            r#"<img src="{}" style="display:none" alt="" />"#,
            self.url(EventKind::Open, "")
        );
        for close in ["</body>", "</html>"] {
            if let Some(pos) = html.find(close) {
                return format!("{}{pixel}{}", &html[..pos], &html[pos..]);
            }
        }
        format!("{html}{pixel}")
    }
}

fn is_absolute_web_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .is_some_and(|rest| {
            rest.split(['/', '?', '#'])
                .next()
                .is_some_and(|host| !host.is_empty())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferropost_domain::tracking::{Origin, decode, tracking_key};

    #[test]
    fn rewrites_links_and_adds_pixel() {
        let key = tracking_key("s");
        let tracker = Tracker::new(
            "https://mail.x.com/",
            12,
            "a@x.com",
            "<m1@mail.x.com>",
            &key,
        );
        let html = r#"<html><body><a href = "https://shop.example/sale?a=1">Sale</a>
                      <a href="mailto:hi@x.com">Mail</a><a href="/relative">R</a></body></html>"#;
        let out = tracker.add_pixel(&tracker.track_links(html));

        assert_eq!(
            out.matches("https://mail.x.com/pmta/v2.").count(),
            2,
            "one click link, one pixel"
        );
        assert!(out.contains(r#"href="mailto:hi@x.com""#) && out.contains(r#"href="/relative""#));
        assert!(out.contains(r#"style="display:none" alt="" /></body>"#));

        let token = out
            .split("https://mail.x.com/pmta/")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("token");
        let (event, origin) = decode(token, &key).expect("valid");
        assert_eq!(origin, Origin::Signed);
        assert_eq!(
            (
                event.kind,
                event.url.as_str(),
                event.message_id.as_str(),
                event.campaign_id
            ),
            (
                EventKind::Click,
                "https://shop.example/sale?a=1",
                "m1@mail.x.com",
                12
            )
        );
    }

    #[test]
    fn pixel_without_body() {
        let key = tracking_key("s");
        let tracker = Tracker::new("https://m", 1, "a@x.com", "m", &key);
        assert!(
            tracker
                .add_pixel("<p>hi</p>")
                .starts_with("<p>hi</p><img src=\"https://m/pmta/v2.")
        );
        assert!(tracker.add_pixel("<html>x</html>").ends_with("/></html>"));
    }
}
