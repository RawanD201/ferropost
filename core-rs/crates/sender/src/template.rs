//! Personalisation of email templates (Go: `batch_mail/template_render.go`).
//!
//! Templates written for the Go core use Go `text/template` syntax through
//! GoFrame's `gview` (`{{.Subscriber.Email}}`, `{{get .Subscriber "x"}}`,
//! `{{UnsubscribeURL .}}`, `{{range ...}}`). They are rendered with `gtmpl`,
//! a Go template implementation, with the same data and the helpers an
//! email is likely to use. Like `gview`, `<no value>` is removed from the
//! output, and a template that fails to render falls back the way Go did.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use gtmpl::{Context, FuncError, Template, Value};
use regex::Regex;

/// The contact a message is rendered for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subscriber {
    pub email: String,
    pub active: i64,
    pub status: i64,
    pub attribs: BTreeMap<String, String>,
}

impl Subscriber {
    /// From a contact row: attribute values become text, as Go's
    /// `map[string]string` contact attributes did.
    pub fn from_contact(
        email: &str,
        attribs: &serde_json::Value,
        active: i32,
        status: i32,
    ) -> Self {
        Self {
            email: email.to_owned(),
            active: active.into(),
            status: status.into(),
            attribs: attribs
                .as_object()
                .map(|o| {
                    o.iter()
                        .map(|(k, v)| {
                            (
                                k.clone(),
                                v.as_str().map_or_else(|| v.to_string(), str::to_owned),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// Campaign fields exposed as `.Task.*` (Go's `entity.EmailTask`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskInfo {
    pub id: i64,
    pub task_name: String,
    pub addresser: String,
    pub subject: String,
    pub full_name: String,
    pub recipient_count: i64,
    pub task_process: i64,
    pub pause: i64,
    pub template_id: i64,
    pub is_record: i64,
    pub unsubscribe: i64,
    pub threads: i64,
    pub track_open: i64,
    pub track_click: i64,
    pub start_time: i64,
    pub create_time: i64,
    pub update_time: i64,
    pub remark: String,
    pub active: i64,
}

#[derive(Debug, Clone, Default)]
pub struct RenderData {
    pub subscriber: Option<Subscriber>,
    pub task: Option<TaskInfo>,
    pub unsubscribe_url: String,
    /// `attribs` of an API send, as `.API.*`.
    pub api: BTreeMap<String, serde_json::Value>,
}

/// Lead-signal phrases for `.Enrichment.*` (Go: `batch_mail.SignalCopy`).
const SIGNAL_COPY: &[(&str, &str)] = &[
    ("multiple_providers", "managing multiple locations"),
    ("running_ads", "investing in paid advertising"),
    ("high_reviews", "a strong online reputation"),
    ("premium_services", "offering premium services"),
    ("affluent_zip", "serving an affluent market"),
    ("no_chat", "missing live chat on your website"),
    (
        "voicemail_after_hrs",
        "calls going to voicemail after hours",
    ),
    ("no_online_booking", "no online self-scheduling for clients"),
    ("slow_form", "slow response times on contact forms"),
    (
        "high_spend_low_rating",
        "high ad spend with room to improve reviews",
    ),
    ("owner_email", "being hands-on with the business"),
    ("active_social", "being active on social media"),
    (
        "industry_community",
        "being involved in industry communities",
    ),
];

/// Comma-separated signal keys to phrases, unknown keys dropped.
pub fn signals_to_copy(signals: &str) -> Vec<&'static str> {
    signals
        .split(',')
        .map(str::trim)
        .filter_map(|key| {
            SIGNAL_COPY
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, copy)| *copy)
        })
        .collect()
}

fn s(v: impl Into<String>) -> Value {
    Value::String(v.into())
}

fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::from(i),
            None => Value::from(n.as_f64().unwrap_or_default()),
        },
        serde_json::Value::String(t) => s(t.as_str()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_value).collect()),
        serde_json::Value::Object(o) => Value::Map(
            o.iter()
                .map(|(k, v)| (k.clone(), json_to_value(v)))
                .collect(),
        ),
    }
}

impl RenderData {
    fn to_value(&self) -> Value {
        let mut subscriber = HashMap::new();
        let mut video = HashMap::new();
        let mut enrichment = HashMap::new();
        if let Some(sub) = &self.subscriber {
            for (k, v) in &sub.attribs {
                subscriber.insert(k.clone(), s(v.as_str()));
            }
            subscriber.insert("Email".into(), s(sub.email.as_str()));
            subscriber.insert("Active".into(), Value::from(sub.active));
            subscriber.insert("Status".into(), Value::from(sub.status));

            for (key, name) in [
                ("video_url", "VideoURL"),
                ("thumbnail_url", "ThumbnailURL"),
                ("landing_page_url", "LandingPageURL"),
                ("lead_tier", "LeadTier"),
                ("lead_score", "LeadScore"),
            ] {
                if let Some(v) = sub.attribs.get(key) {
                    video.insert(name.to_owned(), s(v.as_str()));
                }
            }

            let signals = sub.attribs.get("lead_signals").cloned().unwrap_or_default();
            let copies = signals_to_copy(&signals);
            enrichment.insert("Signals".into(), s(signals.as_str()));
            enrichment.insert("SignalCount".into(), Value::from(copies.len() as i64));
            enrichment.insert(
                "TopSignal".into(),
                s(copies.first().copied().unwrap_or_default()),
            );
            enrichment.insert(
                "SecondSignal".into(),
                s(copies.get(1).copied().unwrap_or_default()),
            );
            enrichment.insert("PainPoints".into(), s(copies.join(", ")));
        }

        let t = self.task.clone().unwrap_or_default();
        let task = HashMap::from([
            ("Id".to_owned(), Value::from(t.id)),
            ("TaskName".to_owned(), s(t.task_name)),
            ("Addresser".to_owned(), s(t.addresser)),
            ("Subject".to_owned(), s(t.subject)),
            ("FullName".to_owned(), s(t.full_name)),
            ("RecipientCount".to_owned(), Value::from(t.recipient_count)),
            ("TaskProcess".to_owned(), Value::from(t.task_process)),
            ("Pause".to_owned(), Value::from(t.pause)),
            ("TemplateId".to_owned(), Value::from(t.template_id)),
            ("IsRecord".to_owned(), Value::from(t.is_record)),
            ("Unsubscribe".to_owned(), Value::from(t.unsubscribe)),
            ("Threads".to_owned(), Value::from(t.threads)),
            ("Etypes".to_owned(), s("")),
            ("TrackOpen".to_owned(), Value::from(t.track_open)),
            ("TrackClick".to_owned(), Value::from(t.track_click)),
            ("StartTime".to_owned(), Value::from(t.start_time)),
            ("CreateTime".to_owned(), Value::from(t.create_time)),
            ("UpdateTime".to_owned(), Value::from(t.update_time)),
            ("Remark".to_owned(), s(t.remark)),
            ("Active".to_owned(), Value::from(t.active)),
        ]);

        // Go only exposed API attributes when a contact was present.
        let api: HashMap<String, Value> = if self.subscriber.is_some() {
            self.api
                .iter()
                .map(|(k, v)| (k.clone(), json_to_value(v)))
                .collect()
        } else {
            HashMap::new()
        };

        Value::Map(HashMap::from([
            ("Subscriber".to_owned(), Value::Map(subscriber)),
            ("Task".to_owned(), Value::Map(task)),
            (
                "UnsubscribeURL".to_owned(),
                s(self.unsubscribe_url.as_str()),
            ),
            ("API".to_owned(), Value::Map(api)),
            ("VideoOutreach".to_owned(), Value::Map(video)),
            ("Enrichment".to_owned(), Value::Map(enrichment)),
        ]))
    }
}

/// Renders `content` for one recipient. Never fails: on errors it falls back
/// like Go (unknown tags become `[__tag__]`, and if that still fails the
/// raw content is returned).
pub fn render(content: &str, data: &RenderData) -> String {
    // Go turned literal escape sequences into the characters.
    let content = content
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
        .replace("\\t", "\t");
    let value = data.to_value();
    match try_render(&content, &value) {
        Ok(out) => out,
        Err(_) => try_render(&clean_unknown_tags(&content), &value).unwrap_or(content),
    }
}

/// Renders arbitrary data (used by subscribe pages and system mail).
pub fn render_value(content: &str, value: &serde_json::Value) -> Result<String, String> {
    try_render(content, &json_to_value(value))
}

fn try_render(content: &str, value: &Value) -> Result<String, String> {
    let mut template = Template::default();
    for (name, func) in FUNCS {
        template.add_func(name, *func);
    }
    template.parse(content).map_err(|e| e.to_string())?;
    let out = template
        .render(&Context::from(value.clone()))
        .map_err(|e| e.to_string())?;
    Ok(out.replace("<no value>", ""))
}

static ANY_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{[\s\S]*?}}").expect("pattern"));
static KNOWN_VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\{\{\s*\.\s*(Subscriber|Task|API|VideoOutreach|Enrichment)\s*\.\s*[^\s{}]+[^}]*}}$",
    )
    .expect("pattern")
});
static KNOWN_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*UnsubscribeURL\s+[^}]*").expect("pattern"));

/// Go's `cleanUndefinedVariables`: keeps known variables and functions,
/// turns every other tag into `[__inner__]`, and drops blank lines.
fn clean_unknown_tags(content: &str) -> String {
    let cleaned = ANY_TAG.replace_all(content, |caps: &regex::Captures| {
        let tag = &caps[0];
        let inner = tag[2..tag.len() - 2].trim();
        if KNOWN_VARIABLE.is_match(tag) || KNOWN_FUNCTION.is_match(inner) {
            tag.to_owned()
        } else {
            format!("[__{inner}__]")
        }
    });
    cleaned
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

// ---- helpers ---------------------------------------------------------------

type Func = fn(&[Value]) -> Result<Value, FuncError>;

const FUNCS: &[(&str, Func)] = &[
    ("get", get),
    ("UnsubscribeURL", unsubscribe_url),
    ("html", html_encode),
    ("htmlencode", html_encode),
    ("encode", html_encode),
    ("url", url_encode),
    ("urlencode", url_encode),
    ("toupper", to_upper),
    ("tolower", to_lower),
    ("concat", concat),
    ("replace", replace),
    ("substr", substr),
    ("strlimit", strlimit),
];

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Nil | Value::NoValue => String::new(),
        other => other.to_string(),
    }
}

fn arg(args: &[Value], i: usize) -> String {
    args.get(i).map(text).unwrap_or_default()
}

fn int_arg(args: &[Value], i: usize) -> i64 {
    match args.get(i) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or_default(),
        Some(v) => text(v).trim().parse().unwrap_or_default(),
        None => 0,
    }
}

/// `get .Subscriber "key"`: map lookup that yields `""` when missing.
fn get(args: &[Value]) -> Result<Value, FuncError> {
    Ok(match (args.first(), args.get(1)) {
        (Some(Value::Map(m)), Some(key)) => m.get(&text(key)).cloned().unwrap_or_else(|| s("")),
        _ => s(""),
    })
}

/// `UnsubscribeURL .`
fn unsubscribe_url(args: &[Value]) -> Result<Value, FuncError> {
    Ok(match args.first() {
        Some(Value::Map(m)) => m.get("UnsubscribeURL").cloned().unwrap_or_else(|| s("")),
        _ => s(""),
    })
}

fn html_encode(args: &[Value]) -> Result<Value, FuncError> {
    let mut out = String::new();
    for c in arg(args, 0).chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    Ok(s(out))
}

/// Go's `url.QueryEscape`.
fn url_encode(args: &[Value]) -> Result<Value, FuncError> {
    let mut out = String::new();
    for b in arg(args, 0).bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    Ok(s(out))
}

fn to_upper(args: &[Value]) -> Result<Value, FuncError> {
    Ok(s(arg(args, 0).to_uppercase()))
}

fn to_lower(args: &[Value]) -> Result<Value, FuncError> {
    Ok(s(arg(args, 0).to_lowercase()))
}

fn concat(args: &[Value]) -> Result<Value, FuncError> {
    Ok(s(args.iter().map(text).collect::<String>()))
}

/// `replace search replacement subject` (gview's argument order).
fn replace(args: &[Value]) -> Result<Value, FuncError> {
    Ok(s(arg(args, 2).replace(&arg(args, 0), &arg(args, 1))))
}

/// `substr start length subject`, in characters.
fn substr(args: &[Value]) -> Result<Value, FuncError> {
    let subject: Vec<char> = arg(args, 2).chars().collect();
    let start = usize::try_from(int_arg(args, 0).max(0))
        .unwrap_or(0)
        .min(subject.len());
    let len = usize::try_from(int_arg(args, 1).max(0)).unwrap_or(0);
    Ok(s(subject[start..(start + len).min(subject.len())]
        .iter()
        .collect::<String>()))
}

/// `strlimit length suffix subject`.
fn strlimit(args: &[Value]) -> Result<Value, FuncError> {
    let subject = arg(args, 2);
    let limit = usize::try_from(int_arg(args, 0).max(0)).unwrap_or(0);
    if subject.chars().count() <= limit {
        return Ok(s(subject));
    }
    Ok(s(
        subject.chars().take(limit).collect::<String>() + &arg(args, 1)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> RenderData {
        RenderData {
            subscriber: Some(Subscriber {
                email: "ann@x.com".into(),
                active: 1,
                status: 1,
                attribs: BTreeMap::from([
                    ("first_name".to_owned(), "Ann".to_owned()),
                    (
                        "lead_signals".to_owned(),
                        "no_chat, running_ads, bogus".to_owned(),
                    ),
                    ("video_url".to_owned(), "https://v".to_owned()),
                ]),
            }),
            task: Some(TaskInfo {
                id: 7,
                full_name: "Acme Team".into(),
                subject: "News".into(),
                ..TaskInfo::default()
            }),
            unsubscribe_url: "https://mail.x.com/u/abc".into(),
            api: BTreeMap::from([("code".to_owned(), serde_json::json!(1234))]),
        }
    }

    #[test]
    fn renders_go_templates() {
        let out = render(
            "Hi {{.Subscriber.first_name}} ({{.Subscriber.Email}}) from {{.Task.FullName}}\\n\
             {{get .Subscriber \"first_name\"}}|{{.Subscriber.missing}}|{{.API.code}}\
             |<a href=\"{{UnsubscribeURL .}}\">x</a>|{{.Enrichment.TopSignal}}; {{.Enrichment.PainPoints}}\
             |{{.VideoOutreach.VideoURL}}|{{if eq .Task.Id 7}}seven{{end}}",
            &data(),
        );
        assert_eq!(
            out,
            "Hi Ann (ann@x.com) from Acme Team\n\
             Ann||1234|<a href=\"https://mail.x.com/u/abc\">x</a>|missing live chat on your website; \
             missing live chat on your website, investing in paid advertising|https://v|seven"
        );
    }

    /// Output of GoFrame `gview` v2.10.0 (real Go, same helpers bound) for
    /// the same template and data.
    #[test]
    fn matches_goframe_gview() {
        let template = "Hi {{.Subscriber.first_name}} ({{.Subscriber.Email}}) from {{.Task.FullName}}\
                        |{{get .Subscriber \"first_name\"}}|{{.Subscriber.missing}}|{{.API.code}}\
                        |<a href=\"{{UnsubscribeURL .}}\">x</a>|{{if eq .Task.Id 7}}seven{{end}}\
                        |{{toupper .Subscriber.first_name}}|{{html \"<b>&\"}}\
                        |{{replace \"Ann\" \"Bo\" .Subscriber.first_name}}|{{substr 1 2 \"héllo\"}}";
        assert_eq!(
            render(template, &data()),
            "Hi Ann (ann@x.com) from Acme Team|Ann||1234|<a href=\"https://mail.x.com/u/abc\">x</a>\
             |seven|ANN|&lt;b&gt;&amp;|Bo|él"
        );
    }

    #[test]
    fn helpers() {
        let d = data();
        assert_eq!(render("{{toupper .Subscriber.first_name}}", &d), "ANN");
        assert_eq!(render("{{html \"<b>&\"}}", &d), "&lt;b&gt;&amp;");
        assert_eq!(render("{{url \"a b&c\"}}", &d), "a+b%26c");
        assert_eq!(
            render("{{replace \"Ann\" \"Bo\" .Subscriber.first_name}}", &d),
            "Bo"
        );
        assert_eq!(render("{{substr 1 2 \"héllo\"}}", &d), "él");
        assert_eq!(render("{{strlimit 3 \"…\" \"abcdef\"}}", &d), "abc…");
        assert_eq!(render("{{concat \"a\" .Task.Id}}", &d), "a7");
    }

    #[test]
    fn falls_back_like_go() {
        // Unknown function: Go replaced the tag and dropped blank lines.
        let out = render(
            "Hello {{.Subscriber.first_name}}\n\n{{badfunc .x}} end",
            &data(),
        );
        assert_eq!(out, "Hello Ann\n[__badfunc .x__] end");
        // Unparseable even after cleaning: the content is sent as is.
        assert_eq!(render("{{if}}", &data()), "[__if__]");
        assert_eq!(
            render("{{.Subscriber.first_name", &data()),
            "{{.Subscriber.first_name"
        );
    }

    #[test]
    fn signals() {
        assert_eq!(
            signals_to_copy("owner_email,nope"),
            ["being hands-on with the business"]
        );
        assert!(signals_to_copy("").is_empty());
    }
}
