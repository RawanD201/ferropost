//! AskAI (Go: `service/askai`): AI model providers ("suppliers") and their
//! models, kept as JSON files in `conf/supplier/<name>/` as Go kept them.

use serde::{Deserialize, Serialize};

/// The name of the folder holding the built-in providers' templates.
pub const TEMPLATE_DIR: &str = "template";
/// Output budget of a model whose file gives none (Go's).
pub const DEFAULT_MAX_TOKENS: i64 = 8192;
/// Shown instead of a stored API key; sending it back keeps the key.
const MASK: &str = "••••••••";

/// A provider's `config.json` (Go's `Supplier`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Supplier {
    pub supplier_title: String,
    pub supplier_name: String,
    pub base_url: String,
    pub base_url_example: String,
    pub is_use_url_example: bool,
    pub api_key: String,
    pub home: String,
    pub help: String,
    pub status: bool,
    pub sort: i64,
    pub icon: String,
}

impl Supplier {
    /// Whether it can be used: switched on, with an address and a key.
    pub fn is_active(&self) -> bool {
        self.status && !self.base_url.is_empty() && !self.api_key.is_empty()
    }

    /// As shown to the console: the key masked.
    pub fn shown(mut self) -> Self {
        self.api_key = mask_key(&self.api_key);
        if self.base_url.is_empty() || self.api_key.is_empty() {
            self.status = false;
        }
        self
    }
}

/// One entry of a provider's `models.json` (Go's `ModelInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelInfo {
    pub title: String,
    #[serde(rename = "supplierName")]
    pub supplier_name: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    pub max_tokens: i64,
    pub capability: Vec<String>,
    pub status: bool,
}

/// Go's reading of `models.json`: a default title and budget, and every
/// model off while its provider is.
pub fn normalize_models(supplier: &str, models: &mut [ModelInfo], active: bool) {
    for model in models {
        if model.title.is_empty() {
            model.title = format!("{supplier}/{}", model.model_id);
        }
        if model.max_tokens <= 0 {
            model.max_tokens = DEFAULT_MAX_TOKENS;
        }
        if model.supplier_name.is_empty() {
            model.supplier_name = supplier.to_owned();
        }
        if !active {
            model.status = false;
        }
    }
}

/// A provider name usable as a folder name. Go joined it into paths as
/// given, so `../..` reached any folder, and removing a provider deleted
/// it.
pub fn is_supplier_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != TEMPLATE_DIR
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A model id as providers name them (`gpt-4o`, `models/gemini-2.5-pro`,
/// `accounts/x/models/y`).
pub fn is_model_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 200 && !id.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// A capability name (`llm`, `vision`, `tools`, `text-to-image`, ...).
pub fn is_capability(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An `http`/`https` address of an OpenAI-compatible API.
pub fn is_base_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    rest.is_some_and(|r| !r.is_empty() && !r.starts_with('/'))
        && url.len() <= 2048
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// `<base>/<path>` without a doubled slash (Go appended `/models` to
/// addresses ending in `/`).
pub fn endpoint(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

/// What the console sees of a key: its start and end only.
pub fn mask_key(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = key.chars().collect();
    if chars.len() < 12 {
        return MASK.to_owned();
    }
    let start: String = chars[..3].iter().collect();
    let end: String = chars[chars.len() - 4..].iter().collect();
    format!("{start}{MASK}{end}")
}

/// The key to use for a request: the stored one when the console sent its
/// mask back.
pub fn resolve_key(sent: &str, stored: &str) -> String {
    let sent = sent.trim();
    if !stored.is_empty() && sent == mask_key(stored) {
        stored.to_owned()
    } else {
        sent.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_urls() {
        assert!(is_supplier_name("OpenAI"));
        assert!(is_supplier_name("my-llm_2.local"));
        for bad in ["", "..", "../etc", "a/b", ".hidden", "template", "a b"] {
            assert!(!is_supplier_name(bad), "{bad}");
        }
        assert!(is_model_id("models/gemini-2.5-pro"));
        assert!(!is_model_id("bad id"));
        assert!(is_capability("text-to-image"));
        assert!(!is_capability("LLM"));
        assert!(is_base_url("http://127.0.0.1:11434/v1"));
        assert!(is_base_url("https://api.openai.com/v1"));
        assert!(!is_base_url("ftp://x"));
        assert!(!is_base_url("https:///x"));
        assert_eq!(
            endpoint("https://api.anthropic.com/v1/", "/models"),
            "https://api.anthropic.com/v1/models"
        );
    }

    #[test]
    fn keys_are_masked_and_kept() {
        let key = "sk-proj-abcdefghijklmnop";
        let shown = mask_key(key);
        assert!(shown.starts_with("sk-") && shown.ends_with("mnop") && !shown.contains("abcdef"));
        assert_eq!(
            resolve_key(&shown, key),
            key,
            "the mask sent back keeps the key"
        );
        assert_eq!(
            resolve_key("sk-new-key-0000000000", key),
            "sk-new-key-0000000000"
        );
        assert_eq!(mask_key("short"), MASK);
        assert_eq!(resolve_key(MASK, "short"), "short");
        assert_eq!(mask_key(""), "");
        let supplier = Supplier {
            api_key: key.to_owned(),
            base_url: String::new(),
            status: true,
            ..Supplier::default()
        };
        let shown = supplier.shown();
        assert!(!shown.status, "no address: off, as in Go");
        assert_ne!(shown.api_key, key);
        let json = serde_json::to_value(&shown).expect("json");
        assert!(json.get("supplierTitle").is_some() && json.get("isUseUrlExample").is_some());
    }

    #[test]
    fn models() {
        let mut models: Vec<ModelInfo> =
            serde_json::from_str(r#"[{"modelId":"gpt-4o","status":true,"capability":["llm"]}]"#)
                .expect("json");
        normalize_models("OpenAI", &mut models, false);
        assert_eq!(models[0].title, "OpenAI/gpt-4o");
        assert_eq!(models[0].max_tokens, DEFAULT_MAX_TOKENS);
        assert_eq!(models[0].supplier_name, "OpenAI");
        assert!(!models[0].status, "off while the provider is");
        let json = serde_json::to_value(&models[0]).expect("json");
        assert_eq!(json["modelId"], "gpt-4o");
        assert_eq!(json["max_tokens"], 8192);
    }
}

/// A brand project's `project.json` (Go's `ProjectConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub domain: String,
    pub urls: Vec<String>,
    pub project_name: String,
    pub description: String,
    pub industry: String,
    pub primary_logo: String,
    pub secondary_logo: String,
    pub favicon: String,
    pub knowledge_base: Vec<KnowledgeInfo>,
    pub status: bool,
    pub update_time: i64,
}

/// A knowledge base document (Go's `KnowledgeInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KnowledgeInfo {
    pub kid: String,
    pub title: String,
    pub content: String,
    pub update_time: i64,
}

/// Go's `CompanyProfile`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CompanyProfile {
    pub legal_company_name: String,
    pub web_site: String,
    pub company_profile: String,
    pub email: String,
    pub phone: String,
    pub support_url: String,
    pub update_time: i64,
}

/// Go's `StyleConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StyleConfig {
    pub accent_color: String,
    pub text_color: String,
    pub page_background: String,
    pub container_background: String,
    pub link_social_color: String,
    pub link_footer_color: String,
    pub heading_font: String,
    pub body_font: String,
    pub update_time: i64,
}

impl Default for StyleConfig {
    /// Go's defaults.
    fn default() -> Self {
        Self {
            accent_color: "#007bff".to_owned(),
            text_color: "#000000".to_owned(),
            page_background: "#ffffff".to_owned(),
            container_background: "#f8f9fa".to_owned(),
            link_social_color: "#007bff".to_owned(),
            link_footer_color: "#6c757d".to_owned(),
            heading_font: "Arial, sans-serif".to_owned(),
            body_font: "Arial, sans-serif".to_owned(),
            update_time: 0,
        }
    }
}

/// One page of a brand's site (Go's `SiteMap`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SitemapNode {
    pub title: String,
    pub uri_path: String,
    pub update_time: i64,
}

/// Go's `FooterConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FooterConfig {
    pub copyright_text: String,
    pub disclaimer: String,
    pub text: String,
    pub update_time: i64,
}

impl Default for FooterConfig {
    /// Go's defaults.
    fn default() -> Self {
        Self {
            copyright_text: "© 2023 Your Company. All rights reserved.".to_owned(),
            disclaimer: "This is a sample disclaimer.".to_owned(),
            text: String::new(),
            update_time: 0,
        }
    }
}

/// Go's `PromptConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PromptConfig {
    pub prompt: String,
    pub update_time: i64,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            prompt: "This is a default prompt. Please customize it.".to_owned(),
            update_time: 0,
        }
    }
}

/// A brand image (Go's `ImageInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageInfo {
    pub image_id: String,
    pub image_url: String,
    pub filename: String,
    pub alt_text: String,
    pub image_tag: String,
    pub update_time: i64,
    pub size: String,
}

/// Brand URLs a project may have (Go's limit).
pub const MAX_PROJECT_URLS: usize = 3;

/// An id this module made (UUIDs) or Go did, safe as a file name.
pub fn is_item_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A CSS colour as the style settings take it (`#rgb`, `#rrggbb`,
/// `#rrggbbaa`).
pub fn is_color(value: &str) -> bool {
    value.strip_prefix('#').is_some_and(|hex| {
        matches!(hex.len(), 3 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// A project's brand URLs: `http://` added where no scheme is given (as
/// Go did), at most three.
pub fn project_urls(domain: &str, urls: &[String]) -> Result<Vec<String>, String> {
    let mut cleaned: Vec<String> = Vec::new();
    for url in urls {
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        let url = if url.to_ascii_lowercase().starts_with("http") {
            url.to_owned()
        } else {
            format!("http://{url}")
        };
        if !is_base_url(&url) {
            return Err(format!("`{url}` is not an http or https link"));
        }
        if !cleaned.contains(&url) {
            cleaned.push(url);
        }
    }
    if cleaned.len() > MAX_PROJECT_URLS {
        return Err("Add up to 3 URLs".to_owned());
    }
    if cleaned.is_empty() {
        cleaned.push(format!("http://{domain}"));
    }
    Ok(cleaned)
}

/// Whether an address is public (not loopback, private, link-local,
/// shared, reserved or documentation space). The containers' own network
/// (`IPV4_NETWORK`, `172.66.0.0/16` by default) is public space and must be
/// refused separately.
pub fn is_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || first == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;

    #[test]
    fn project_rules() {
        assert!(is_item_id("0190f2c4-7d9c-7c3e-9a3f-1c2d3e4f5a6b"));
        assert!(!is_item_id("../x"));
        assert!(is_color("#fff") && is_color("#0a0B0c") && !is_color("red") && !is_color("#12345"));
        assert_eq!(
            project_urls("ex.test", &[]).expect("urls"),
            ["http://ex.test"],
            "Go's default"
        );
        assert_eq!(
            project_urls(
                "ex.test",
                &["ex.test/about".to_owned(), "https://ex.test".to_owned()]
            )
            .expect("urls"),
            ["http://ex.test/about", "https://ex.test"]
        );
        let four: Vec<String> = (0..4).map(|i| format!("https://{i}.test")).collect();
        assert_eq!(
            project_urls("ex.test", &four),
            Err("Add up to 3 URLs".to_owned())
        );
        let json = serde_json::to_value(StyleConfig::default()).expect("json");
        assert_eq!(json["accent_color"], "#007bff");
    }

    #[test]
    fn public_addresses() {
        let public = |s: &str| is_public_ip(s.parse().expect("ip"));
        for ip in ["93.184.216.34", "2606:4700::1111", "1.1.1.1"] {
            assert!(public(ip), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "198.18.0.1",
        ] {
            assert!(!public(ip), "{ip}");
        }
    }
}

/// A chat's `config.json` (Go's `TempChat`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TempChat {
    #[serde(rename = "chatId")]
    pub chat_id: String,
    pub domain: String,
    pub add_type: i64,
    pub temp_name: String,
    pub html_content: String,
    pub drag_data: String,
    pub create_time: i64,
    pub update_time: i64,
}

/// Go's `ChatUsage`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChatUsage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

/// One message of `message.json` (Go's `Message`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChatMessage {
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "chatId")]
    pub chat_id: String,
    pub ppid: String,
    pub content: String,
    pub html_content: String,
    pub role: String,
    pub create_time: i64,
    pub end_time: i64,
    pub reasoning: String,
    pub supplier_name: String,
    pub model_id: String,
    pub finish_reason: String,
    pub usage: ChatUsage,
    pub time_consuming: i64,
}

/// Go's `File` (never filled in).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChatFile {
    pub fid: String,
    pub content: String,
    pub title: String,
    pub size: i64,
    pub update_time: i64,
}

/// A chat's `info.json` (Go's `ChatInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChatInfo {
    #[serde(rename = "chatId")]
    pub chat_id: String,
    pub domain: String,
    pub prompt: String,
    pub title: String,
    #[serde(rename = "supplierName")]
    pub supplier_name: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    pub messages: Vec<ChatMessage>,
    pub files: Vec<ChatFile>,
    pub create_time: i64,
    pub update_time: i64,
}

/// The HTML document in a model's answer: its ```` ```html ```` block, or
/// the text from `<!DOCTYPE html>` to the last `</html>`.
pub fn extract_html(answer: &str) -> Option<String> {
    let lower = answer.to_ascii_lowercase();
    if let Some(start) = lower.find("```html") {
        let body = &answer[start + 7..];
        let end = body.find("```").unwrap_or(body.len());
        let html = body[..end].trim();
        if !html.is_empty() {
            return Some(html.to_owned());
        }
    }
    let start = lower.find("<!doctype html")?;
    let end = lower.rfind("</html>")? + "</html>".len();
    (end > start).then(|| answer[start..end].trim().to_owned())
}

/// Go's `DataToText` for one record: `Name: value` lines between
/// `<Title-START>` and `<Title-END>`, empty values and inline images
/// (`data:` URLs) left out. Empty when there is nothing to say.
pub fn reference_block(title: &str, records: &[Vec<(&str, String)>]) -> String {
    let mut lines = Vec::new();
    for (i, fields) in records.iter().enumerate() {
        let shown: Vec<String> = fields
            .iter()
            .filter(|(_, v)| !v.is_empty() && !v.starts_with("data:"))
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        if shown.is_empty() {
            continue;
        }
        if records.len() > 1 {
            lines.push(format!("[{}]:", i + 1));
        }
        lines.extend(shown);
    }
    if lines.is_empty() {
        return String::new();
    }
    format!("<{title}-START>\n{}\n<{title}-END>\n", lines.join("\n"))
}

#[cfg(test)]
mod chat_tests {
    use super::*;

    #[test]
    fn html_and_references() {
        let answer =
            "Here you go:\n```html\n<!DOCTYPE html>\n<html><body>Hi</body></html>\n```\nDone.";
        assert_eq!(
            extract_html(answer).as_deref(),
            Some("<!DOCTYPE html>\n<html><body>Hi</body></html>")
        );
        let bare = "x <!DOCTYPE html><html><b>a</b></html> y";
        assert_eq!(
            extract_html(bare).as_deref(),
            Some("<!DOCTYPE html><html><b>a</b></html>")
        );
        assert_eq!(extract_html("no html"), None);

        let block = reference_block(
            "Company Profile",
            &[vec![
                ("LegalCompanyName", "Acme".to_owned()),
                ("Phone", String::new()),
                ("Logo", "data:image/png;base64,AAAA".to_owned()),
            ]],
        );
        assert_eq!(
            block,
            "<Company Profile-START>\nLegalCompanyName: Acme\n<Company Profile-END>\n"
        );
        let many = reference_block(
            "Sitemap",
            &[
                vec![
                    ("Title", "About".to_owned()),
                    ("UriPath", "/about".to_owned()),
                ],
                vec![
                    ("Title", "Blog".to_owned()),
                    ("UriPath", "/blog".to_owned()),
                ],
            ],
        );
        assert!(many.contains("[1]:\nTitle: About\nUriPath: /about\n[2]:"));
        assert_eq!(reference_block("Images", &[]), "");
        let json = serde_json::to_value(ChatInfo::default()).expect("json");
        assert!(json.get("chatId").is_some() && json.get("supplierName").is_some());
    }
}
