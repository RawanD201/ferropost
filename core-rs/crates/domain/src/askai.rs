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
