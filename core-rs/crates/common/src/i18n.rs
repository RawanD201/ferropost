//! Server-side message translation.
//!
//! Compatible with the Go language packs: `languages/<lang>/server.json` maps
//! the MD5 hex digest of an English message to its translation, and `{}`
//! placeholders are filled in order.

use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use md5::{Digest, Md5};

pub const DEFAULT_LANGUAGE: &str = "en";

type Pack = Arc<HashMap<String, String>>;

#[derive(Debug)]
pub struct Translator {
    dir: PathBuf,
    packs: RwLock<HashMap<String, Pack>>,
}

impl Translator {
    /// `dir` is the `languages` directory of the core.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            packs: RwLock::new(HashMap::new()),
        }
    }

    /// Translates `msg` into `lang`, falling back to `msg` itself.
    pub fn tr(&self, lang: &str, msg: &str, args: &[&dyn Display]) -> String {
        let key = hex::encode(Md5::digest(msg.as_bytes()));
        let translated = self.pack(lang).and_then(|pack| pack.get(&key).cloned());
        fill(translated.as_deref().unwrap_or(msg), args)
    }

    /// True when a language pack exists for `lang`.
    pub fn supports(&self, lang: &str) -> bool {
        is_language_code(lang) && self.dir.join(lang).join("server.json").is_file()
    }

    fn pack(&self, lang: &str) -> Option<Pack> {
        if !is_language_code(lang) {
            return None;
        }
        if let Some(pack) = self
            .packs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(lang)
        {
            return Some(pack.clone());
        }

        let path = self.dir.join(lang).join("server.json");
        let pack: Pack = match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|raw| serde_json::from_str(&raw).map_err(|e| e.to_string()))
        {
            Ok(map) => Arc::new(map),
            Err(err) => {
                tracing::debug!(path = %path.display(), %err, "language pack unavailable");
                Arc::new(HashMap::new())
            }
        };
        self.packs
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lang.to_owned(), pack.clone());
        Some(pack)
    }
}

/// Language codes are short lowercase ASCII words (`en`, `zh`, `ja`). This
/// also prevents path traversal through the `lang` query parameter.
pub fn is_language_code(lang: &str) -> bool {
    (2..=8).contains(&lang.len()) && lang.bytes().all(|b| b.is_ascii_lowercase())
}

/// Normalises user input such as `zh-CN` or `EN` to a language code.
pub fn normalize_language(raw: &str) -> Option<String> {
    let code = raw
        .trim()
        .split(['-', '_', ',', ';'])
        .next()?
        .to_ascii_lowercase();
    is_language_code(&code).then_some(code)
}

fn fill(template: &str, args: &[&dyn Display]) -> String {
    let mut out = template.to_owned();
    for arg in args {
        if let Some(pos) = out.find("{}") {
            out.replace_range(pos..pos + 2, &arg.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translator_with(lang: &str, entries: &[(&str, &str)]) -> (tempfile::TempDir, Translator) {
        let dir = tempfile::tempdir().expect("tempdir");
        let pack: HashMap<String, String> = entries
            .iter()
            .map(|(msg, tr)| (hex::encode(Md5::digest(msg.as_bytes())), (*tr).to_owned()))
            .collect();
        std::fs::create_dir_all(dir.path().join(lang)).expect("mkdir");
        std::fs::write(
            dir.path().join(lang).join("server.json"),
            serde_json::to_string(&pack).expect("json"),
        )
        .expect("write");
        let translator = Translator::new(dir.path());
        (dir, translator)
    }

    #[test]
    fn translates_by_md5_and_fills_args() {
        let (_dir, tr) = translator_with("zh", &[("Update failed: {}", "更新失败：{}")]);
        assert_eq!(
            tr.tr("zh", "Update failed: {}", &[&"timeout"]),
            "更新失败：timeout"
        );
        assert_eq!(tr.tr("zh", "Untranslated", &[]), "Untranslated");
        assert_eq!(
            tr.tr("ja", "Update failed: {}", &[&42]),
            "Update failed: 42"
        );
        assert!(tr.supports("zh"));
        assert!(!tr.supports("ja"));
    }

    #[test]
    fn rejects_unsafe_language_codes() {
        let (_dir, tr) = translator_with("en", &[]);
        assert_eq!(tr.tr("../../etc", "x", &[]), "x");
        assert!(!tr.supports("../en"));
    }

    #[test]
    fn normalises_language_input() {
        assert_eq!(normalize_language("zh-CN").as_deref(), Some("zh"));
        assert_eq!(normalize_language("EN").as_deref(), Some("en"));
        assert_eq!(normalize_language("ja,en;q=0.8").as_deref(), Some("ja"));
        assert_eq!(normalize_language("../x"), None);
        assert_eq!(normalize_language(""), None);
    }

    #[test]
    fn fill_extra_args_are_ignored() {
        assert_eq!(fill("a {} b", &[&1, &2]), "a 1 b");
        assert_eq!(fill("no slots", &[&1]), "no slots");
    }
}
