//! Brand projects (Go: `askai/project.go`): what AskAI knows of a domain's
//! brand, in Go's files under `conf/askai/<domain>/`.
//!
//! Differences from Go: reading a setting no longer writes its default
//! file (and fails when the project folder is missing); ids and domains are
//! checked before they become file names (Go's `../` reached any `.json`
//! file); edits are serialized.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ferropost_domain::askai::{
    CompanyProfile, FooterConfig, ImageInfo, KnowledgeInfo, ProjectConfig, PromptConfig,
    SitemapNode, StyleConfig, is_item_id,
};
use ferropost_domain::domains::is_domain_name;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::state::AppState;

static WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub const PROJECT: &str = "project.json";
pub const COMPANY: &str = "company_profile.json";
pub const STYLE: &str = "style_config.json";
pub const SITEMAP: &str = "sitemap.json";
pub const FOOTER: &str = "footer_config.json";
pub const PROMPT: &str = "prompt_config.json";
pub const IMAGES: &str = "images.json";

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// `conf/askai`.
pub fn root(state: &AppState) -> PathBuf {
    state.config.conf_dir.join("askai")
}

/// A project's folder.
pub fn folder(state: &AppState, domain: &str) -> Result<PathBuf> {
    if !is_domain_name(domain) {
        bail!("invalid domain");
    }
    Ok(root(state).join(domain))
}

fn read<T: DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let json = serde_json::to_vec_pretty(value)?;
    crate::fsio::write_atomic(path, &json, 0o644)
        .with_context(|| format!("write {}", path.display()))
}

/// A setting file, or its default when there is none yet.
pub fn get<T: DeserializeOwned + Default>(state: &AppState, domain: &str, file: &str) -> Result<T> {
    Ok(read(&folder(state, domain)?.join(file)).unwrap_or_default())
}

/// Changes a setting file (its default when missing) and saves it.
pub async fn update<T, R>(
    state: &AppState,
    domain: &str,
    file: &str,
    change: impl FnOnce(&mut T) -> R,
) -> Result<R>
where
    T: DeserializeOwned + Default + Serialize,
{
    let path = folder(state, domain)?.join(file);
    let _writes = WRITES.lock().await;
    let mut value: T = read(&path).unwrap_or_default();
    let result = change(&mut value);
    write(&path, &value)?;
    Ok(result)
}

/// The project, if one was created.
pub fn project(state: &AppState, domain: &str) -> Option<ProjectConfig> {
    read(&folder(state, domain).ok()?.join(PROJECT))
}

/// Creates (or starts again) a domain's project: the brand site is read
/// again (Go's `Create`).
pub async fn create(state: &AppState, domain: &str, urls: Vec<String>) -> Result<()> {
    let path = folder(state, domain)?.join(PROJECT);
    let _writes = WRITES.lock().await;
    write(
        &path,
        &ProjectConfig {
            domain: domain.to_owned(),
            urls,
            status: true,
            ..ProjectConfig::default()
        },
    )
}

/// Edits the project; `false` when there is none.
pub async fn edit_project(
    state: &AppState,
    domain: &str,
    change: impl FnOnce(&mut ProjectConfig),
) -> Result<bool> {
    let path = folder(state, domain)?.join(PROJECT);
    let _writes = WRITES.lock().await;
    let Some(mut project) = read::<ProjectConfig>(&path) else {
        return Ok(false);
    };
    change(&mut project);
    write(&path, &project)?;
    Ok(true)
}

/// Domains that have a project.
pub fn domains(state: &AppState) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root(state)) else {
        return Vec::new();
    };
    let mut domains: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|d| is_domain_name(d) && root(state).join(d).join(PROJECT).exists())
        .collect();
    domains.sort();
    domains
}

fn knowledge_dir(state: &AppState, domain: &str) -> Result<PathBuf> {
    Ok(folder(state, domain)?.join("knowledge"))
}

fn knowledge_path(state: &AppState, domain: &str, kid: &str) -> Result<PathBuf> {
    if !is_item_id(kid) {
        bail!("invalid knowledge base file id");
    }
    Ok(knowledge_dir(state, domain)?.join(format!("{kid}.json")))
}

/// The knowledge base, oldest first.
pub fn knowledge(state: &AppState, domain: &str) -> Vec<KnowledgeInfo> {
    let Ok(dir) = knowledge_dir(state, domain) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut docs: Vec<KnowledgeInfo> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| read(&e.path()))
        .collect();
    docs.sort_by(|a, b| a.update_time.cmp(&b.update_time).then(a.kid.cmp(&b.kid)));
    docs
}

/// Saves a knowledge base document (a new id when none is given).
pub async fn save_knowledge(
    state: &AppState,
    domain: &str,
    kid: Option<&str>,
    title: &str,
    content: &str,
) -> Result<String> {
    let kid = kid
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    let path = knowledge_path(state, domain, &kid)?;
    let _writes = WRITES.lock().await;
    write(
        &path,
        &KnowledgeInfo {
            kid: kid.clone(),
            title: title.to_owned(),
            content: content.to_owned(),
            update_time: now(),
        },
    )?;
    Ok(kid)
}

/// Edits a document; `false` when there is none.
pub async fn modify_knowledge(
    state: &AppState,
    domain: &str,
    kid: &str,
    title: &str,
    content: &str,
) -> Result<bool> {
    let path = knowledge_path(state, domain, kid)?;
    let _writes = WRITES.lock().await;
    let Some(mut doc) = read::<KnowledgeInfo>(&path) else {
        return Ok(false);
    };
    doc.title = title.to_owned();
    doc.content = content.to_owned();
    doc.update_time = now();
    write(&path, &doc)?;
    Ok(true)
}

pub async fn remove_knowledge(state: &AppState, domain: &str, kid: &str) -> Result<bool> {
    let path = knowledge_path(state, domain, kid)?;
    let _writes = WRITES.lock().await;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).context("remove knowledge base file"),
    }
}

pub fn company(state: &AppState, domain: &str) -> Result<CompanyProfile> {
    get(state, domain, COMPANY)
}

pub fn style(state: &AppState, domain: &str) -> Result<StyleConfig> {
    get(state, domain, STYLE)
}

pub fn sitemap(state: &AppState, domain: &str) -> Result<Vec<SitemapNode>> {
    get(state, domain, SITEMAP)
}

pub fn footer(state: &AppState, domain: &str) -> Result<FooterConfig> {
    get(state, domain, FOOTER)
}

pub fn prompt(state: &AppState, domain: &str) -> Result<PromptConfig> {
    get(state, domain, PROMPT)
}

pub fn images(state: &AppState, domain: &str) -> Result<Vec<ImageInfo>> {
    get(state, domain, IMAGES)
}
