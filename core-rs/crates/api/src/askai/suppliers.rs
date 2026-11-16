//! AI providers and their models (Go: `askai/supplier.go`), in
//! `conf/supplier/<name>/{config.json,models.json}`; the built-in ones are
//! copied from `conf/supplier/template/` when missing.
//!
//! Differences from Go: provider names are checked before they become
//! folder names (Go's `../..` reached and deleted any folder); files
//! holding API keys are owner-only (Go: 0777) and keys are masked in
//! answers; edits are serialized, so two at once no longer lose one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferropost_domain::askai::{
    self as rules, DEFAULT_MAX_TOKENS, ModelInfo, Supplier, TEMPLATE_DIR,
};
use serde::Deserialize;

use crate::state::AppState;

static WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const FILES: [&str; 3] = ["config.json", "models.json", "embedding.json"];

/// `conf/supplier`.
pub fn root(state: &AppState) -> PathBuf {
    state.config.conf_dir.join("supplier")
}

fn folder(state: &AppState, name: &str) -> Result<PathBuf> {
    if !rules::is_supplier_name(name) {
        bail!("invalid supplier name");
    }
    Ok(root(state).join(name))
}

/// Copies the built-in providers' files that are missing (Go's
/// `SyncTemplateToConfig`).
fn sync_templates(root: &Path) {
    let Ok(templates) = std::fs::read_dir(root.join(TEMPLATE_DIR)) else {
        return;
    };
    for template in templates.flatten() {
        let name = template.file_name().to_string_lossy().into_owned();
        if !rules::is_supplier_name(&name) || !template.path().is_dir() {
            continue;
        }
        for file in FILES {
            let target = root.join(&name).join(file);
            if target.exists() {
                continue;
            }
            if let Ok(content) = std::fs::read(template.path().join(file))
                && let Err(err) = crate::askai::write_private(&target, &content)
            {
                tracing::warn!(supplier = %name, %err, "AI provider template not copied");
            }
        }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// A provider's stored configuration (key included).
pub fn config(state: &AppState, name: &str) -> Option<Supplier> {
    let dir = folder(state, name).ok()?;
    read_json(&dir.join("config.json"))
}

fn save_config(state: &AppState, name: &str, supplier: &Supplier) -> Result<()> {
    let dir = folder(state, name)?;
    let json = serde_json::to_vec_pretty(supplier)?;
    crate::askai::write_private(&dir.join("config.json"), &json)
        .with_context(|| format!("write {name}'s configuration"))
}

/// Every provider, by their sort order (Go's `List`), keys masked. `None`
/// when there is no provider folder at all.
pub fn list(state: &AppState) -> Option<Vec<Supplier>> {
    let root = root(state);
    sync_templates(&root);
    let entries = std::fs::read_dir(&root).ok()?;
    let mut suppliers: Vec<Supplier> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            rules::is_supplier_name(&name)
                .then(|| read_json::<Supplier>(&e.path().join("config.json")))
                .flatten()
        })
        .map(Supplier::shown)
        .collect();
    suppliers.sort_by(|a, b| {
        a.sort
            .cmp(&b.sort)
            .then(a.supplier_name.cmp(&b.supplier_name))
    });
    Some(suppliers)
}

/// `models.json` as stored.
fn raw_models(state: &AppState, name: &str) -> Vec<ModelInfo> {
    folder(state, name)
        .ok()
        .and_then(|dir| read_json(&dir.join("models.json")))
        .unwrap_or_default()
}

/// A provider's models as shown (Go's `GetModelList`): every one off while
/// the provider is. Edits work on the stored list, so switching a model
/// while its provider is off no longer saves every model as off (Go saved
/// the shown list).
pub fn model_list(state: &AppState, name: &str) -> Vec<ModelInfo> {
    let mut models = raw_models(state, name);
    let active = config(state, name).is_some_and(|s| s.is_active());
    rules::normalize_models(name, &mut models, active);
    models
}

/// A model of a provider, if listed.
pub fn model(state: &AppState, supplier: &str, model_id: &str) -> Option<ModelInfo> {
    model_list(state, supplier)
        .into_iter()
        .find(|m| m.model_id == model_id)
}

fn save_models(state: &AppState, name: &str, models: &[ModelInfo]) -> Result<()> {
    let dir = folder(state, name)?;
    let json = serde_json::to_vec_pretty(models)?;
    crate::askai::write_private(&dir.join("models.json"), &json)
        .with_context(|| format!("write {name}'s models"))
}

fn client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(timeout).build()?)
}

#[derive(Deserialize)]
struct ModelsResponse {
    #[serde(default)]
    data: Vec<RemoteModel>,
}

#[derive(Deserialize)]
struct RemoteModel {
    id: String,
}

/// Lists the provider's models from its API into `models.json` (Go's
/// `GetCloudModels`). Returns how many were added.
pub async fn fetch_models(state: &AppState, name: &str) -> Result<usize> {
    let supplier = config(state, name).context("supplier configuration not found")?;
    if supplier.api_key.is_empty() || supplier.base_url.is_empty() {
        return Ok(0);
    }
    let response = client(Duration::from_secs(15))?
        .get(rules::endpoint(&supplier.base_url, "models"))
        .bearer_auth(&supplier.api_key)
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("listing models failed: {}", response.status());
    }
    let listed: ModelsResponse = serde_json::from_slice(&response.bytes().await?)?;
    let _writes = WRITES.lock().await;
    let mut models = raw_models(state, name);
    let mut added = 0;
    for remote in listed.data {
        if !rules::is_model_id(&remote.id) || models.iter().any(|m| m.model_id == remote.id) {
            continue;
        }
        models.push(ModelInfo {
            title: String::new(),
            supplier_name: name.to_owned(),
            model_id: remote.id,
            max_tokens: DEFAULT_MAX_TOKENS,
            capability: vec!["llm".to_owned()],
            status: true,
        });
        added += 1;
    }
    if added > 0 {
        save_models(state, name, &models)?;
    }
    Ok(added)
}

/// Go's `Models`: one provider's models (asking its API when it has none
/// yet), or every usable model of every provider.
pub async fn models(state: &AppState, name: Option<&str>) -> Vec<ModelInfo> {
    match name {
        Some(name) => {
            let models = model_list(state, name);
            if !models.is_empty() {
                return models;
            }
            if let Err(err) = fetch_models(state, name).await {
                tracing::info!(supplier = %name, error = %format!("{err:#}"), "models not listed");
            }
            model_list(state, name)
        }
        None => {
            sync_templates(&root(state));
            let Ok(entries) = std::fs::read_dir(root(state)) else {
                return Vec::new();
            };
            let mut names: Vec<String> = entries
                .flatten()
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| rules::is_supplier_name(n))
                .collect();
            names.sort();
            names
                .iter()
                .flat_map(|n| model_list(state, n))
                .filter(|m| m.status)
                .collect()
        }
    }
}

/// Whether any model can be used (Go's `Status`).
pub async fn is_configured(state: &AppState) -> bool {
    !models(state, None).await.is_empty()
}

/// Checks an address and key against the provider (Go's `Testing`).
pub async fn test(base_url: &str, api_key: &str) -> Result<()> {
    if !rules::is_base_url(base_url) {
        bail!("base URL must use http or https protocol");
    }
    client(Duration::from_secs(3))?
        .head(base_url)
        .send()
        .await
        .map_err(|e| anyhow!("base URL accessibility test failed: {e}"))?;
    let response = client(Duration::from_secs(15))?
        .get(rules::endpoint(base_url, "models"))
        .bearer_auth(api_key)
        .send()
        .await
        .map_err(|e| anyhow!("API key validation failed: {e}"))?;
    match response.status() {
        s if s.is_success() || s == reqwest::StatusCode::NOT_FOUND => Ok(()),
        reqwest::StatusCode::UNAUTHORIZED => bail!("API key validation failed: invalid API key"),
        s => bail!(
            "API key validation failed: unexpected API response: {} {}",
            s.as_u16(),
            s.canonical_reason().unwrap_or_default()
        ),
    }
}

/// Edits one model; `false` when it is not listed.
async fn edit_model(
    state: &AppState,
    supplier: &str,
    model_id: &str,
    edit: impl FnOnce(&mut ModelInfo),
) -> Result<bool> {
    let _writes = WRITES.lock().await;
    let mut models = raw_models(state, supplier);
    let Some(model) = models.iter_mut().find(|m| m.model_id == model_id) else {
        return Ok(false);
    };
    edit(model);
    save_models(state, supplier, &models)?;
    Ok(true)
}

pub async fn add_model(state: &AppState, model: ModelInfo) -> Result<()> {
    let supplier = model.supplier_name.clone();
    config(state, &supplier).context("supplier configuration not found")?;
    let _writes = WRITES.lock().await;
    let mut models = raw_models(state, &supplier);
    match models.iter_mut().find(|m| m.model_id == model.model_id) {
        Some(existing) => *existing = model,
        None => models.push(model),
    }
    save_models(state, &supplier, &models)
}

pub async fn remove_model(state: &AppState, supplier: &str, model_id: &str) -> Result<bool> {
    let _writes = WRITES.lock().await;
    let mut models = raw_models(state, supplier);
    let before = models.len();
    models.retain(|m| m.model_id != model_id);
    if models.len() == before {
        return Ok(false);
    }
    save_models(state, supplier, &models)?;
    Ok(true)
}

pub async fn set_model_status(
    state: &AppState,
    supplier: &str,
    model_id: &str,
    status: bool,
) -> Result<bool> {
    edit_model(state, supplier, model_id, |m| m.status = status).await
}

pub async fn set_model_title(
    state: &AppState,
    supplier: &str,
    model_id: &str,
    title: &str,
) -> Result<bool> {
    edit_model(state, supplier, model_id, |m| m.title = title.to_owned()).await
}

pub async fn set_model_capability(
    state: &AppState,
    supplier: &str,
    model_id: &str,
    capability: Vec<String>,
) -> Result<bool> {
    edit_model(state, supplier, model_id, |m| m.capability = capability).await
}

pub async fn modify_model(
    state: &AppState,
    supplier: &str,
    model_id: &str,
    title: &str,
    max_tokens: i64,
    capability: Vec<String>,
) -> Result<bool> {
    edit_model(state, supplier, model_id, |m| {
        m.title = title.to_owned();
        m.max_tokens = max_tokens;
        m.capability = capability;
    })
    .await
}

/// Sets a provider's address and key (the mask sent back keeps the key).
pub async fn set_config(state: &AppState, name: &str, base_url: &str, api_key: &str) -> Result<()> {
    let _writes = WRITES.lock().await;
    let mut supplier = config(state, name).context("supplier configuration not found")?;
    supplier.api_key = rules::resolve_key(api_key, &supplier.api_key);
    supplier.base_url = base_url.to_owned();
    save_config(state, name, &supplier)
}

pub async fn set_status(state: &AppState, name: &str, status: bool) -> Result<()> {
    let _writes = WRITES.lock().await;
    let mut supplier = config(state, name).context("supplier configuration not found")?;
    if supplier.api_key.is_empty() || supplier.base_url.is_empty() {
        bail!("supplier configuration is incomplete, cannot set status");
    }
    supplier.status = status;
    save_config(state, name, &supplier)
}

pub async fn add_supplier(
    state: &AppState,
    title: &str,
    name: &str,
    base_url: &str,
    api_key: &str,
) -> Result<()> {
    let _writes = WRITES.lock().await;
    let dir = folder(state, name)?;
    if dir.exists() {
        bail!("supplier already exists");
    }
    save_config(
        state,
        name,
        &Supplier {
            supplier_title: title.to_owned(),
            supplier_name: name.to_owned(),
            base_url: base_url.to_owned(),
            base_url_example: base_url.to_owned(),
            is_use_url_example: false,
            api_key: api_key.to_owned(),
            status: true,
            sort: 100,
            ..Supplier::default()
        },
    )
}

pub async fn remove_supplier(state: &AppState, name: &str) -> Result<()> {
    let _writes = WRITES.lock().await;
    let dir = folder(state, name)?;
    if !dir.is_dir() {
        bail!("supplier does not exist");
    }
    if root(state).join(TEMPLATE_DIR).join(name).exists() {
        bail!("Cannot delete the system's built-in model supplier.");
    }
    std::fs::remove_dir_all(&dir).with_context(|| format!("remove {name}"))
}
