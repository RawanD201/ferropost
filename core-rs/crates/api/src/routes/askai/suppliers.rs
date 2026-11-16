//! `/api/askai/supplier/*` (Go: `controller/askai`, suppliers): AI
//! providers and their models. See `crate::askai::suppliers`.
//!
//! Differences from Go: keys are masked in every answer (the console sends
//! the mask back to keep a key); removing a model reports success (Go
//! answered "Model not found" when it worked and success when it did not);
//! adding a model to an unknown provider fails instead of succeeding;
//! provider changes are in the audit log, without their keys.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::askai::{self as rules, ModelInfo, Supplier};
use ferropost_domain::audit::LogType;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::askai::suppliers;
use crate::audit::Audit;
use crate::body::{ApiBody, Input};
use crate::de::{opt_bool, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

const DEFAULT_CAPABILITY: [&str; 4] = ["llm", "vision", "tools", "text-to-image"];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/askai/supplier/list", get(list).post(list))
        .route("/api/askai/supplier/models", get(models).post(models))
        .route("/api/askai/supplier/status", get(status).post(status))
        .route("/api/askai/supplier/add_model", post(add_model))
        .route("/api/askai/supplier/remove_model", post(remove_model))
        .route(
            "/api/askai/supplier/set_supplier_config",
            post(set_supplier_config),
        )
        .route("/api/askai/supplier/testing", post(testing))
        .route(
            "/api/askai/supplier/get_supplier_config",
            post(get_supplier_config),
        )
        .route(
            "/api/askai/supplier/set_supplier_status",
            post(set_supplier_status),
        )
        .route(
            "/api/askai/supplier/set_model_status",
            post(set_model_status),
        )
        .route("/api/askai/supplier/add_supplier", post(add_supplier))
        .route("/api/askai/supplier/remove_supplier", post(remove_supplier))
        .route("/api/askai/supplier/set_model_title", post(set_model_title))
        .route(
            "/api/askai/supplier/set_model_capability",
            post(set_model_capability),
        )
        .route("/api/askai/supplier/modify_model", post(modify_model))
}

/// Every field these routes take, in Go's names and the console's
/// (GoFrame matched `supplierName` to `supplier_name`).
#[derive(Debug, Default, Deserialize)]
struct Body {
    #[serde(default, alias = "supplierName", deserialize_with = "opt_string")]
    supplier_name: Option<String>,
    #[serde(default, alias = "supplierTitle", deserialize_with = "opt_string")]
    supplier_title: Option<String>,
    #[serde(default, alias = "baseUrl", deserialize_with = "opt_string")]
    base_url: Option<String>,
    #[serde(default, alias = "apiKey", deserialize_with = "opt_string")]
    api_key: Option<String>,
    #[serde(default, alias = "modelId", deserialize_with = "opt_string")]
    model_id: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    title: Option<String>,
    #[serde(default, alias = "maxTokens", deserialize_with = "opt_i64")]
    max_tokens: Option<i64>,
    #[serde(default)]
    capability: Option<Vec<String>>,
    #[serde(default, deserialize_with = "opt_bool")]
    status: Option<bool>,
}

fn required<'a>(value: &'a Option<String>, message: &str) -> Result<&'a str, ApiError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::Validation(message.to_owned()))
}

fn supplier_name(body: &Body) -> Result<String, ApiError> {
    let name = required(&body.supplier_name, "supplier name is required")?;
    if !rules::is_supplier_name(name) {
        return Err(ApiError::Validation(
            "supplier name may only contain letters, digits, `.`, `-` and `_`".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

fn model_id(body: &Body) -> Result<String, ApiError> {
    let id = required(&body.model_id, "model id is required")?;
    if !rules::is_model_id(id) {
        return Err(ApiError::Validation("invalid model id".to_owned()));
    }
    Ok(id.to_owned())
}

fn base_url(body: &Body) -> Result<String, ApiError> {
    let url = required(&body.base_url, "base url is required")?;
    if !rules::is_base_url(url) {
        return Err(ApiError::Validation(
            "base URL must use http or https protocol".to_owned(),
        ));
    }
    Ok(url.to_owned())
}

fn max_tokens(body: &Body) -> Result<i64, ApiError> {
    match body.max_tokens {
        None => Err(ApiError::Validation("max tokens is required".to_owned())),
        Some(n) if n < 1 => Err(ApiError::Validation(
            "max tokens must be at least 1".to_owned(),
        )),
        Some(n) => Ok(n),
    }
}

/// The capabilities given, or Go's default list when `default` applies.
fn capability(body: &Body, default: bool) -> Result<Vec<String>, ApiError> {
    let list = match &body.capability {
        Some(list) if !list.is_empty() => list.clone(),
        _ if default => DEFAULT_CAPABILITY.iter().map(|c| (*c).to_owned()).collect(),
        _ => return Err(ApiError::Validation("capability is required".to_owned())),
    };
    let mut cleaned: Vec<String> = Vec::new();
    for item in list {
        let item = item.trim().to_ascii_lowercase();
        if !rules::is_capability(&item) {
            return Err(ApiError::Validation(format!("invalid capability `{item}`")));
        }
        if !cleaned.contains(&item) {
            cleaned.push(item);
        }
    }
    Ok(cleaned)
}

fn rejected(err: anyhow::Error) -> ApiError {
    ApiError::Rejected(format!("{err:#}"))
}

fn ok<T: serde::Serialize>(state: &AppState, lang: &str, msg: &str, data: T) -> ApiResponse<T> {
    ApiResponse::ok(state.i18n.tr(lang, msg, &[]), data)
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Vec<Supplier>>, ApiError> {
    let suppliers = suppliers::list(&state)
        .ok_or_else(|| ApiError::Rejected(state.i18n.tr(&lang, "Not suppliers found", &[])))?;
    Ok(ok(
        &state,
        &lang,
        "List of suppliers retrieved successfully",
        suppliers,
    ))
}

async fn models(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Input(body): Input<Body>,
) -> Result<ApiResponse<Vec<ModelInfo>>, ApiError> {
    let name = match body.supplier_name.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(_) => Some(supplier_name(&body)?),
    };
    let models = suppliers::models(&state, name.as_deref()).await;
    Ok(ok(
        &state,
        &lang,
        "List of models retrieved successfully",
        models,
    ))
}

async fn status(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Value>, ApiError> {
    let configured = suppliers::is_configured(&state).await;
    Ok(ok(
        &state,
        &lang,
        "Supplier status retrieved successfully",
        json!({"is_configured": configured}),
    ))
}

async fn add_model(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let supplier = supplier_name(&body)?;
    let title = required(&body.title, "model title is required")?.to_owned();
    let model_id = model_id(&body)?;
    let max_tokens = max_tokens(&body)?;
    let capability = capability(&body, false)?;
    suppliers::add_model(
        &state,
        ModelInfo {
            title,
            supplier_name: supplier,
            model_id,
            max_tokens,
            capability,
            status: true,
        },
    )
    .await
    .map_err(rejected)?;
    Ok(ok(&state, &lang, "Model added successfully", ()))
}

async fn remove_model(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let supplier = supplier_name(&body)?;
    let model_id = model_id(&body)?;
    if !suppliers::remove_model(&state, &supplier, &model_id)
        .await
        .map_err(rejected)?
    {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "Model not found",
            &[],
        )));
    }
    Ok(ok(&state, &lang, "Model removed successfully", ()))
}

async fn set_supplier_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = supplier_name(&body)?;
    let url = base_url(&body)?;
    let key = required(&body.api_key, "api key is required")?;
    suppliers::set_config(&state, &name, &url, key)
        .await
        .map_err(rejected)?;
    audit
        .record_with(
            LogType::Settings,
            &format!("Set AI supplier {name} configuration"),
            &json!({"supplier_name": name, "base_url": url}),
        )
        .await;
    Ok(ok(
        &state,
        &lang,
        "Supplier configuration updated successfully",
        (),
    ))
}

async fn testing(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = supplier_name(&body)?;
    let url = base_url(&body)?;
    let sent = required(&body.api_key, "api key is required")?;
    let stored = suppliers::config(&state, &name)
        .map(|s| s.api_key)
        .unwrap_or_default();
    suppliers::test(&url, &rules::resolve_key(sent, &stored))
        .await
        .map_err(rejected)?;
    Ok(ok(&state, &lang, "Supplier connection successful", ()))
}

async fn get_supplier_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Supplier>, ApiError> {
    let name = supplier_name(&body)?;
    let supplier = suppliers::config(&state, &name).ok_or_else(|| {
        ApiError::NotFound(
            state
                .i18n
                .tr(&lang, "supplier configuration not found", &[]),
        )
    })?;
    Ok(ok(
        &state,
        &lang,
        "Supplier configuration retrieved successfully",
        supplier.shown(),
    ))
}

async fn set_supplier_status(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = supplier_name(&body)?;
    let on = body
        .status
        .ok_or_else(|| ApiError::Validation("status is required".to_owned()))?;
    suppliers::set_status(&state, &name, on)
        .await
        .map_err(rejected)?;
    audit
        .record(
            LogType::Settings,
            &format!("Set AI supplier {name} status: {on}"),
        )
        .await;
    Ok(ok(
        &state,
        &lang,
        "Supplier status updated successfully",
        (),
    ))
}

/// The answer for an edit of a model that may not exist.
fn model_edited(
    state: &AppState,
    lang: &str,
    found: bool,
    msg: &str,
) -> Result<ApiResponse<()>, ApiError> {
    if !found {
        return Err(ApiError::NotFound(state.i18n.tr(
            lang,
            "model not found",
            &[],
        )));
    }
    Ok(ok(state, lang, msg, ()))
}

async fn set_model_status(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let supplier = supplier_name(&body)?;
    let model_id = model_id(&body)?;
    let on = body
        .status
        .ok_or_else(|| ApiError::Validation("status is required".to_owned()))?;
    let found = suppliers::set_model_status(&state, &supplier, &model_id, on)
        .await
        .map_err(rejected)?;
    model_edited(&state, &lang, found, "Model status updated successfully")
}

async fn add_supplier(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let title = required(&body.supplier_title, "supplier title is required")?.to_owned();
    let name = supplier_name(&body)?;
    let url = base_url(&body)?;
    let key = required(&body.api_key, "api key is required")?;
    suppliers::add_supplier(&state, &title, &name, &url, key)
        .await
        .map_err(rejected)?;
    audit
        .record_with(
            LogType::Settings,
            &format!("Add AI supplier {name}"),
            &json!({"supplier_title": title, "supplier_name": name, "base_url": url}),
        )
        .await;
    Ok(ok(&state, &lang, "Supplier added successfully", ()))
}

async fn remove_supplier(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = supplier_name(&body)?;
    suppliers::remove_supplier(&state, &name)
        .await
        .map_err(rejected)?;
    audit
        .record(LogType::Settings, &format!("Remove AI supplier {name}"))
        .await;
    Ok(ok(&state, &lang, "Supplier removed successfully", ()))
}

async fn set_model_title(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let supplier = supplier_name(&body)?;
    let model_id = model_id(&body)?;
    let title = required(&body.title, "title is required")?;
    let found = suppliers::set_model_title(&state, &supplier, &model_id, title)
        .await
        .map_err(rejected)?;
    model_edited(&state, &lang, found, "Model title updated successfully")
}

async fn set_model_capability(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let supplier = supplier_name(&body)?;
    let model_id = model_id(&body)?;
    let capability = capability(&body, true)?;
    let found = suppliers::set_model_capability(&state, &supplier, &model_id, capability)
        .await
        .map_err(rejected)?;
    model_edited(
        &state,
        &lang,
        found,
        "Model capability updated successfully",
    )
}

async fn modify_model(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let supplier = supplier_name(&body)?;
    let model_id = model_id(&body)?;
    let max_tokens = max_tokens(&body)?;
    let capability = capability(&body, true)?;
    let title = required(&body.title, "title is required")?;
    let found =
        suppliers::modify_model(&state, &supplier, &model_id, title, max_tokens, capability)
            .await
            .map_err(rejected)?;
    model_edited(&state, &lang, found, "Model modified successfully")
}
