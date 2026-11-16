//! `/api/askai/chat/*` (Go: `controller/askai`, chats): designing email
//! templates with an AI model. See `crate::askai::chat`.

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ferropost_domain::askai::{ChatInfo, TempChat, is_item_id, is_supplier_name};
use ferropost_domain::domains::is_domain_name;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::askai::chat::{self, Ask};
use crate::askai::openai::ChatModel;
use crate::body::{ApiBody, Input};
use crate::de::{opt_bool, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/askai/chat/create_chat", post(create_chat))
        .route("/api/askai/chat/get_chat_list", post(get_chat_list))
        .route("/api/askai/chat/info", post(info))
        .route("/api/askai/chat/chat", get(ask).post(ask))
        .route("/api/askai/chat/remove_chat", post(remove_chat))
        .route("/api/askai/chat/stop", post(stop))
        .route("/api/askai/chat/get_html", post(get_html))
        .route("/api/askai/chat/modify_html", post(modify_html))
        .route("/api/askai/chat/copy_chat", post(copy_chat))
}

#[derive(Debug, Default, Deserialize)]
struct Body {
    #[serde(
        default,
        rename = "chatId",
        alias = "chat_id",
        deserialize_with = "opt_string"
    )]
    chat_id: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    add_type: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    temp_name: Option<String>,
    #[serde(default, alias = "supplierName", deserialize_with = "opt_string")]
    supplier_name: Option<String>,
    #[serde(default, alias = "modelId", deserialize_with = "opt_string")]
    model_id: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default, deserialize_with = "opt_bool")]
    is_text: Option<bool>,
}

fn chat_id(body: &Body) -> Result<String, ApiError> {
    let id = body
        .chat_id
        .as_deref()
        .map(str::trim)
        .filter(|i| !i.is_empty())
        .ok_or_else(|| ApiError::Validation("chat id is required".to_owned()))?;
    if !is_item_id(id) {
        return Err(ApiError::Validation("invalid chat id".to_owned()));
    }
    Ok(id.to_owned())
}

fn domain(body: &Body) -> Result<String, ApiError> {
    let domain = body
        .domain
        .as_deref()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .ok_or_else(|| ApiError::Validation("domain is required".to_owned()))?;
    if !is_domain_name(&domain) {
        return Err(ApiError::Validation(format!(
            "The domain value `{domain}` is not a valid domain format"
        )));
    }
    Ok(domain)
}

fn failed(err: anyhow::Error) -> ApiError {
    ApiError::Rejected(format!("{err:#}"))
}

fn ok<T: serde::Serialize>(state: &AppState, lang: &str, msg: &str, data: T) -> ApiResponse<T> {
    ApiResponse::ok(state.i18n.tr(lang, msg, &[]), data)
}

fn chat_not_found(state: &AppState, lang: &str) -> ApiError {
    ApiError::NotFound(state.i18n.tr(lang, "Chat not found", &[]))
}

async fn create_chat(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Value>, ApiError> {
    let domain = domain(&body)?;
    let add_type = body
        .add_type
        .ok_or_else(|| ApiError::Validation("add type is required".to_owned()))?;
    let title = body
        .temp_name
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ApiError::Validation("temporary name is required".to_owned()))?;
    if title.chars().count() > 200 {
        return Err(ApiError::Validation(
            "temporary name is longer than 200 characters".to_owned(),
        ));
    }
    let id = chat::create(&state, &domain, add_type, title)
        .await
        .map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Chat created successfully",
        json!({"chatId": id}),
    ))
}

async fn get_chat_list(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> ApiResponse<Vec<TempChat>> {
    ok(
        &state,
        &lang,
        "Chat list retrieved successfully",
        chat::list(&state),
    )
}

async fn info(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<ChatInfo>, ApiError> {
    let id = chat_id(&body)?;
    let info = chat::info(&state, &id).ok_or_else(|| chat_not_found(&state, &lang))?;
    Ok(ok(&state, &lang, "Chat info retrieved successfully", info))
}

/// `chat`: answers as server-sent events (or plain text with `is_text`).
async fn ask(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Input(body): Input<Body>,
) -> Result<Response, ApiError> {
    let id = chat_id(&body)?;
    let question = body.content.as_deref().map(str::trim).unwrap_or_default();
    if question.is_empty() {
        return Err(ApiError::Validation("Content cannot be empty".to_owned()));
    }
    let supplier = body
        .supplier_name
        .as_deref()
        .map(str::trim)
        .filter(|s| is_supplier_name(s))
        .ok_or_else(|| ApiError::Validation("supplier name is required".to_owned()))?;
    let model_id = body
        .model_id
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| ApiError::Validation("model id is required".to_owned()))?;
    if crate::askai::suppliers::config(&state, supplier).is_none() {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "Supplier not found",
            &[],
        )));
    }
    if crate::askai::suppliers::model(&state, supplier, model_id).is_none() {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "Model not found",
            &[],
        )));
    }
    let model = ChatModel::of(&state, supplier, model_id).ok_or_else(|| {
        ApiError::Rejected(state.i18n.tr(&lang, "The AI model is switched off", &[]))
    })?;
    if chat::temp(&state, &id).is_none() {
        return Err(chat_not_found(&state, &lang));
    }
    chat::use_model(&state, &id, &model)
        .await
        .map_err(|_| chat_not_found(&state, &lang))?;
    let ask = Ask {
        chat_id: id,
        model,
        question: question.to_owned(),
        is_text: body.is_text.unwrap_or(false),
    };
    match chat::respond(&state, ask) {
        Some(response) => Ok(response.into_response()),
        None => Err(ApiError::Conflict(state.i18n.tr(
            &lang,
            "This chat is already answering",
            &[],
        ))),
    }
}

async fn remove_chat(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = chat_id(&body)?;
    if !chat::remove(&state, &id).await.map_err(failed)? {
        return Err(chat_not_found(&state, &lang));
    }
    Ok(ok(&state, &lang, "Chat removed successfully", ()))
}

async fn stop(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = chat_id(&body)?;
    if !chat::stop(&id) {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Chat not found or already stopped",
            &[],
        )));
    }
    Ok(ok(&state, &lang, "Chat stopped successfully", ()))
}

async fn get_html(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Value>, ApiError> {
    let id = chat_id(&body)?;
    if chat::temp(&state, &id).is_none() {
        return Err(chat_not_found(&state, &lang));
    }
    Ok(ok(
        &state,
        &lang,
        "HTML content retrieved successfully",
        json!({
            "html_content": chat::html(&state, &id),
            "last_usage": chat::last_usage(&state, &id),
        }),
    ))
}

async fn modify_html(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = chat_id(&body)?;
    let content = body
        .content
        .as_deref()
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| ApiError::Validation("content is required".to_owned()))?;
    if content.len() > 5_000_000 {
        return Err(ApiError::Validation(
            "content is larger than 5 MB".to_owned(),
        ));
    }
    if chat::temp(&state, &id).is_none() {
        return Err(chat_not_found(&state, &lang));
    }
    chat::set_html(&state, &id, content).await.map_err(failed)?;
    Ok(ok(&state, &lang, "HTML content modified successfully", ()))
}

async fn copy_chat(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<Body>,
) -> Result<ApiResponse<Value>, ApiError> {
    let id = chat_id(&body)?;
    let domain = domain(&body)?;
    if chat::temp(&state, &id).is_none() {
        return Err(chat_not_found(&state, &lang));
    }
    let (new_id, content) = chat::copy(&state, &id, &domain).await.map_err(failed)?;
    Ok(ok(
        &state,
        &lang,
        "Chat copied successfully",
        json!({"chatId": new_id, "content": content}),
    ))
}
