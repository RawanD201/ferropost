//! `/api/email_template/*` (Go: `internal/controller/email_template`).
//!
//! Fully ported: `create`, `delete`, `update`, `list`, `copy`, `get`, `all`,
//! `check`.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_domain::templates::{
    ContentScore, EmailTemplate, TemplateKind, check_content, copy_name,
};
use ferropost_store::Write;
use ferropost_store::templates::NewTemplate;
use serde::{Deserialize, Serialize};

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/email_template/create", post(create))
        .route("/api/email_template/delete", post(delete))
        .route("/api/email_template/update", post(update))
        .route("/api/email_template/list", get(list))
        .route("/api/email_template/copy", post(copy))
        .route("/api/email_template/get", get(get_one))
        .route("/api/email_template/all", get(all))
        .route("/api/email_template/check", post(check))
}

/// How many `_bak` names `copy` tries before giving up.
const COPY_ATTEMPTS: u32 = 50;

#[derive(Serialize)]
struct Created {
    id: i32,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateBody {
    #[serde(default)]
    temp_name: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    add_type: Option<i64>,
    #[serde(default)]
    html_content: Option<String>,
    #[serde(default)]
    drag_data: Option<String>,
    #[serde(default)]
    chat_id: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<CreateBody>,
) -> Result<ApiResponse<Created>, ApiError> {
    let name = validate::required("temp_name", &body.temp_name)?;
    let code = validate::one_of("add_type", body.add_type, &[0, 1, 2])?;
    let kind = TemplateKind::from_code(code).ok_or_else(|| anyhow::anyhow!("checked above"))?;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    let (content, render) = kind
        .content(
            body.html_content.as_deref().unwrap_or_default(),
            body.drag_data.as_deref().unwrap_or_default(),
        )
        .map_err(|msg| ApiError::Rejected(tr(msg)))?;

    let id = ferropost_store::templates::create(
        &state.store.pg,
        &NewTemplate {
            name,
            add_type: kind.code(),
            content,
            render,
            chat_id: body.chat_id.as_deref().unwrap_or_default(),
            now: now(),
        },
    )
    .await?
    .ok_or_else(|| ApiError::Conflict(tr("Template name already exists")))?;

    let log = format!("Create template :{name} successfully");
    audit.record_with(LogType::Template, &log, &body).await;
    Ok(ApiResponse::ok(
        tr("Template created successfully"),
        Created { id },
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct IdBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
    #[serde(default)]
    chat_id: Option<String>,
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<IdBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    // Go dereferenced a nil template here and crashed the request.
    let template = ferropost_store::templates::delete(&state.store.pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(tr("Template not found")))?;

    let log = format!("Delete template :{} successfully", template.temp_name);
    audit.record_with(LogType::Template, &log, &template).await;
    Ok(ApiResponse::ok(tr("Template deleted successfully"), ()))
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
    #[serde(default)]
    temp_name: Option<String>,
    #[serde(default)]
    html_content: Option<String>,
    #[serde(default)]
    drag_data: Option<String>,
}

async fn update(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<UpdateBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let name = body.temp_name.as_deref().map(str::trim);
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    let outcome = ferropost_store::templates::update(
        &state.store.pg,
        id,
        name,
        body.html_content.as_deref(),
        body.drag_data.as_deref(),
        now(),
    )
    .await?;
    match outcome {
        Write::Done => {}
        Write::NotFound => return Err(ApiError::NotFound(tr("Template not found"))),
        // Go surfaced this as "Failed to update template".
        Write::Duplicate => return Err(ApiError::Conflict(tr("Template name already exists"))),
    }

    let log = format!("Update template :{} successfully", name.unwrap_or_default());
    audit.record_with(LogType::Template, &log, &body).await;
    Ok(ApiResponse::ok(tr("Template updated successfully"), ()))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    /// `-1` or absent means every type.
    #[serde(default, deserialize_with = "opt_i64")]
    add_type: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<EmailTemplate>>, ApiError> {
    let page = validate::id("page", q.page)?;
    let page_size = validate::id("page_size", q.page_size)?;
    let add_type = match q.add_type {
        None | Some(-1) => None,
        Some(code) => Some(i16::try_from(code).map_err(|_| {
            ApiError::Validation(format!("The add_type value `{code}` is out of range"))
        })?),
    };

    let data = ferropost_store::templates::list(
        &state.store.pg,
        q.keyword.as_deref(),
        add_type,
        PageRequest::new(page.into(), page_size.into()),
    )
    .await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Get template list successfully", &[]),
        data,
    ))
}

async fn copy(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<IdBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);
    let pg = &state.store.pg;

    let template = ferropost_store::templates::get(pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(tr("Template not found")))?;

    // Go always used `<name>_bak`, so a second copy failed on the unique name.
    let mut copied = None;
    for attempt in 1..=COPY_ATTEMPTS {
        let name = copy_name(&template.temp_name, attempt);
        let new = NewTemplate {
            name: &name,
            add_type: template.add_type,
            content: &template.content,
            render: &template.render,
            chat_id: body.chat_id.as_deref().unwrap_or_default(),
            now: now(),
        };
        if ferropost_store::templates::create(pg, &new)
            .await?
            .is_some()
        {
            copied = Some(name);
            break;
        }
    }
    let new_name = copied.ok_or_else(|| ApiError::Conflict(tr("Template name already exists")))?;

    let log = format!(
        "Copy template :{} to {new_name} successfully",
        template.temp_name
    );
    audit.record_with(LogType::Template, &log, &template).await;
    Ok(ApiResponse::ok(tr("Template copied successfully"), ()))
}

#[derive(Debug, Deserialize)]
struct GetQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
}

async fn get_one(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<GetQuery>,
) -> Result<ApiResponse<EmailTemplate>, ApiError> {
    let id = validate::id("id", q.id)?;
    let template = ferropost_store::templates::get(&state.store.pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "Template not found", &[])))?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Get template successfully", &[]),
        template,
    ))
}

/// Every template, newest first. An empty list is `[]` (Go sent `null`).
async fn all(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Vec<EmailTemplate>>, ApiError> {
    let templates = ferropost_store::templates::all(&state.store.pg).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Get template list successfully", &[]),
        templates,
    ))
}

#[derive(Debug, Deserialize)]
struct CheckBody {
    #[serde(default)]
    content: Option<String>,
}

async fn check(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<CheckBody>,
) -> ApiResponse<ContentScore> {
    let score = check_content(body.content.as_deref().unwrap_or_default());
    ApiResponse::ok(state.i18n.tr(&lang, "Successful", &[]), score)
}
