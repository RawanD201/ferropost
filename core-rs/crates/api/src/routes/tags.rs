//! `/api/tags/*` (Go: `internal/controller/tags`).
//!
//! Fully ported: `list`, `all`, `create`, `update`, `delete`,
//! `batch_contacts`.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::contacts::parse_email_list;
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_domain::tags::Tag;
use ferropost_store::tags::{TagFilter, Write};
use serde::{Deserialize, Serialize};

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, i64_list, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/tags/list", get(list))
        .route("/api/tags/all", get(all))
        .route("/api/tags/create", post(create))
        .route("/api/tags/update", post(update))
        .route("/api/tags/delete", post(delete))
        .route("/api/tags/batch_contacts", post(batch_contacts))
}

/// Longest tag name accepted (Go's `max-length:50`).
const NAME_MAX: usize = 50;

const LIST_OK: &str = "Get tag list successfully";

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(query): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<Tag>>, ApiError> {
    let filter = TagFilter {
        keyword: query.keyword,
        group_id: group_filter(query.group_id)?,
    };
    let page = PageRequest::new(query.page.unwrap_or(1), query.page_size.unwrap_or(20));
    let data = ferropost_store::tags::list(&state.store.pg, &filter, page).await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, LIST_OK, &[]), data))
}

async fn all(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Page<Tag>>, ApiError> {
    let list = ferropost_store::tags::all(&state.store.pg).await?;
    let data = Page {
        total: i64::try_from(list.len()).unwrap_or(i64::MAX),
        list,
    };
    Ok(ApiResponse::ok(state.i18n.tr(&lang, LIST_OK, &[]), data))
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateBody {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<CreateBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let group_id = validate::id("group_id", body.group_id)?;
    let name = validate::required("name", &body.name)?;
    validate::max_len("name", name, NAME_MAX)?;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    // Go created the tag even when the group did not exist.
    let group = ferropost_store::groups::name(&state.store.pg, group_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(tr("Group not found")))?;
    if !ferropost_store::tags::create(&state.store.pg, group_id, name, now()).await? {
        return Err(ApiError::Conflict(tr("Tag name already exists")));
    }

    let log = format!("Create [{group}] tag :{name} successfully");
    audit.record_with(LogType::Tag, &log, &body).await;
    Ok(ApiResponse::ok(tr("Tag created successfully"), ()))
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
}

async fn update(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<UpdateBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let name = validate::required("name", &body.name)?;
    validate::max_len("name", name, NAME_MAX)?;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    match ferropost_store::tags::rename(&state.store.pg, id, name).await? {
        Write::Done => {}
        Write::NotFound => return Err(ApiError::NotFound(tr("Tag not found"))),
        Write::Duplicate => return Err(ApiError::Conflict(tr("Tag name already exists"))),
    }

    let log = format!("Update tag: {name} successfully");
    audit.record_with(LogType::Tag, &log, &body).await;
    Ok(ApiResponse::ok(tr("Tag updated successfully"), ()))
}

#[derive(Debug, Deserialize, Serialize)]
struct DeleteBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DeleteBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    let name = ferropost_store::tags::delete(&state.store.pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(tr("Tag not found")))?;

    let log = format!("Delete tag: {name} successfully");
    audit.record_with(LogType::Tag, &log, &body).await;
    Ok(ApiResponse::ok(tr("Tag deleted successfully"), ()))
}

#[derive(Debug, Deserialize)]
struct BatchBody {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "i64_list")]
    tag_ids: Vec<i64>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    mark_include: Option<i64>,
}

#[derive(Serialize)]
struct BatchSnapshot<'a> {
    tag_ids: &'a [i32],
    tag_names: &'a [String],
    group_id: i32,
    operation: &'a str,
    total_emails: usize,
    processed: u64,
    skipped: u64,
    errors: u64,
}

/// Tags the listed addresses (`mark_include: 1`) or every other contact of
/// the group (`mark_include: 0`).
async fn batch_contacts(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<BatchBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let group_id = validate::id("group_id", body.group_id)?;
    let tag_ids = validate::id_list("tag_ids", &body.tag_ids)?;
    let data = validate::required("data", &body.data)?;
    let include = validate::one_of("mark_include", body.mark_include, &[0, 1])? == 1;
    let pg = &state.store.pg;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    if ferropost_store::groups::name(pg, group_id).await?.is_none() {
        return Err(ApiError::NotFound(tr("Group not found")));
    }

    let found = ferropost_store::tags::by_ids(pg, &tag_ids).await?;
    if found.is_empty() {
        return Err(ApiError::Rejected(tr("No tags found")));
    }
    if found.len() != tag_ids.len() {
        return Err(ApiError::Rejected(tr("Some tags not found")));
    }
    let mut tag_names = Vec::with_capacity(tag_ids.len());
    for id in &tag_ids {
        let Some(tag) = found.iter().find(|t| t.id == *id) else {
            return Err(ApiError::Rejected(tr("Some tags not found")));
        };
        if tag.group_id != group_id {
            return Err(ApiError::Rejected(state.i18n.tr(
                &lang,
                "Tag '{}' does not belong to this group",
                &[&tag.name],
            )));
        }
        tag_names.push(tag.name.clone());
    }

    let emails = parse_email_list(data);
    if emails.is_empty() {
        return Err(ApiError::Rejected(tr("No valid emails provided")));
    }

    let result = if include {
        ferropost_store::tags::tag_contacts(pg, group_id, &tag_ids, &emails, now()).await?
    } else {
        ferropost_store::tags::tag_contacts_except(pg, group_id, &tag_ids, &emails, now()).await?
    };

    let operation = if include { " Include" } else { " Not included" };
    let log = format!(
        "Batch add tags: {}{operation} for {} contact-tag pairs successfully",
        tag_names.join(", "),
        result.inserted
    );
    let snapshot = BatchSnapshot {
        tag_ids: &tag_ids,
        tag_names: &tag_names,
        group_id,
        operation,
        total_emails: emails.len(),
        processed: result.inserted,
        skipped: result.skipped,
        errors: 0,
    };
    audit.record_with(LogType::Tag, &log, &snapshot).await;

    let mut msg = tr("Batch tag operation completed");
    if result.skipped > 0 {
        // The statement is all-or-nothing, so there are never partial errors.
        msg.push_str(&state.i18n.tr(
            &lang,
            " ( {}  skipped,  {}  errors)",
            &[&result.skipped, &0],
        ));
    }
    Ok(ApiResponse::ok(msg, ()))
}

/// `0` or absent means "all groups"; negatives fail like Go's `min:1` rule.
fn group_filter(group_id: Option<i64>) -> Result<Option<i32>, ApiError> {
    match group_id {
        None | Some(0) => Ok(None),
        Some(id) if id < 0 => Err(ApiError::Validation(format!(
            "The group_id value `{id}` must be equal or greater than 1"
        ))),
        Some(id) => i32::try_from(id).map(Some).map_err(|_| {
            ApiError::Validation(format!("The group_id value `{id}` is out of range"))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_filter_rules() {
        assert_eq!(group_filter(None).expect("ok"), None);
        assert_eq!(group_filter(Some(0)).expect("ok"), None);
        assert_eq!(group_filter(Some(7)).expect("ok"), Some(7));
        assert!(matches!(
            group_filter(Some(-1)),
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            group_filter(Some(i64::MAX)),
            Err(ApiError::Validation(_))
        ));
    }
}
