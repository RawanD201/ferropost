//! `/api/contact/*` contact routes (Go: `internal/controller/contact`).
//!
//! Fully ported: `list`, `list_ndp`, `edit`, `edit_ndp`, `delete`,
//! `delete_ndp`, `update_group`, `batch_tags_opt`, `trend`.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::contacts::{
    Contact, Granularity, TrendPoint, active_window_start, fill_trend, parse_attributes,
    trend_window,
};
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_store::contacts::{ContactFilter, EmailFilter, TrendFilter};
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
        .route("/api/contact/list", get(list))
        .route("/api/contact/list_ndp", get(list_ndp))
        .route("/api/contact/edit", post(edit))
        .route("/api/contact/edit_ndp", post(edit_ndp))
        .route("/api/contact/delete", post(delete))
        .route("/api/contact/delete_ndp", post(delete_ndp))
        .route("/api/contact/update_group", post(update_group))
        .route("/api/contact/batch_tags_opt", post(batch_tags))
        .route("/api/contact/trend", get(trend))
}

const LIST_OK: &str = "Get contacts list successfully";
const UPDATED: &str = "Contact updated successfully";
const DELETED: &str = "Contacts deleted successfully";

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    /// Subscription state: 1 subscribed (default), 0 unsubscribed.
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
}

/// One entry per address, with every group it is in.
async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<Contact>>, ApiError> {
    let page = validate::id("page", q.page)?;
    let page_size = validate::id("page_size", q.page_size)?.min(100);
    let active = validate::optional_one_of("status", q.status, &[0, 1], 1)? as i32;
    let filter = EmailFilter {
        group_id: validate::optional_id("group_id", q.group_id)?,
        keyword: q.keyword,
        active: Some(active),
    };
    let data = ferropost_store::contacts::list_by_address(
        &state.store.pg,
        &filter,
        PageRequest::new(page.into(), page_size.into()),
    )
    .await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, LIST_OK, &[]), data))
}

#[derive(Debug, Deserialize)]
struct ListRowsQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    last_active_status: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    time_interval: Option<i64>,
    /// Comma-separated tag IDs; `-1` or empty means no tag filter.
    #[serde(default)]
    tags: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    sort_by: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    sort_order: Option<String>,
}

/// One entry per group membership, with group name and tags.
async fn list_ndp(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListRowsQuery>,
) -> Result<ApiResponse<Page<Contact>>, ApiError> {
    let page = validate::id("page", q.page)?;
    let page_size = validate::id("page_size", q.page_size)?.min(1000);
    let active = validate::optional_one_of("active", q.active, &[0, 1, -1], -1)?;
    let last_active =
        validate::optional_one_of("last_active_status", q.last_active_status, &[0, 1, -1], -1)?;
    let sort_by = q.sort_by.unwrap_or_else(|| "create_time".to_owned());
    validate::optional_str_in(
        "sort_by",
        &Some(sort_by.clone()),
        &["create_time", "last_active_at"],
    )?;
    let sort_order = q.sort_order.unwrap_or_else(|| "desc".to_owned());
    validate::optional_str_in("sort_order", &Some(sort_order.clone()), &["asc", "desc"])?;

    let tag_ids = parse_tag_ids(q.tags.as_deref());
    let last_active = match (last_active, q.time_interval) {
        (-1, _) | (_, None) => None,
        (status, Some(days)) => active_window_start(chrono::Utc::now().timestamp(), days)
            .map(|since| (since, status == 1)),
    };

    let filter = ContactFilter {
        group_id: validate::optional_id("group_id", q.group_id)?,
        keyword: q.keyword,
        active: (active != -1).then_some(active as i32),
        tag_ids,
        last_active,
        sort_by_last_active: sort_by == "last_active_at",
        ascending: sort_order == "asc",
    };
    let data = ferropost_store::contacts::list_rows(
        &state.store.pg,
        &filter,
        PageRequest::new(page.into(), page_size.into()),
    )
    .await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, LIST_OK, &[]), data))
}

/// Parses the console's attribute JSON (Go's quote handling) into a JSON
/// object string for the `attribs` column.
fn attributes(state: &AppState, lang: &str, raw: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(raw) = raw.filter(|r| !r.trim().is_empty()) else {
        return Ok(None);
    };
    let parsed = parse_attributes(raw).ok_or_else(|| {
        ApiError::Rejected(state.i18n.tr(
            lang,
            "Invalid attributes format:{}",
            &[&"expected a JSON object"],
        ))
    })?;
    Ok(Some(
        serde_json::to_string(&parsed).map_err(anyhow::Error::from)?,
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct EditBody {
    /// A single address, despite the name.
    #[serde(default)]
    emails: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(default, deserialize_with = "i64_list")]
    group_ids: Vec<i64>,
    #[serde(default)]
    attribs: Option<String>,
}

/// Edits an address everywhere. With `group_ids`, the address ends up in
/// exactly those groups; rows of groups it stays in are kept with their
/// tags and history.
async fn edit(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<EditBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let email = validate::required("emails", &body.emails)?;
    let active = match body.active {
        Some(_) => Some(validate::one_of("active", body.active, &[0, 1])? as i32),
        None => None,
    };
    let attribs = attributes(&state, &lang, body.attribs.as_deref())?;
    let pg = &state.store.pg;

    if body.group_ids.is_empty() {
        // Go did nothing here but reported success.
        ferropost_store::contacts::update_address(pg, email, active, attribs.as_deref()).await?;
    } else {
        let group_ids = validate::id_list("group_ids", &body.group_ids)?;
        let found = ferropost_store::groups::names(pg, &group_ids).await?;
        if let Some(missing) = group_ids
            .iter()
            .find(|id| !found.iter().any(|(g, _)| g == *id))
        {
            return Err(ApiError::NotFound(state.i18n.tr(
                &lang,
                "Group {} not found",
                &[missing],
            )));
        }
        ferropost_store::contacts::set_groups(
            pg,
            email,
            &group_ids,
            active,
            attribs.as_deref(),
            now(),
        )
        .await?;
    }

    let log = format!("Edit contact: {email} successfully");
    audit.record_with(LogType::Contacts, &log, &body).await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, UPDATED, &[]), ()))
}

#[derive(Debug, Deserialize, Serialize)]
struct EditRowBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
    #[serde(default)]
    attribs: Option<String>,
}

/// Edits one membership row. Fields left out keep their value (Go reset
/// `active` and `status` to 0).
async fn edit_ndp(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<EditRowBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let flag = |field: &str, value: Option<i64>| match value {
        Some(_) => validate::one_of(field, value, &[0, 1]).map(|v| Some(v as i32)),
        None => Ok(None),
    };
    let active = flag("active", body.active)?;
    let status = flag("status", body.status)?;
    let attribs = attributes(&state, &lang, body.attribs.as_deref())?;
    if active.is_none() && status.is_none() && attribs.is_none() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "No valid fields to update",
            &[],
        )));
    }

    let email = ferropost_store::contacts::update_row(
        &state.store.pg,
        id,
        active,
        status,
        attribs.as_deref(),
    )
    .await?
    .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "Contact not found", &[])))?;

    let log = format!("Edit contact: {email} successfully");
    audit.record_with(LogType::Contacts, &log, &body).await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, UPDATED, &[]), ()))
}

#[derive(Debug, Deserialize)]
struct DeleteBody {
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
}

#[derive(Serialize)]
struct Deleted {
    deleted_count: u64,
}

/// Deletes addresses in one subscription state from every group.
async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DeleteBody>,
) -> Result<ApiResponse<Deleted>, ApiError> {
    let emails = required_emails(&body.emails)?;
    let active = validate::one_of("status", body.status, &[0, 1])? as i32;

    let deleted_count =
        ferropost_store::contacts::delete_addresses(&state.store.pg, &emails, active).await?;

    let log = format!("Delete contacts :{} successfully", emails.join(", "));
    audit.record_with(LogType::Contacts, &log, &emails).await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, DELETED, &[]),
        Deleted { deleted_count },
    ))
}

#[derive(Debug, Deserialize)]
struct DeleteRowsBody {
    #[serde(default, deserialize_with = "i64_list")]
    ids: Vec<i64>,
}

#[derive(Serialize)]
struct DeletedRow<'a> {
    id: i32,
    email: &'a str,
    group_id: i32,
}

async fn delete_ndp(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DeleteRowsBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let ids = validate::id_list("ids", &body.ids)?;
    let deleted = ferropost_store::contacts::delete_rows(&state.store.pg, &ids).await?;

    let emails: Vec<&str> = deleted.iter().map(|(_, email, _)| email.as_str()).collect();
    let log = format!("Delete contacts successfully :{}", emails.join(", "));
    let snapshot: Vec<DeletedRow> = deleted
        .iter()
        .map(|(id, email, group_id)| DeletedRow {
            id: *id,
            email,
            group_id: *group_id,
        })
        .collect();
    audit.record_with(LogType::Contacts, &log, &snapshot).await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, DELETED, &[]), ()))
}

#[derive(Debug, Deserialize, Serialize)]
struct MoveBody {
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
    #[serde(default, deserialize_with = "i64_list")]
    group_ids: Vec<i64>,
}

#[derive(Serialize)]
struct Moved {
    updated_count: i64,
}

/// Puts addresses (in one subscription state) into exactly `group_ids`.
async fn update_group(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<MoveBody>,
) -> Result<ApiResponse<Moved>, ApiError> {
    let emails = required_emails(&body.emails)?;
    let active = validate::one_of("status", body.status, &[0, 1])? as i32;
    let group_ids = validate::id_list("group_ids", &body.group_ids)?;
    let pg = &state.store.pg;

    let found = ferropost_store::groups::names(pg, &group_ids).await?;
    if let Some(missing) = group_ids
        .iter()
        .find(|id| !found.iter().any(|(g, _)| g == *id))
    {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "Group {} not found",
            &[missing],
        )));
    }

    let updated_count =
        ferropost_store::contacts::move_addresses(pg, &emails, active, &group_ids, now()).await?;

    // Go did not record group moves in the operation log.
    let log = format!(
        "Update contacts group: {} contacts successfully",
        emails.len()
    );
    audit.record_with(LogType::Contacts, &log, &body).await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Contacts group updated successfully", &[]),
        Moved { updated_count },
    ))
}

#[derive(Debug, Deserialize)]
struct BatchTagsBody {
    #[serde(default, deserialize_with = "i64_list")]
    ids: Vec<i64>,
    #[serde(default, deserialize_with = "i64_list")]
    tag_ids: Vec<i64>,
    /// 1 add, 2 remove.
    #[serde(default, deserialize_with = "opt_i64")]
    action: Option<i64>,
}

#[derive(Serialize)]
struct BatchTagsSnapshot<'a> {
    tag_ids: &'a [i32],
    contact_ids: &'a [i32],
    operation: &'a str,
    total_contacts: usize,
    processed: u64,
    skipped: u64,
    errors: u64,
}

/// Adds or removes tags on contact rows. A tag only applies to contacts of
/// its group. One statement either way, so the change is all-or-nothing.
async fn batch_tags(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<BatchTagsBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let ids = validate::id_list("ids", &body.ids)?;
    let tag_ids = validate::id_list("tag_ids", &body.tag_ids)?;
    let add = validate::one_of("action", body.action, &[1, 2])? == 1;
    let pg = &state.store.pg;

    let change = if add {
        ferropost_store::contacts::tag_rows(pg, &ids, &tag_ids, now()).await?
    } else {
        ferropost_store::contacts::untag_rows(pg, &ids, &tag_ids).await?
    };

    let operation = if add { "Add tags" } else { "Remove tags" };
    let log = format!("{operation} for {} contacts successfully", change.changed);
    let snapshot = BatchTagsSnapshot {
        tag_ids: &tag_ids,
        contact_ids: &ids,
        operation,
        total_contacts: ids.len(),
        processed: change.changed,
        skipped: change.skipped,
        errors: 0,
    };
    audit.record_with(LogType::Tag, &log, &snapshot).await;

    let template = if add {
        "Successfully added tags to {} contacts"
    } else {
        "Successfully removed tags from {} contacts"
    };
    let mut msg = state.i18n.tr(&lang, template, &[&change.changed]);
    if change.skipped > 0 {
        msg.push_str(
            &state
                .i18n
                .tr(&lang, " ({} skipped, {} errors)", &[&change.skipped, &0]),
        );
    }
    Ok(ApiResponse::ok(msg, ()))
}

#[derive(Debug, Deserialize)]
struct TrendQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    last_active_status: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    time_interval: Option<i64>,
    #[serde(default)]
    tags: Option<String>,
}

#[derive(Serialize)]
struct Trend {
    time_granularity: &'static str,
    monthly_data: Vec<TrendPoint>,
    daily_data: Vec<TrendPoint>,
}

/// New (or active) subscribers per day or month.
async fn trend(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<TrendQuery>,
) -> Result<ApiResponse<Trend>, ApiError> {
    let active = validate::optional_one_of("active", q.active, &[0, 1, -1], -1)?;
    let last_active =
        validate::optional_one_of("last_active_status", q.last_active_status, &[0, 1, -1], -1)?;
    let interval = q.time_interval.unwrap_or(0);
    let now_ts = chrono::Utc::now().timestamp();
    let window = trend_window(now_ts, interval);

    let filter = TrendFilter {
        group_id: validate::optional_id("group_id", q.group_id)?,
        active: (active != -1).then_some(active as i32),
        tag_ids: parse_tag_ids(q.tags.as_deref()),
        last_active: if last_active != -1 && interval > 0 {
            active_window_start(now_ts, interval).map(|since| (since, last_active == 1))
        } else {
            None
        },
    };
    let counts = ferropost_store::contacts::trend(&state.store.pg, &filter, &window).await?;
    let points = fill_trend(&window, &counts);
    let (monthly_data, daily_data) = match window.granularity {
        Granularity::Monthly => (points, Vec::new()),
        Granularity::Daily => (Vec::new(), points),
    };
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Get contacts trend successfully", &[]),
        Trend {
            time_granularity: window.granularity.as_str(),
            monthly_data,
            daily_data,
        },
    ))
}

/// Comma-separated tag IDs; `-1`, empty, invalid or non-positive entries
/// are ignored (as in Go).
fn parse_tag_ids(raw: Option<&str>) -> Vec<i32> {
    raw.unwrap_or_default()
        .split(',')
        .filter_map(|t| t.trim().parse::<i32>().ok())
        .filter(|id| *id > 0)
        .collect()
}

/// Non-empty, trimmed, de-duplicated addresses.
fn required_emails(emails: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::with_capacity(emails.len());
    for email in emails.iter().map(|e| e.trim()).filter(|e| !e.is_empty()) {
        if !out.iter().any(|e| e == email) {
            out.push(email.to_owned());
        }
    }
    if out.is_empty() {
        return Err(ApiError::Validation(
            "The emails field is required".to_owned(),
        ));
    }
    Ok(out)
}
