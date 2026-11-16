//! `/api/contact/group/*` (Go: `internal/controller/contact`).
//!
//! Fully ported: `create`, `import`, `export`, `delete`, `update`,
//! `update_unsubscribe`, `list`, `all`, `info`, `merge_contacts`,
//! `contact_count`, `tag_contact_count`.

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::contacts::{ImportSource, dedupe, parse_contacts};
use ferropost_domain::groups::{GroupBrief, GroupListItem, TagLogic};
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_store::Write;
use ferropost_store::groups::GroupChanges;
use serde::{Deserialize, Serialize};

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, i64_list, opt_bool, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::export::{self as files, Format};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/contact/group/create", post(create))
        .route("/api/contact/group/import", post(import))
        .route("/api/contact/group/export", post(export))
        .route("/api/contact/group/delete", post(delete))
        .route("/api/contact/group/update", post(update))
        .route(
            "/api/contact/group/update_unsubscribe",
            post(update_unsubscribe),
        )
        .route("/api/contact/group/list", get(list))
        .route("/api/contact/group/all", get(all))
        .route("/api/contact/group/info", get(info))
        .route("/api/contact/group/merge_contacts", post(merge))
        .route("/api/contact/group/contact_count", post(contact_count))
        .route(
            "/api/contact/group/tag_contact_count",
            post(tag_contact_count),
        )
}

const FILE_TYPES: &[&str] = &["csv", "excel", "txt"];
const NAME_MAX: usize = 255;

#[derive(Serialize)]
struct GroupId {
    group_id: i32,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateBody {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    /// Not kept in the operation-log snapshot: it can be megabytes.
    #[serde(default, skip_serializing)]
    file_data: Option<String>,
    #[serde(default)]
    file_type: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    create_type: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    double_optin: Option<i64>,
}

#[derive(Serialize)]
struct ImportSummary<'a> {
    group_ids: &'a [i32],
    contacts: usize,
    imported: u64,
}

/// `create_type` 1: create a group; 2: create a group and import a file;
/// 3: import a file into an existing group. Creating and importing happen
/// in one transaction, so a failed import leaves no empty group behind.
async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<CreateBody>,
) -> Result<ApiResponse<GroupId>, ApiError> {
    let create_type = validate::one_of("create_type", body.create_type, &[1, 2, 3])?;
    let double_optin = validate::optional_one_of("double_optin", body.double_optin, &[0, 1], 0)?;
    validate::optional_str_in("file_type", &body.file_type, FILE_TYPES)?;
    let file = body.file_data.as_deref().unwrap_or_default();
    let pg = &state.store.pg;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    let mut tx = pg.begin().await.map_err(anyhow::Error::from)?;
    let (group_id, group_name) = if create_type == 3 {
        let id = validate::optional_id("group_id", body.group_id)?.ok_or_else(|| {
            ApiError::Rejected(tr("Group ID is required for importing to existing group"))
        })?;
        let name = ferropost_store::groups::name(pg, id)
            .await?
            .ok_or_else(|| {
                ApiError::NotFound(state.i18n.tr(&lang, "Group {} does not exist", &[&id]))
            })?;
        (id, name)
    } else {
        // Go accepted an empty name here.
        let name = validate::required("name", &body.name)?;
        validate::max_len("name", name, NAME_MAX)?;
        let description = body.description.as_deref().unwrap_or_default();
        let id =
            ferropost_store::groups::create(&mut tx, name, description, double_optin as i16, now())
                .await?
                .ok_or_else(|| ApiError::Conflict(tr("The group name already exists")))?;
        (id, name.to_owned())
    };

    if create_type == 1 || (create_type == 2 && file.trim().is_empty()) {
        tx.commit().await.map_err(anyhow::Error::from)?;
        let log = format!("Created group :{group_name} successfully");
        audit.record(LogType::ContactsGroup, &log).await;
        return Ok(ApiResponse::ok(
            tr("Group created successfully"),
            GroupId { group_id },
        ));
    }
    if file.trim().is_empty() {
        return Err(ApiError::Rejected(tr("File content cannot be empty")));
    }

    let contacts = dedupe(parse_contacts(file, ImportSource::File), false);
    if contacts.is_empty() {
        return Err(ApiError::Rejected(tr("No valid contacts found in file")));
    }
    // Go inserted without skipping duplicates, so re-importing a file into
    // an existing group failed as a whole.
    let imported =
        ferropost_store::contacts::insert_new(&mut tx, group_id, 1, &contacts, now()).await?;
    tx.commit().await.map_err(anyhow::Error::from)?;

    let (log, msg) = if create_type == 2 {
        (
            format!("Created group :{group_name} successfully"),
            "Group created and contacts imported successfully",
        )
    } else {
        (
            format!("Imported contacts into group :{group_name} successfully"),
            "Contacts imported to existing group successfully",
        )
    };
    let summary = ImportSummary {
        group_ids: &[group_id],
        contacts: contacts.len(),
        imported,
    };
    audit
        .record_with(LogType::ContactsGroup, &log, &summary)
        .await;
    Ok(ApiResponse::ok(tr(msg), GroupId { group_id }))
}

#[derive(Debug, Deserialize)]
struct ImportBody {
    #[serde(default, deserialize_with = "i64_list")]
    group_ids: Vec<i64>,
    #[serde(default)]
    file_data: Option<String>,
    #[serde(default)]
    file_type: Option<String>,
    #[serde(default)]
    contacts: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    import_type: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    default_active: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    overwrite: Option<i64>,
}

#[derive(Serialize)]
struct Imported {
    imported_count: u64,
}

/// Imports a file (`import_type` 1) or pasted lines (2) into each group.
/// With `overwrite: 1`, existing addresses get the imported subscription
/// state and attributes; otherwise they are skipped.
async fn import(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ImportBody>,
) -> Result<ApiResponse<Imported>, ApiError> {
    let group_ids = validate::id_list("group_ids", &body.group_ids)?;
    let import_type = validate::one_of("import_type", body.import_type, &[1, 2])?;
    let default_active =
        validate::optional_one_of("default_active", body.default_active, &[0, 1], 0)?;
    let status = validate::optional_one_of("status", body.status, &[0, 1], 0)?;
    let overwrite = validate::optional_one_of("overwrite", body.overwrite, &[0, 1], 0)? == 1;
    validate::optional_str_in("file_type", &body.file_type, FILE_TYPES)?;
    let pg = &state.store.pg;
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);

    let groups = ferropost_store::groups::names(pg, &group_ids).await?;
    if let Some(missing) = group_ids
        .iter()
        .find(|id| !groups.iter().any(|(g, _)| g == *id))
    {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "Group {} does not exist",
            &[missing],
        )));
    }

    let (text, source) = if import_type == 1 {
        (body.file_data.as_deref(), ImportSource::File)
    } else {
        (body.contacts.as_deref(), ImportSource::Paste)
    };
    let Some(text) = text.filter(|t| !t.trim().is_empty()) else {
        return Err(ApiError::Rejected(tr(if import_type == 1 {
            "File content cannot be empty"
        } else {
            "Contacts content cannot be empty"
        })));
    };

    let mut contacts = parse_contacts(text, source);
    for contact in &mut contacts {
        // Go's rule: rows marked subscribed take the requested default.
        if contact.active == 1 {
            contact.active = default_active as i32;
        }
    }
    let contacts = dedupe(contacts, overwrite);
    if contacts.is_empty() {
        return Err(ApiError::Rejected(tr("No valid contacts found")));
    }

    let mut tx = pg.begin().await.map_err(anyhow::Error::from)?;
    let mut imported = 0;
    for group_id in &group_ids {
        imported += if overwrite {
            ferropost_store::contacts::upsert(&mut tx, *group_id, status as i32, &contacts, now())
                .await?
        } else {
            ferropost_store::contacts::insert_new(
                &mut tx,
                *group_id,
                status as i32,
                &contacts,
                now(),
            )
            .await?
        };
    }
    tx.commit().await.map_err(anyhow::Error::from)?;

    let names: Vec<&str> = groups.iter().map(|(_, name)| name.as_str()).collect();
    let log = format!("Import contacts: {} successfully", names.join(", "));
    let summary = ImportSummary {
        group_ids: &group_ids,
        contacts: contacts.len(),
        imported,
    };
    audit.record_with(LogType::Contacts, &log, &summary).await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Successfully imported {} contacts", &[&imported]),
        Imported {
            imported_count: imported,
        },
    ))
}

#[derive(Debug, Deserialize)]
struct ExportBody {
    #[serde(default, deserialize_with = "i64_list")]
    group_ids: Vec<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    export_type: Option<i64>,
    #[serde(default)]
    format: Option<String>,
    /// Go always exported unsubscribed contacts, ignoring `false`.
    #[serde(default, deserialize_with = "opt_bool")]
    include_unsubscribe: Option<bool>,
}

/// `export_type` 1: one file with every address across the groups;
/// 2: a ZIP with one file per group.
async fn export(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ExportBody>,
) -> Result<Response, ApiError> {
    let group_ids = validate::id_list("group_ids", &body.group_ids)?;
    let merged = validate::one_of("export_type", body.export_type, &[1, 2])? == 1;
    let format = validate::str_one_of("format", &body.format, &["csv", "excel", "txt"])?;
    let format = Format::parse(format).ok_or_else(|| anyhow::anyhow!("validated above"))?;
    let include_inactive = body.include_unsubscribe.unwrap_or(true);
    let pg = &state.store.pg;
    let groups = ferropost_store::groups::names(pg, &group_ids).await?;

    let (name, bytes) = if merged {
        let rows =
            ferropost_store::contacts::export_merged(pg, &group_ids, include_inactive).await?;
        (
            files::download_name(format.extension()),
            files::render(&rows, format)?,
        )
    } else {
        let mut entries = Vec::new();
        for (id, group) in &groups {
            let rows = ferropost_store::contacts::export_group(pg, *id, include_inactive).await?;
            if !rows.is_empty() {
                let entry = format!("{}.{}", files::file_name(group), format.extension());
                entries.push((entry, files::render(&rows, format)?));
            }
        }
        if entries.is_empty() {
            return Err(ApiError::Rejected(state.i18n.tr(
                &lang,
                "No contacts to export",
                &[],
            )));
        }
        (files::download_name("zip"), files::zip(&entries)?)
    };

    let names: Vec<&str> = groups.iter().map(|(_, n)| n.as_str()).collect();
    let log = format!(
        "Contacts Group exported successfully: {} ",
        names.join(", ")
    );
    audit.record(LogType::ContactsGroup, &log).await;
    Ok(files::download(&name, bytes))
}

#[derive(Debug, Deserialize)]
struct GroupIdsBody {
    #[serde(default, deserialize_with = "i64_list")]
    group_ids: Vec<i64>,
}

#[derive(Serialize)]
struct DeleteResult {
    success_count: u32,
    failed_count: u32,
}

#[derive(Serialize)]
struct DeleteSnapshot<'a> {
    group_ids: &'a [i32],
    deleted: &'a [String],
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<GroupIdsBody>,
) -> Result<ApiResponse<DeleteResult>, ApiError> {
    let group_ids = validate::id_list("group_ids", &body.group_ids)?;
    let mut deleted = Vec::new();
    let mut failed_count = 0;
    for id in &group_ids {
        match ferropost_store::groups::delete(&state.store.pg, *id).await {
            Ok(Some(name)) => deleted.push(name),
            Ok(None) => failed_count += 1,
            Err(err) => {
                tracing::error!(group = id, error = %format!("{err:#}"), "delete group");
                failed_count += 1;
            }
        }
    }

    let log = format!("Deleted group successfully: {}", deleted.join(", "));
    let snapshot = DeleteSnapshot {
        group_ids: &group_ids,
        deleted: &deleted,
    };
    audit
        .record_with(LogType::ContactsGroup, &log, &snapshot)
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Groups deleted successfully", &[]),
        DeleteResult {
            success_count: u32::try_from(deleted.len()).unwrap_or(u32::MAX),
            failed_count,
        },
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateBody {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    double_optin: Option<i64>,
    #[serde(default)]
    welcome_mail_html: Option<String>,
    #[serde(default)]
    welcome_mail_drag: Option<String>,
    #[serde(default)]
    confirm_mail_html: Option<String>,
    #[serde(default)]
    confirm_mail_drag: Option<String>,
    #[serde(default)]
    success_url: Option<String>,
    #[serde(default)]
    confirm_url: Option<String>,
    #[serde(default)]
    already_url: Option<String>,
    #[serde(default)]
    welcome_subject: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    send_welcome_email: Option<i64>,
    #[serde(default)]
    confirm_subject: Option<String>,
}

/// Non-empty strings are applied, as in Go. Unlike Go, flags left out of
/// the request keep their value (Go reset them to 0).
async fn update(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<UpdateBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("group_id", body.group_id)?;
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty());
    if let Some(name) = name {
        validate::max_len("name", name, NAME_MAX)?;
    }
    let mut changes = GroupChanges::default();
    if let Some(name) = name {
        changes.text.push(("name", name));
    }
    for (column, value) in [
        ("description", &body.description),
        ("welcome_mail_html", &body.welcome_mail_html),
        ("welcome_mail_drag", &body.welcome_mail_drag),
        ("confirm_mail_html", &body.confirm_mail_html),
        ("confirm_mail_drag", &body.confirm_mail_drag),
        ("success_url", &body.success_url),
        ("confirm_url", &body.confirm_url),
        ("already_url", &body.already_url),
        ("welcome_subject", &body.welcome_subject),
        ("confirm_subject", &body.confirm_subject),
    ] {
        if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
            changes.text.push((column, value));
        }
    }
    for (column, value) in [
        ("double_optin", body.double_optin),
        ("send_welcome_email", body.send_welcome_email),
    ] {
        if value.is_some() {
            let flag = validate::one_of(column, value, &[0, 1])?;
            changes.flags.push((column, flag as i16));
        }
    }

    let old_name = apply_group_changes(&state, &lang, id, &changes).await?;
    let log = match name {
        Some(name) => format!("Updated group: {name} successfully"),
        None => format!("Update the subscription link Settings for group: {old_name} "),
    };
    audit.record_with(LogType::ContactsGroup, &log, &body).await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Group updated successfully", &[]),
        (),
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct UnsubscribeBody {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default)]
    unsubscribe_mail_html: Option<String>,
    #[serde(default)]
    unsubscribe_mail_drag: Option<String>,
    #[serde(default)]
    unsubscribe_subject: Option<String>,
    #[serde(default)]
    unsubscribe_redirect_url: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    send_unsubscribe_email: Option<i64>,
}

async fn update_unsubscribe(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<UnsubscribeBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("group_id", body.group_id)?;
    let mut changes = GroupChanges::default();
    for (column, value) in [
        ("unsubscribe_mail_html", &body.unsubscribe_mail_html),
        ("unsubscribe_mail_drag", &body.unsubscribe_mail_drag),
        ("unsubscribe_subject", &body.unsubscribe_subject),
        ("unsubscribe_redirect_url", &body.unsubscribe_redirect_url),
    ] {
        if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
            changes.text.push((column, value));
        }
    }
    if body.send_unsubscribe_email.is_some() {
        let flag = validate::one_of(
            "send_unsubscribe_email",
            body.send_unsubscribe_email,
            &[0, 1],
        )?;
        changes.flags.push(("send_unsubscribe_email", flag as i16));
    }

    let name = apply_group_changes(&state, &lang, id, &changes).await?;
    let log = format!("Update the Unsubscribe Settings for group: {name} ");
    audit.record_with(LogType::ContactsGroup, &log, &body).await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Group updated successfully", &[]),
        (),
    ))
}

/// Shared tail of both update endpoints. Returns the group's name before
/// the update. A missing group is a 404 (Go reported success).
async fn apply_group_changes(
    state: &AppState,
    lang: &str,
    id: i32,
    changes: &GroupChanges<'_>,
) -> Result<String, ApiError> {
    let tr = |msg: &str| state.i18n.tr(lang, msg, &[]);
    if changes.is_empty() {
        return Err(ApiError::Rejected(tr("No fields to update")));
    }
    let pg = &state.store.pg;
    let old_name = ferropost_store::groups::name(pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(tr("Group not found")))?;
    match ferropost_store::groups::update(pg, id, changes, now()).await? {
        Write::Done => Ok(old_name),
        Write::NotFound => Err(ApiError::NotFound(tr("Group not found"))),
        Write::Duplicate => Err(ApiError::Conflict(tr("The group name already exists"))),
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<GroupListItem>>, ApiError> {
    let page = validate::id("page", q.page)?;
    let page_size = validate::id("page_size", q.page_size)?;
    let pg = &state.store.pg;
    ferropost_store::groups::backfill_tokens(pg).await?;
    let keyword = q
        .keyword
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty());
    let data =
        ferropost_store::groups::list(pg, keyword, PageRequest::new(page.into(), page_size.into()))
            .await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Group list retrieved successfully", &[]),
        data,
    ))
}

#[derive(Debug, Deserialize)]
struct AllQuery {
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
}

#[derive(Serialize)]
struct GroupList {
    list: Vec<GroupBrief>,
}

async fn all(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<AllQuery>,
) -> Result<ApiResponse<GroupList>, ApiError> {
    let list = ferropost_store::groups::all(&state.store.pg, q.keyword.as_deref()).await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Get all contact groups successfully", &[]),
        GroupList { list },
    ))
}

#[derive(Debug, Deserialize)]
struct InfoQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
}

/// A group with its subscription settings, filling unset ones with the
/// defaults the subscribe flow uses (the console shows them as such).
async fn info(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<InfoQuery>,
) -> Result<ApiResponse<GroupListItem>, ApiError> {
    use crate::templates::{Kind, default_mail, subscribe_form_code};
    let id = validate::id("group_id", q.group_id)?;
    let pg = &state.store.pg;
    ferropost_store::groups::backfill_tokens(pg).await?;
    let mut g = ferropost_store::groups::get(pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "Group not found", &[])))?;
    let host = crate::base_url::global(&state).await;

    let fill = |value: &mut String, default: String| {
        if value.is_empty() {
            *value = default;
        }
    };
    if g.welcome_mail_html.is_empty() {
        (g.welcome_mail_html, g.welcome_mail_drag) = default_mail(&state, Kind::Welcome);
    }
    if g.confirm_mail_html.is_empty() {
        (g.confirm_mail_html, g.confirm_mail_drag) = default_mail(&state, Kind::Confirm);
    }
    if g.unsubscribe_mail_html.is_empty() {
        (g.unsubscribe_mail_html, g.unsubscribe_mail_drag) =
            default_mail(&state, Kind::Unsubscribe);
    }
    fill(&mut g.success_url, format!("{host}/subscribe_success.html"));
    fill(&mut g.confirm_url, format!("{host}/subscribe_confirm.html"));
    fill(
        &mut g.already_url,
        format!("{host}/already_subscribed.html"),
    );
    fill(
        &mut g.unsubscribe_redirect_url,
        format!("{host}/unsubscribe_success.html"),
    );
    fill(
        &mut g.subscribe_form,
        subscribe_form_code(&state, &host, &g.token),
    );
    fill(&mut g.welcome_subject, "Welcome Aboard!".to_owned());
    fill(
        &mut g.confirm_subject,
        "Confirm Your Subscription".to_owned(),
    );
    fill(&mut g.unsubscribe_subject, "You're unsubscribed".to_owned());

    let domain = ferropost_store::subscriptions::default_sender_domain(pg)
        .await?
        .unwrap_or_default();
    let subscribe_link = format!("{host}/subscribe_form.html?token={}", g.token);
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Group info retrieved successfully", &[]),
        GroupListItem {
            group: g,
            total_count: 0,
            active_count: 0,
            unsubscribe_count: 0,
            subscribe_link,
            sender: format!("noreply@{domain}"),
        },
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct MergeBody {
    #[serde(default, deserialize_with = "i64_list")]
    source_groups: Vec<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    target_group: Option<i64>,
}

async fn merge(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<MergeBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let sources = validate::id_list("source_groups", &body.source_groups)?;
    let target = validate::id("target_group", body.target_group)?;
    let pg = &state.store.pg;

    if ferropost_store::groups::name(pg, target).await?.is_none() {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "Target group not found",
            &[],
        )));
    }
    let found = ferropost_store::groups::names(pg, &sources).await?;
    if let Some(missing) = sources
        .iter()
        .find(|id| !found.iter().any(|(g, _)| g == *id))
    {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "Source group {} not found",
            &[missing],
        )));
    }

    ferropost_store::groups::merge(pg, &sources, target, now()).await?;
    audit
        .record_with(
            LogType::ContactsGroup,
            "Contact groups merged successfully",
            &body,
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Contact groups merged successfully", &[]),
        (),
    ))
}

#[derive(Serialize)]
struct Total {
    total: i64,
}

/// Distinct subscribed addresses across the groups.
async fn contact_count(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<GroupIdsBody>,
) -> Result<ApiResponse<Total>, ApiError> {
    let group_ids = validate::id_list("group_ids", &body.group_ids)?;
    let total = ferropost_store::groups::active_contact_count(&state.store.pg, &group_ids).await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Successfully retrieved contact count", &[]),
        Total { total },
    ))
}

#[derive(Debug, Deserialize)]
struct TagCountBody {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "i64_list")]
    tag_ids: Vec<i64>,
    #[serde(default)]
    tag_logic: Option<String>,
}

/// Recipients of a group for a tag filter. Without tags this counts every
/// subscribed address; with tags only confirmed ones count, as in Go.
async fn tag_contact_count(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<TagCountBody>,
) -> Result<ApiResponse<Total>, ApiError> {
    let group_id = validate::id("group_id", body.group_id)?;
    let logic = validate::str_one_of("tag_logic", &body.tag_logic, &["AND", "OR", "NOT"])?;
    let logic = TagLogic::parse(logic).ok_or_else(|| anyhow::anyhow!("validated above"))?;
    let pg = &state.store.pg;

    let total = if body.tag_ids.is_empty() {
        ferropost_store::groups::active_contact_count(pg, &[group_id]).await?
    } else {
        let tag_ids = validate::id_list("tag_ids", &body.tag_ids)?;
        ferropost_store::groups::tag_contact_count(pg, group_id, &tag_ids, logic).await?
    };
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Successfully retrieved contact count", &[]),
        Total { total },
    ))
}
