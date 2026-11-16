//! `/api/batch_mail/task/*` and `/api/batch_mail/tracking/*` (Go:
//! `controller/batch_mail`). Served natively only while this process owns
//! the `campaigns` job, since pausing, resuming and the speed act on the
//! sender through the database.
//!
//! Differences from Go: `update` changes only the fields it is given (Go
//! reset `unsubscribe` to 0 when absent, ignored `warmup`, could not clear
//! the tag filter, and crashed without a subject), and rebuilds a campaign's
//! recipients when its tag filter changes before it starts; `speed` works
//! on any campaign (Go needed one sending right now); `send_test` renders
//! the template even for an address that is not a contact (Go sent the raw
//! tags); the list's keyword search no longer bypasses the status filter.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::campaigns::{
    Task, add_unsubscribe_button, emails_per_minute, list_progress, status, unsubscribe_page_url,
};
use ferropost_domain::contacts::is_valid_email;
use ferropost_domain::groups::TagLogic;
use ferropost_domain::paging::Page;
use ferropost_domain::warmup::{PROVIDER_GROUPS, estimated_seconds};
use ferropost_sender::smtp::{Mailer, Outgoing, SmtpConfig, decode_mailbox_password, message_id};
use ferropost_sender::template::{RenderData, Subscriber};
use ferropost_sender::tokens::{UnsubscribeClaims, issue_unsubscribe};
use ferropost_store::campaigns::{
    self as store, Audience, LogFilter, NewTask, NoRecipients, TaskChanges,
};
use serde::{Deserialize, Serialize};

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::campaigns::compose::personalise;
use crate::de::{ApiQuery, opt_i64, opt_string, some_i64_list};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/batch_mail/task/list", get(list))
        .route("/api/batch_mail/task/find", get(find))
        .route("/api/batch_mail/task/create", post(create))
        .route("/api/batch_mail/task/update", post(update))
        .route("/api/batch_mail/task/delete", post(delete))
        .route("/api/batch_mail/task/pause", post(pause))
        .route("/api/batch_mail/task/resume", post(resume))
        .route("/api/batch_mail/task/speed", post(speed))
        .route("/api/batch_mail/task/overview", get(overview))
        .route("/api/batch_mail/task/send_count", get(send_count))
        .route("/api/batch_mail/task/send_test", post(send_test))
        .route("/api/batch_mail/task/stat_chart", get(stat_chart))
        .route("/api/batch_mail/tracking/logs", get(logs))
        .route("/api/batch_mail/tracking/mail_provider", get(mail_provider))
}

async fn load(state: &AppState, lang: &str, id: i32) -> Result<Task, ApiError> {
    store::get(&state.store.pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(lang, "Task not found: {}", &[&id])))
}

fn no_recipients(state: &AppState, lang: &str, why: NoRecipients, group_id: i32) -> ApiError {
    ApiError::Rejected(match why {
        NoRecipients::EmptyGroup => {
            state
                .i18n
                .tr(lang, "No contacts found in group {}", &[&group_id])
        }
        NoRecipients::NoTagMatch => state.i18n.tr(
            lang,
            "No contacts found matching the tag filter criteria",
            &[],
        ),
        NoRecipients::NoneValid => {
            state
                .i18n
                .tr(lang, "No valid contacts found after filtering", &[])
        }
    })
}

// ---- list / find ----------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
}

#[derive(Serialize)]
struct TagInfo {
    id: i32,
    name: String,
    create_time: i32,
}

/// Always empty, as in Go.
#[derive(Serialize, Default)]
struct GroupInfo {
    id: i32,
    name: String,
    description: String,
    count: i32,
}

/// Go's `v1.TaskDetail`.
#[derive(Serialize)]
struct TaskDetail {
    id: i32,
    task_name: String,
    addresser: String,
    subject: String,
    full_name: String,
    recipient_count: i32,
    task_process: i32,
    pause: i32,
    template_id: i32,
    is_record: i32,
    unsubscribe: i32,
    threads: i32,
    track_open: i32,
    track_click: i32,
    start_time: i32,
    create_time: i32,
    update_time: i32,
    remark: String,
    active: i32,
    add_type: i32,
    /// Seconds a warmup campaign still needs; -1 without warmup.
    estimated_time_with_warmup: i64,
    #[serde(rename = "sendsCount")]
    sends_count: i32,
    #[serde(rename = "deliveredCount")]
    delivered_count: i32,
    #[serde(rename = "bouncedCount")]
    bounced_count: i32,
    #[serde(rename = "deferredCount")]
    deferred_count: i32,
    #[serde(rename = "statsUpdateTime")]
    stats_update_time: i32,
    group_id: i32,
    group_name: String,
    tags: Vec<TagInfo>,
    use_tag_filter: i32,
    tag_logic: String,
    groups: GroupInfo,
    sent_count: i32,
    unsent_count: i32,
    progress: i32,
    template_name: String,
    success_count: i32,
    error_count: i32,
    deferred: i32,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<TaskDetail>>, ApiError> {
    let pg = &state.store.pg;
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(10).clamp(1, 1000);
    let status = match q.status {
        None | Some(-1) => None,
        Some(s) => Some(i32::try_from(s).map_err(|_| {
            ApiError::Validation(format!("The status value `{s}` is out of range"))
        })?),
    };
    let (total, mut tasks) = store::list(pg, q.keyword.as_deref(), status, page, page_size).await?;

    let ids: Vec<i32> = tasks.iter().map(|t| t.id).collect();
    let unset: Vec<i32> = tasks
        .iter()
        .filter(|t| t.recipient_count <= 0)
        .map(|t| t.id)
        .collect();
    if !unset.is_empty() {
        let counts = store::repair_recipient_counts(pg, &unset).await?;
        for t in &mut tasks {
            if let Some(n) = counts.get(&t.id) {
                t.recipient_count = *n;
            }
        }
    }
    let group_ids: Vec<i32> = tasks
        .iter()
        .map(|t| t.group_id)
        .filter(|g| *g > 0)
        .collect();
    let template_ids: Vec<i32> = tasks.iter().map(|t| t.template_id).collect();
    let mut tag_ids: Vec<i32> = tasks.iter().flat_map(Task::tag_ids).collect();
    tag_ids.sort_unstable();
    tag_ids.dedup();
    let (groups, templates, tags, warmups) = tokio::try_join!(
        store::group_names(pg, &group_ids),
        store::template_names(pg, &template_ids),
        store::tags(pg, &tag_ids),
        store::warmup_campaigns(pg, &ids),
    )?;

    // Warmup estimates share one set of limits per server IP.
    let mut estimates = std::collections::HashMap::new();
    if !warmups.is_empty()
        && let Some(ip) = crate::edge::server_public_ip(&state).await
    {
        let ip = ip.to_string();
        let now = chrono::Utc::now().timestamp();
        let mut limits = Vec::new();
        for group in PROVIDER_GROUPS {
            limits.push(ferropost_store::warmup::limits(pg, &ip, group, now).await?);
        }
        let unsent = store::unsent_counts(pg, &warmups).await?;
        for id in &warmups {
            let left = unsent.get(id).copied().unwrap_or(0);
            estimates.insert(*id, estimated_seconds(left, limits.iter().copied()));
        }
    }

    let list = tasks
        .into_iter()
        .map(|t| {
            let task_tags = t
                .tag_ids()
                .into_iter()
                .filter_map(|id| tags.iter().find(|(tid, ..)| *tid == id))
                .map(|(id, name, create_time)| TagInfo {
                    id: *id,
                    name: name.clone(),
                    create_time: *create_time,
                })
                .collect();
            TaskDetail {
                estimated_time_with_warmup: estimates.get(&t.id).copied().unwrap_or(-1),
                group_name: groups.get(&t.group_id).cloned().unwrap_or_default(),
                template_name: templates.get(&t.template_id).cloned().unwrap_or_default(),
                tags: task_tags,
                groups: GroupInfo::default(),
                sent_count: t.sends_count,
                unsent_count: (t.recipient_count - t.sends_count).max(0),
                progress: list_progress(t.sends_count, t.recipient_count),
                success_count: t.delivered_count,
                error_count: t.bounced_count + t.deferred_count,
                deferred: t.deferred_count,
                use_tag_filter: 0,
                id: t.id,
                task_name: t.task_name,
                addresser: t.addresser,
                subject: t.subject,
                full_name: t.full_name,
                recipient_count: t.recipient_count,
                task_process: t.task_process,
                pause: t.pause,
                template_id: t.template_id,
                is_record: t.is_record,
                unsubscribe: t.unsubscribe,
                threads: t.threads,
                track_open: t.track_open,
                track_click: t.track_click,
                start_time: t.start_time,
                create_time: t.create_time,
                update_time: t.update_time,
                remark: t.remark,
                active: t.active,
                add_type: t.add_type,
                sends_count: t.sends_count,
                delivered_count: t.delivered_count,
                bounced_count: t.bounced_count,
                deferred_count: t.deferred_count,
                stats_update_time: t.stats_update_time,
                group_id: t.group_id,
                tag_logic: t.tag_logic,
            }
        })
        .collect();
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Task list retrieved successfully", &[]),
        Page { total, list },
    ))
}

/// Go's `entity.EmailTask` JSON.
#[derive(Serialize)]
struct TaskInfo {
    id: i32,
    task_name: String,
    addresser: String,
    subject: String,
    full_name: String,
    recipient_count: i32,
    task_process: i32,
    pause: i32,
    template_id: i32,
    is_record: i32,
    unsubscribe: i32,
    threads: i32,
    track_open: i32,
    track_click: i32,
    start_time: i32,
    create_time: i32,
    update_time: i32,
    remark: String,
    active: i32,
    #[serde(rename = "addType")]
    add_type: i32,
    #[serde(rename = "sendsCount")]
    sends_count: i32,
    #[serde(rename = "deliveredCount")]
    delivered_count: i32,
    #[serde(rename = "bouncedCount")]
    bounced_count: i32,
    #[serde(rename = "deferredCount")]
    deferred_count: i32,
    #[serde(rename = "statsUpdateTime")]
    stats_update_time: i32,
    group_id: i32,
    tag_ids: Vec<i32>,
    tag_logic: String,
    use_tag_filter: i32,
}

impl From<Task> for TaskInfo {
    fn from(t: Task) -> Self {
        Self {
            tag_ids: t.tag_ids(),
            id: t.id,
            task_name: t.task_name,
            addresser: t.addresser,
            subject: t.subject,
            full_name: t.full_name,
            recipient_count: t.recipient_count,
            task_process: t.task_process,
            pause: t.pause,
            template_id: t.template_id,
            is_record: t.is_record,
            unsubscribe: t.unsubscribe,
            threads: t.threads,
            track_open: t.track_open,
            track_click: t.track_click,
            start_time: t.start_time,
            create_time: t.create_time,
            update_time: t.update_time,
            remark: t.remark,
            active: t.active,
            add_type: t.add_type,
            sends_count: t.sends_count,
            delivered_count: t.delivered_count,
            bounced_count: t.bounced_count,
            deferred_count: t.deferred_count,
            stats_update_time: t.stats_update_time,
            group_id: t.group_id,
            tag_logic: t.tag_logic,
            use_tag_filter: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
struct IdQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
}

async fn find(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<IdQuery>,
) -> Result<ApiResponse<TaskInfo>, ApiError> {
    let id = validate::id("id", q.id)?;
    let task = load(&state, &lang, id).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        task.into(),
    ))
}

// ---- create / update / delete --------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct CreateBody {
    #[serde(default, deserialize_with = "opt_string")]
    addresser: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    subject: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    full_name: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    template_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    is_record: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    unsubscribe: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    threads: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    track_open: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    track_click: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    warmup: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    remark: Option<String>,
    #[serde(default, deserialize_with = "some_i64_list")]
    tag_ids: Option<Vec<i64>>,
    #[serde(default, deserialize_with = "opt_string")]
    tag_logic: Option<String>,
}

const FLAG: &[i64] = &[0, 1];

fn tag_ids(values: &[i64]) -> Result<Vec<i32>, ApiError> {
    let mut ids = Vec::new();
    for v in values {
        let id = validate::id("tag_ids", Some(*v))?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn int_field(field: &str, value: i64) -> Result<i32, ApiError> {
    i32::try_from(value)
        .map_err(|_| ApiError::Validation(format!("The {field} value `{value}` is out of range")))
}

/// Ties a campaign to the warmup of this server's IP, as Go did (failures
/// are only logged).
async fn link_warmup(state: &AppState, task_id: i32) {
    let Some(ip) = crate::edge::server_public_ip(state).await else {
        tracing::warn!(task_id, "warmup requested but the server IP is unknown");
        return;
    };
    let pg = &state.store.pg;
    let linked = async {
        let rec = ferropost_store::warmup::ip_or_start(
            pg,
            &ip.to_string(),
            chrono::Utc::now().timestamp(),
        )
        .await?;
        store::associate_warmup(pg, task_id, rec.id).await
    };
    if let Err(err) = linked.await {
        tracing::warn!(task_id, error = %format!("{err:#}"), "linking the campaign to warmup failed");
    }
}

#[derive(Serialize)]
struct Created {
    id: i32,
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<CreateBody>,
) -> Result<ApiResponse<Created>, ApiError> {
    let addresser = validate::required("addresser", &body.addresser)?;
    let subject = validate::required("subject", &body.subject)?;
    let template_id = validate::id("template_id", body.template_id)?;
    let group_id = body
        .group_id
        .ok_or_else(|| ApiError::Validation("The group_id field is required".to_owned()))?;
    let start_time = body
        .start_time
        .ok_or_else(|| ApiError::Validation("The start_time field is required".to_owned()))?;
    let is_record = validate::optional_one_of("is_record", body.is_record, FLAG, 1)?;
    let unsubscribe = validate::optional_one_of("unsubscribe", body.unsubscribe, FLAG, 1)?;
    let track_open = validate::optional_one_of("track_open", body.track_open, FLAG, 1)?;
    let track_click = validate::optional_one_of("track_click", body.track_click, FLAG, 1)?;
    let warmup = validate::optional_one_of("warmup", body.warmup, FLAG, 0)?;
    let threads = body.threads.unwrap_or(5);
    if threads < 0 {
        return Err(ApiError::Validation(format!(
            "The threads value `{threads}` must be equal or greater than 0"
        )));
    }
    validate::optional_str_in("tag_logic", &body.tag_logic, &["AND", "OR", "NOT"])?;
    let tag_logic = body
        .tag_logic
        .clone()
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "AND".to_owned());
    let tag_ids = tag_ids(body.tag_ids.as_deref().unwrap_or_default())?;
    if group_id <= 0 {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Must select a contact group",
            &[],
        )));
    }
    let group_id = int_field("group_id", group_id)?;
    let pg = &state.store.pg;
    if ferropost_store::templates::get(pg, template_id)
        .await?
        .is_none()
    {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Template not found",
            &[],
        )));
    }

    let created = store::create(
        pg,
        &NewTask {
            addresser,
            subject,
            full_name: body.full_name.as_deref().unwrap_or_default(),
            template_id,
            is_record: is_record as i32,
            unsubscribe: unsubscribe as i32,
            threads: int_field("threads", threads)?,
            track_open: track_open as i32,
            track_click: track_click as i32,
            start_time: int_field("start_time", start_time)?,
            remark: body.remark.as_deref().unwrap_or_default(),
            tag_logic: &tag_logic,
            audience: Audience {
                group_id,
                tag_ids: &tag_ids,
                tag_logic: TagLogic::parse(&tag_logic).unwrap_or(TagLogic::All),
            },
            now: now(),
        },
        is_valid_email,
    )
    .await?;
    let id = created.map_err(|why| no_recipients(&state, &lang, why, group_id))?;
    if warmup == 1 {
        link_warmup(&state, id).await;
    }
    audit
        .record_with(
            LogType::Task,
            &format!("Create task :{subject} successfully"),
            &body,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Task created successfully", &[]),
        Created { id },
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateBody {
    #[serde(default, deserialize_with = "opt_i64")]
    task_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    addresser: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    subject: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    full_name: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    remark: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    template_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    unsubscribe: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    warmup: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    threads: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "some_i64_list")]
    tag_ids: Option<Vec<i64>>,
    #[serde(default, deserialize_with = "opt_string")]
    tag_logic: Option<String>,
}

async fn update(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<UpdateBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("task_id", body.task_id)?;
    let pg = &state.store.pg;
    let task = store::get(pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "The task does not exist.", &[])))?;
    if task.is_running() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "The task is currently running. Please pause the task first.",
            &[],
        )));
    }
    if let Some(v) = body.unsubscribe {
        validate::one_of("unsubscribe", Some(v), FLAG)?;
    }
    if let Some(v) = body.warmup {
        validate::one_of("warmup", Some(v), FLAG)?;
    }
    if let Some(t) = body.threads
        && t < 0
    {
        return Err(ApiError::Validation(format!(
            "The threads value `{t}` must be equal or greater than 0"
        )));
    }
    validate::optional_str_in("tag_logic", &body.tag_logic, &["AND", "OR", "NOT"])?;

    let non_empty = |v: &Option<String>| v.clone().filter(|s| !s.trim().is_empty());
    let changes = TaskChanges {
        addresser: non_empty(&body.addresser),
        subject: non_empty(&body.subject),
        full_name: non_empty(&body.full_name),
        remark: non_empty(&body.remark),
        template_id: body
            .template_id
            .filter(|t| *t > 0)
            .map(|t| int_field("template_id", t))
            .transpose()?,
        unsubscribe: body.unsubscribe.map(|v| v as i32),
        threads: body
            .threads
            .filter(|t| *t > 0)
            .map(|t| int_field("threads", t))
            .transpose()?,
        start_time: body
            .start_time
            .filter(|t| *t > 0)
            .map(|t| int_field("start_time", t))
            .transpose()?,
        tag_ids: body.tag_ids.as_deref().map(tag_ids).transpose()?,
        tag_logic: non_empty(&body.tag_logic),
    };
    let nothing = changes.addresser.is_none()
        && changes.subject.is_none()
        && changes.full_name.is_none()
        && changes.remark.is_none()
        && changes.template_id.is_none()
        && changes.unsubscribe.is_none()
        && changes.threads.is_none()
        && changes.start_time.is_none()
        && changes.tag_ids.is_none()
        && changes.tag_logic.is_none()
        && body.warmup.is_none();
    if nothing {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "No valid update fields",
            &[],
        )));
    }
    if let Some(template_id) = changes.template_id
        && ferropost_store::templates::get(pg, template_id)
            .await?
            .is_none()
    {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Template not found",
            &[],
        )));
    }
    store::update(pg, &task, &changes, is_valid_email, now())
        .await?
        .map_err(|why| no_recipients(&state, &lang, why, task.group_id))?;
    match body.warmup {
        Some(1) => link_warmup(&state, id).await,
        Some(0) => store::dissociate_warmup(pg, id).await?,
        _ => {}
    }

    let subject = changes.subject.as_deref().unwrap_or(&task.subject);
    audit
        .record_with(
            LogType::Task,
            &format!("Update Task Info :{subject} successfully"),
            &body,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Task update successful", &[]),
        (),
    ))
}

#[derive(Debug, Deserialize)]
struct IdBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<IdBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let task = load(&state, &lang, id).await?;
    store::delete(&state.store.pg, id).await?;
    let info = TaskInfo::from(task);
    audit
        .record_with(
            LogType::Task,
            &format!("Delete task :{} successfully", info.subject),
            &info,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Task deleted successfully", &[]),
        (),
    ))
}

// ---- pause / resume / speed ----------------------------------------------

#[derive(Debug, Deserialize)]
struct TaskBody {
    #[serde(default, deserialize_with = "opt_i64")]
    task_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    threads: Option<i64>,
}

fn state_text(task_process: i32) -> &'static str {
    match task_process {
        status::NOT_STARTED => "not started",
        status::COMPLETED => "already completed",
        _ => "in unknown state",
    }
}

async fn pause(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<TaskBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("task_id", body.task_id)?;
    let task = load(&state, &lang, id).await?;
    if task.pause == 1 {
        return Ok(ApiResponse::ok(
            state.i18n.tr(&lang, "Task is already paused", &[]),
            (),
        ));
    }
    if task.task_process != status::RUNNING {
        let why = state.i18n.tr(&lang, state_text(task.task_process), &[]);
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Cannot pause task because it is {}",
            &[&why],
        )));
    }
    store::set_paused(&state.store.pg, id, true).await?;
    let info = TaskInfo::from(task);
    audit
        .record_with(
            LogType::Task,
            &format!("Pause Task :{} successfully", info.subject),
            &info,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Task paused successfully", &[]),
        (),
    ))
}

async fn resume(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<TaskBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("task_id", body.task_id)?;
    let task = load(&state, &lang, id).await?;
    if task.task_process != status::RUNNING && task.task_process != status::PAUSED {
        let why = state.i18n.tr(&lang, state_text(task.task_process), &[]);
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Cannot resume task because it is {}",
            &[&why],
        )));
    }
    if task.pause == 0 {
        return Ok(ApiResponse::ok(
            state.i18n.tr(&lang, "Task is already running", &[]),
            (),
        ));
    }
    // The sender picks the campaign up within seconds.
    store::set_paused(&state.store.pg, id, false).await?;
    let info = TaskInfo::from(task);
    audit
        .record_with(
            LogType::Task,
            &format!("Resumed Task :{} successfully", info.subject),
            &info,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Task resumed successfully", &[]),
        (),
    ))
}

#[derive(Serialize)]
struct Speed {
    task_id: i32,
    threads: i32,
    emails_per_minute: i64,
}

async fn speed(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<TaskBody>,
) -> Result<ApiResponse<Speed>, ApiError> {
    let id = validate::id("task_id", body.task_id)?;
    let threads = body
        .threads
        .ok_or_else(|| ApiError::Validation("The threads field is required".to_owned()))?;
    if threads <= 0 {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Threads must be greater than zero",
            &[],
        )));
    }
    if threads > 100 {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Threads cannot exceed 100",
            &[],
        )));
    }
    let threads = threads as i32;
    load(&state, &lang, id).await?;
    // The sender reads the new value before its next batch.
    store::set_threads(&state.store.pg, id, threads).await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Task sending speed updated successfully", &[]),
        Speed {
            task_id: id,
            threads,
            emails_per_minute: emails_per_minute(threads),
        },
    ))
}

// ---- statistics -------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RangeQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    end_time: Option<i64>,
}

#[derive(Serialize)]
struct Summary {
    sends: i64,
    delivered: i64,
    bounced: i64,
    opened: i64,
    clicked: i64,
    delivery_rate: f64,
    bounce_rate: f64,
    open_rate: f64,
    click_rate: f64,
}

/// Sending totals over all mail in a window. Go read opens and clicks for
/// the window `[0, 0]` when no times were given, so both were always 0.
async fn overview(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<RangeQuery>,
) -> Result<ApiResponse<Summary>, ApiError> {
    use ferropost_domain::overview::rate;
    let start = q.start_time.unwrap_or(0);
    let mut end = q.end_time.unwrap_or(0);
    if start > 0 && end < 0 {
        end = chrono::Utc::now().timestamp();
    }
    let (sends, delivered, bounced, opened, clicked) =
        store::sending_summary(&state.store.pg, start, end).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        Summary {
            sends,
            delivered,
            bounced,
            opened,
            clicked,
            delivery_rate: rate(delivered, sends),
            bounce_rate: rate(bounced, sends),
            open_rate: rate(opened, sends),
            click_rate: rate(clicked, sends),
        },
    ))
}

#[derive(Debug, Deserialize)]
struct SendCountQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    task_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    end_time: Option<i64>,
}

#[derive(Serialize)]
struct MinuteCount {
    minute: i64,
    send_count: i64,
    start_time: i64,
    end_time: i64,
}

#[derive(Serialize)]
struct SendCount {
    task_id: i32,
    start_time: i64,
    end_time: i64,
    total_sent: i64,
    max_per_minute: i64,
    avg_per_minute: f64,
    minute_details: Vec<MinuteCount>,
}

async fn send_count(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<SendCountQuery>,
) -> Result<ApiResponse<SendCount>, ApiError> {
    let id = match q.task_id {
        Some(id) if id > 0 => int_field("task_id", id)?,
        _ => {
            return Err(ApiError::Rejected(state.i18n.tr(
                &lang,
                "Invalid task ID",
                &[],
            )));
        }
    };
    load(&state, &lang, id).await?;
    let now = chrono::Utc::now().timestamp();
    let start = q.start_time.filter(|t| *t > 0).unwrap_or(now - 86_400);
    let end = q.end_time.filter(|t| *t > 0).unwrap_or(now);
    let minutes = store::sends_per_minute(&state.store.pg, id, start, end).await?;
    let total: i64 = minutes.iter().map(|(_, n)| n).sum();
    let max = minutes.iter().map(|(_, n)| *n).max().unwrap_or(0);
    let avg = if minutes.is_empty() {
        0.0
    } else {
        total as f64 / minutes.len() as f64
    };
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Get task send count successfully", &[]),
        SendCount {
            task_id: id,
            start_time: start,
            end_time: end,
            total_sent: total,
            max_per_minute: max,
            avg_per_minute: avg,
            minute_details: minutes
                .into_iter()
                .map(|(minute, send_count)| MinuteCount {
                    minute,
                    send_count,
                    start_time: minute,
                    end_time: minute + 60,
                })
                .collect(),
        },
    ))
}

#[derive(Debug, Deserialize)]
struct StatQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    task_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    end_time: Option<i64>,
}

/// The dashboard (`/api/overview`) for one campaign.
async fn stat_chart(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<StatQuery>,
) -> Result<ApiResponse<super::overview::Overview>, ApiError> {
    let id = validate::id("task_id", q.task_id)?;
    let scope = super::overview::scope(super::overview::OverviewQuery {
        campaign_id: Some(id.into()),
        domain: q.domain,
        start_time: q.start_time,
        end_time: q.end_time,
    })?;
    load(&state, &lang, id).await?;
    let data = super::overview::build(&state, &scope).await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Task statistics retrieved successfully", &[]),
        data,
    ))
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    task_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
}

/// Delivery attempts of a campaign's mail: `status` 1 delivered, 0 (the
/// default, as in Go) bounced, anything else all.
async fn logs(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<LogsQuery>,
) -> Result<ApiResponse<Page<store::DeliveryLog>>, ApiError> {
    let id = validate::id("task_id", q.task_id)?;
    let task = load(&state, &lang, id).await?;
    let now = chrono::Utc::now().timestamp();
    let start = if task.start_time > 0 {
        i64::from(task.start_time)
    } else {
        now - 86_400
    };
    let page = q.page.filter(|p| *p > 0).unwrap_or(1);
    let page_size = q.page_size.filter(|p| *p > 0).unwrap_or(20).min(1000);
    let (total, list) = store::delivery_log(
        &state.store.pg,
        &LogFilter {
            task_id: id,
            outcome: q.status.unwrap_or(0),
            domain: q.domain.as_deref(),
            start,
            end: now,
        },
        page,
        page_size,
    )
    .await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Task mail logs retrieved successfully", &[]),
        Page { total, list },
    ))
}

#[derive(Debug, Deserialize)]
struct ProviderQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    task_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    status: Option<i64>,
}

#[derive(Serialize)]
struct DomainCount {
    domain: String,
    count: i64,
}

async fn mail_provider(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ProviderQuery>,
) -> Result<ApiResponse<Vec<DomainCount>>, ApiError> {
    let id = validate::id("task_id", q.task_id)?;
    load(&state, &lang, id).await?;
    let rows = store::deliveries_by_domain(&state.store.pg, id, q.status.unwrap_or(0)).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        rows.into_iter()
            .map(|(domain, count)| DomainCount { domain, count })
            .collect(),
    ))
}

// ---- test mail ----------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct TestBody {
    #[serde(default, deserialize_with = "opt_string")]
    addresser: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    subject: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    recipient: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    template_id: Option<i64>,
}

async fn send_test(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<TestBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let addresser = validate::required("addresser", &body.addresser)?;
    let subject = validate::required("subject", &body.subject)?;
    let recipient = validate::required("recipient", &body.recipient)?;
    let template_id = validate::id("template_id", body.template_id)?;
    if !is_valid_email(recipient) {
        return Err(ApiError::Validation(format!(
            "The recipient value `{recipient}` is not a valid email address"
        )));
    }
    let pg = &state.store.pg;
    let sender_failed = |why: String| {
        ApiError::Rejected(
            state
                .i18n
                .tr(&lang, "create email sender failed: : {}", &[&why]),
        )
    };
    let encoded = ferropost_store::mailboxes::encoded_password(pg, addresser)
        .await?
        .ok_or_else(|| sender_failed(format!("password not found for {addresser}")))?;
    let password = decode_mailbox_password(&encoded).map_err(|e| sender_failed(e.to_string()))?;
    let template = ferropost_store::templates::get(pg, template_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "Template not found", &[])))?;

    let content = add_unsubscribe_button(&template.content)
        .replace("__UNSUBSCRIBE_URL__", "{{ UnsubscribeURL . }}");
    let base = crate::base_url::global(&state).await;
    let keys = state.token_keys().await?;
    let jwt = issue_unsubscribe(
        &keys,
        UnsubscribeClaims {
            email: recipient.to_owned(),
            template_id: template_id.into(),
            task_id: 0,
            group_id: 0,
        },
        chrono::Utc::now().timestamp(),
    );
    let subscriber = match ferropost_store::subscriptions::first_contact(pg, recipient).await? {
        Some((attribs, active, status)) => {
            Subscriber::from_contact(recipient, &attribs, active, status)
        }
        None => Subscriber {
            email: recipient.to_owned(),
            ..Subscriber::default()
        },
    };
    let data = RenderData {
        subscriber: Some(subscriber),
        unsubscribe_url: unsubscribe_page_url(&base, &jwt, recipient, 0),
        ..RenderData::default()
    };
    let mut rng = rand::rngs::OsRng;
    let html = personalise(&content, &data, &mut rng);
    let rendered_subject = personalise(subject, &data, &mut rng);

    let mailer = Mailer::new(&SmtpConfig {
        host: state.config.smtp_host.clone(),
        port: state.config.smtp_port,
        username: addresser.to_owned(),
        password,
    })
    .map_err(|e| sender_failed(format!("{e:#}")))?;
    mailer
        .send(&Outgoing {
            message_id: message_id(addresser),
            from_email: addresser.to_owned(),
            from_name: None,
            to: vec![recipient.to_owned()],
            subject: rendered_subject.clone(),
            html,
            headers: Vec::new(),
        })
        .await
        .map_err(|e| {
            ApiError::Rejected(state.i18n.tr(
                &lang,
                "send email to {} failed: {}",
                &[&recipient, &format!("{e:#}")],
            ))
        })?;
    audit
        .record(
            LogType::Task,
            &format!("Send test email :{rendered_subject}to{recipient} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "send email successfully", &[]),
        (),
    ))
}
