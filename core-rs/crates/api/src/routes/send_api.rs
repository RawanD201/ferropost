//! `/api/batch_mail/api/*` (Go: `controller/batch_mail` `api_*`): managing
//! send-API keys (console) and queueing mail with one (`send`,
//! `batch_send`, public, authenticated by the `x-api-key` header).
//!
//! Differences from Go: an expired key (`expire_time` seconds after it was
//! issued) is refused, and `reset_key` issues a new key (Go ignored both);
//! a different sender must be on the API's own domain (Go let a key send
//! as any mailbox on the server); addresses are validated and people who
//! unsubscribed from the API's group are not mailed (Go mailed them when
//! the API had its own group); `update` keeps settings it is not given;
//! stats are computed in a few queries over the chosen window.

use axum::Extension;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::contacts::is_valid_email;
use ferropost_domain::overview::rate;
use ferropost_domain::paging::Page;
use ferropost_domain::send_api::{clean_whitelist, code, key_valid, sender_allowed};
use ferropost_store::send_api::{self as store, ApiKey, ApiSettings};
use serde::{Deserialize, Serialize};

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::conn::ClientIp;
use crate::de::{ApiQuery, opt_bool, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

/// Console routes, behind login.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/batch_mail/api/list", get(list))
        .route("/api/batch_mail/api/overview_stats", get(overview_stats))
        .route("/api/batch_mail/api/create", post(create))
        .route("/api/batch_mail/api/update", post(update))
        .route("/api/batch_mail/api/delete", post(delete))
}

/// Routes other systems call with an API key.
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/batch_mail/api/send", post(send))
        .route("/api/batch_mail/api/batch_send", post(batch_send))
}

// ---- console -----------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    end_time: Option<i64>,
}

#[derive(Serialize)]
struct ApiInfo {
    #[serde(flatten)]
    api: ApiKey,
    send_count: i64,
    success_count: i64,
    fail_count: i64,
    open_rate: f64,
    click_rate: f64,
    delivery_rate: f64,
    bounce_rate: f64,
    ip_whitelist: Vec<String>,
    server_addresser: String,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<ApiInfo>>, ApiError> {
    let pg = &state.store.pg;
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(10).clamp(1, 1000);
    let active = match q.active {
        None | Some(-1) => None,
        Some(a) => Some(a as i32),
    };
    let (total, apis) = store::list(pg, q.keyword.as_deref(), active, page, page_size).await?;
    let ids: Vec<i32> = apis.iter().map(|a| a.id).collect();
    let stats = store::stats(pg, &ids, q.start_time.unwrap_or(0), q.end_time.unwrap_or(0)).await?;
    let mut whitelists = store::whitelists(pg, &ids).await?;
    let server = format!(
        "{}/api/batch_mail/api/send",
        crate::base_url::global(&state).await
    );
    let list = apis
        .into_iter()
        .map(|api| {
            let s = stats.get(&api.id).copied().unwrap_or_default();
            ApiInfo {
                ip_whitelist: whitelists.remove(&api.id).unwrap_or_default(),
                server_addresser: server.clone(),
                send_count: s.sends,
                success_count: s.delivered,
                fail_count: s.bounced,
                // Go divided opens and clicks by sends here too.
                open_rate: rate(s.opened, s.sends),
                click_rate: rate(s.clicked, s.sends),
                delivery_rate: rate(s.delivered, s.sends),
                bounce_rate: rate(s.bounced, s.sends),
                api,
            }
        })
        .collect();
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Get API list successfully", &[]),
        Page { total, list },
    ))
}

#[derive(Debug, Deserialize)]
struct RangeQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    end_time: Option<i64>,
}

#[derive(Serialize)]
struct Summary {
    total_send: i64,
    avg_delivery_rate: f64,
    avg_open_rate: f64,
    avg_click_rate: f64,
    avg_bounce_rate: f64,
}

async fn overview_stats(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<RangeQuery>,
) -> Result<ApiResponse<Summary>, ApiError> {
    let pg = &state.store.pg;
    let ids = store::all_ids(pg).await?;
    let stats = store::stats(pg, &ids, q.start_time.unwrap_or(0), q.end_time.unwrap_or(0)).await?;
    let t = stats.values().fold(store::ApiStats::default(), |mut t, s| {
        t.sends += s.sends;
        t.delivered += s.delivered;
        t.bounced += s.bounced;
        t.opened += s.opened;
        t.clicked += s.clicked;
        t
    });
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Statistics successful", &[]),
        Summary {
            total_send: t.sends,
            avg_delivery_rate: rate(t.delivered, t.sends),
            avg_open_rate: rate(t.opened, t.sends),
            avg_click_rate: rate(t.clicked, t.sends),
            avg_bounce_rate: rate(t.bounced, t.sends),
        },
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct SettingsBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    api_name: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    template_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    subject: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    addresser: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    full_name: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    unsubscribe: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    track_open: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    track_click: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    expire_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_bool")]
    reset_key: Option<bool>,
    #[serde(default)]
    ip_whitelist: Option<Vec<String>>,
}

const FLAG: &[i64] = &[0, 1];

/// Checks the settings, filling absent ones from `current` (or Go's
/// defaults for a new API).
async fn settings<'a>(
    state: &AppState,
    lang: &str,
    body: &'a SettingsBody,
    current: Option<&'a ApiKey>,
    whitelist: &'a [String],
) -> Result<ApiSettings<'a>, ApiError> {
    let text = |field: &str,
                value: &'a Option<String>,
                keep: Option<&'a str>|
     -> Result<&'a str, ApiError> {
        match (
            value.as_deref().map(str::trim).filter(|v| !v.is_empty()),
            keep,
        ) {
            (Some(v), _) => Ok(v),
            (None, Some(k)) => Ok(k),
            (None, None) => Err(ApiError::Validation(format!(
                "The {field} field is required"
            ))),
        }
    };
    let flag = |field: &str, value: Option<i64>, keep: Option<i32>, default: i64| {
        validate::optional_one_of(field, value, FLAG, keep.map_or(default, i64::from))
            .map(|v| v as i32)
    };
    let template_id = match (body.template_id, current) {
        (Some(id), _) => validate::id("template_id", Some(id))?,
        (None, Some(c)) => c.template_id,
        (None, None) => validate::id("template_id", None)?,
    };
    if ferropost_store::templates::get(&state.store.pg, template_id)
        .await?
        .is_none()
    {
        return Err(ApiError::Rejected(state.i18n.tr(
            lang,
            "Email template does not exist",
            &[],
        )));
    }
    let addresser = text(
        "addresser",
        &body.addresser,
        current.map(|c| c.addresser.as_str()),
    )?;
    if !is_valid_email(addresser) {
        return Err(ApiError::Validation(format!(
            "The addresser value `{addresser}` is not a valid email address"
        )));
    }
    Ok(ApiSettings {
        api_name: text(
            "api_name",
            &body.api_name,
            current.map(|c| c.api_name.as_str()),
        )?,
        template_id,
        group_id: body
            .group_id
            .map(|g| g.max(0) as i32)
            .or(current.map(|c| c.group_id))
            .unwrap_or(0),
        subject: text(
            "subject",
            &body.subject,
            current.map(|c| c.subject.as_str()),
        )?,
        addresser,
        full_name: body
            .full_name
            .as_deref()
            .or(current.map(|c| c.full_name.as_str()))
            .unwrap_or_default(),
        unsubscribe: flag(
            "unsubscribe",
            body.unsubscribe,
            current.map(|c| c.unsubscribe),
            0,
        )?,
        track_open: flag(
            "track_open",
            body.track_open,
            current.map(|c| c.track_open),
            1,
        )?,
        track_click: flag(
            "track_click",
            body.track_click,
            current.map(|c| c.track_click),
            1,
        )?,
        active: flag("active", body.active, current.map(|c| c.active), 0)?,
        expire_time: body
            .expire_time
            .map(|e| e.clamp(0, i64::from(i32::MAX)) as i32)
            .or(current.map(|c| c.expire_time))
            .unwrap_or(0),
        ip_whitelist: whitelist,
    })
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<SettingsBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let whitelist = clean_whitelist(body.ip_whitelist.as_deref().unwrap_or_default());
    let mut s = settings(&state, &lang, &body, None, &whitelist).await?;
    // Go ignored a given expiry on creation.
    s.expire_time = 0;
    let key = ferropost_sender::tokens::new_secret();
    store::create(&state.store.pg, &s, &key, now()).await?;
    audit
        .record_with(
            LogType::SendApi,
            &format!("Create API template :{} successfully", s.api_name),
            &body,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Create API successfully", &[]),
        (),
    ))
}

async fn update(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<SettingsBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = validate::id("id", body.id)?;
    let pg = &state.store.pg;
    let current = store::get(pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "API does not exist", &[])))?;
    let whitelist = match &body.ip_whitelist {
        Some(ips) => clean_whitelist(ips),
        None => store::whitelists(pg, &[id])
            .await?
            .remove(&id)
            .unwrap_or_default(),
    };
    let s = settings(&state, &lang, &body, Some(&current), &whitelist).await?;
    let new_key = body
        .reset_key
        .unwrap_or(false)
        .then(ferropost_sender::tokens::new_secret);
    store::update(pg, id, &s, new_key.as_deref(), now()).await?;
    audit
        .record_with(
            LogType::SendApi,
            &format!("Update API template :{} successfully", s.api_name),
            &body,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Update API successfully", &[]),
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
    let api = store::delete(&state.store.pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "API does not exist", &[])))?;
    audit
        .record_with(
            LogType::SendApi,
            &format!("Delete API template :{} successfully", api.api_name),
            &api,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Delete API successfully", &[]),
        (),
    ))
}

// ---- sending -------------------------------------------------------------------

/// Checks the key, the caller's IP and the template; returns the API.
async fn authorize(
    state: &AppState,
    lang: &str,
    headers: &HeaderMap,
    ip: ClientIp,
) -> Result<ApiKey, ApiError> {
    let tr = |msg: &str| state.i18n.tr(lang, msg, &[]);
    let pg = &state.store.pg;
    let key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    let api = match store::by_key(pg, key).await? {
        Some(api)
            if !key.is_empty()
                && key_valid(
                    api.expire_time.into(),
                    api.last_key_update_time.into(),
                    chrono::Utc::now().timestamp(),
                ) =>
        {
            api
        }
        _ => return Err(ApiError::Coded(code::INVALID_KEY, tr("API key is invalid"))),
    };
    if !store::ip_allowed(pg, api.id, &ip.0.to_canonical().to_string()).await? {
        return Err(ApiError::Coded(code::IP_NOT_ALLOWED, tr("IP not allowed")));
    }
    if ferropost_store::templates::get(pg, api.template_id)
        .await?
        .is_none()
    {
        return Err(ApiError::Coded(
            code::NO_TEMPLATE,
            tr("Email template does not exist"),
        ));
    }
    Ok(api)
}

/// The sender to use: the API's own, or another mailbox on its domain.
async fn sender(
    state: &AppState,
    lang: &str,
    api: &ApiKey,
    requested: &Option<String>,
) -> Result<String, ApiError> {
    let addresser = requested
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .unwrap_or(&api.addresser)
        .to_owned();
    if !sender_allowed(&api.addresser, &addresser) {
        return Err(ApiError::Coded(
            code::NOT_QUEUED,
            state.i18n.tr(
                lang,
                "The addresser must be on the API's sending domain",
                &[],
            ),
        ));
    }
    if ferropost_store::mailboxes::encoded_password(&state.store.pg, &addresser)
        .await?
        .is_none()
    {
        let why = format!("password not found for {addresser}");
        return Err(ApiError::Coded(
            code::NOT_QUEUED,
            state
                .i18n
                .tr(lang, "Failed to create email sender: {}", &[&why]),
        ));
    }
    Ok(addresser)
}

/// Custom properties as Go stored them: text values.
fn attributes(raw: &Option<serde_json::Map<String, serde_json::Value>>) -> serde_json::Value {
    serde_json::Value::Object(
        raw.iter()
            .flatten()
            .map(|(k, v)| {
                let text = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
                (k.clone(), serde_json::Value::String(text))
            })
            .collect(),
    )
}

/// Adds the recipients to the API's group and queues mail for those who
/// may get it; returns how many were queued.
async fn queue(
    state: &AppState,
    lang: &str,
    api: &ApiKey,
    addresser: &str,
    recipients: &[String],
    attribs: &serde_json::Value,
) -> Result<u64, ApiError> {
    let pg = &state.store.pg;
    let description = state
        .i18n
        .tr(lang, "API %d automatically created contact group", &[])
        .replace("%d", &api.id.to_string());
    let group = store::recipient_group(pg, api, &description, now()).await?;
    let accepted = store::accept_recipients(pg, group, recipients, now()).await?;
    let messages: Vec<(String, String)> = accepted
        .into_iter()
        .map(|r| {
            let id = ferropost_sender::smtp::message_id(addresser);
            (r, id.trim_matches(['<', '>']).to_owned())
        })
        .collect();
    let queued = store::enqueue(pg, api.id, addresser, &messages, attribs, now()).await?;
    if queued > 0 {
        state.api_mail_queued.notify_one();
    }
    Ok(queued)
}

#[derive(Debug, Deserialize)]
struct SendBody {
    #[serde(default, deserialize_with = "opt_string")]
    addresser: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    recipient: Option<String>,
    #[serde(default)]
    attribs: Option<serde_json::Map<String, serde_json::Value>>,
}

async fn send(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Extension(ip): Extension<ClientIp>,
    headers: HeaderMap,
    ApiBody(body): ApiBody<SendBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let api = authorize(&state, &lang, &headers, ip).await?;
    let recipient = body.recipient.as_deref().map(str::trim).unwrap_or_default();
    if !is_valid_email(recipient) {
        return Err(ApiError::Coded(
            code::BAD_RECIPIENT,
            state.i18n.tr(&lang, "Invalid recipient", &[]),
        ));
    }
    let addresser = sender(&state, &lang, &api, &body.addresser).await?;
    let queued = queue(
        &state,
        &lang,
        &api,
        &addresser,
        &[recipient.to_owned()],
        &attributes(&body.attribs),
    )
    .await?;
    if queued == 0 {
        let why = "the recipient has unsubscribed from the current group and cannot send";
        return Err(ApiError::Coded(
            code::BAD_RECIPIENT,
            state
                .i18n
                .tr(&lang, "Failed to process recipient: {}", &[&why]),
        ));
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Email sent successfully", &[]),
        (),
    ))
}

#[derive(Debug, Deserialize)]
struct BatchBody {
    #[serde(default, deserialize_with = "opt_string")]
    addresser: Option<String>,
    #[serde(default)]
    recipients: Option<Vec<String>>,
    #[serde(default)]
    attribs: Option<serde_json::Map<String, serde_json::Value>>,
}

async fn batch_send(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Extension(ip): Extension<ClientIp>,
    headers: HeaderMap,
    ApiBody(body): ApiBody<BatchBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let api = authorize(&state, &lang, &headers, ip).await?;
    let given = body.recipients.unwrap_or_default();
    if given.is_empty() {
        return Err(ApiError::Coded(
            code::BAD_RECIPIENT,
            state.i18n.tr(&lang, "Recipients cannot be empty", &[]),
        ));
    }
    let mut recipients: Vec<String> = Vec::new();
    for r in given.iter().map(|r| r.trim()) {
        if is_valid_email(r) && !recipients.iter().any(|x| x == r) {
            recipients.push(r.to_owned());
        }
    }
    if recipients.is_empty() {
        return Err(ApiError::Coded(
            code::BAD_RECIPIENT,
            state.i18n.tr(&lang, "No valid recipients", &[]),
        ));
    }
    let addresser = sender(&state, &lang, &api, &body.addresser).await?;
    let queued = queue(
        &state,
        &lang,
        &api,
        &addresser,
        &recipients,
        &attributes(&body.attribs),
    )
    .await?;
    if queued == 0 {
        return Err(ApiError::Coded(
            code::BAD_RECIPIENT,
            state.i18n.tr(&lang, "No valid recipients to insert", &[]),
        ));
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "Batch email send request accepted, {} emails queued",
            &[&queued],
        ),
        (),
    ))
}
