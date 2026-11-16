//! `/api/abnormal_recipient/*` (Go: `controller/abnormal_recipient`):
//! addresses campaigns skip after repeated failures.
//!
//! Differences from Go: a manual block always blocks (Go left an address
//! already seen once below the blocking count); the group scan accepts
//! domains with only an address record (RFC 5321 implicit MX) and never
//! acts on a domain whose lookup failed (Go treated a DNS timeout as "no
//! MX", so a hiccup could block or delete a whole domain's contacts).

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::contacts::is_valid_email;
use ferropost_domain::paging::Page;
use ferropost_store::abnormal::{self as store, AbnormalRecipient, source};
use futures_util::StreamExt;
use serde::Deserialize;

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::dns::{MailDomain, mail_domain};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/abnormal_recipient/list", get(list))
        .route("/api/abnormal_recipient/add", post(add))
        .route("/api/abnormal_recipient/delete", post(delete))
        .route("/api/abnormal_recipient/check_group", post(check_group))
        .route("/api/abnormal_recipient/check_switch", get(check_switch))
        .route(
            "/api/abnormal_recipient/set_check_switch",
            post(set_check_switch),
        )
        .route("/api/abnormal_recipient/clear_abnormal", post(clear))
        .route("/api/abnormal_recipient/get_scan_log", post(scan_log))
}

const SWITCH: &str = "abnormal_mail_check_switch";
/// Domains looked up at once (Go: 20).
const SCAN_CONCURRENCY: usize = 20;

fn scan_log_path(state: &AppState) -> std::path::PathBuf {
    state.config.root.join("../logs/core/check_email_valid.txt")
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    add_type: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<AbnormalRecipient>>, ApiError> {
    let page = q.page.filter(|p| *p > 0).unwrap_or(1);
    let page_size = q.page_size.filter(|p| *p > 0).unwrap_or(10).min(1000);
    let add_type = q.add_type.filter(|t| *t > 0).map(|t| t as i32);
    let (total, list) = store::list(
        &state.store.pg,
        q.keyword.as_deref(),
        add_type,
        page,
        page_size,
    )
    .await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "The list of exception recipients was successfully obtained",
            &[],
        ),
        Page { total, list },
    ))
}

#[derive(Debug, Deserialize)]
struct AddBody {
    #[serde(default, deserialize_with = "opt_string")]
    recipient: Option<String>,
}

async fn add(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<AddBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let recipient = validate::required("recipient", &body.recipient)?.to_ascii_lowercase();
    if !is_valid_email(&recipient) {
        return Err(ApiError::Validation(format!(
            "The recipient value `{recipient}` is not a valid email address"
        )));
    }
    store::add_manual(&state.store.pg, &recipient, now()).await?;
    audit
        .record(
            LogType::AbnormalRecipient,
            &format!("Add abnormal recipient :{recipient} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "The exception recipient was added successfully", &[]),
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
    let recipient = store::delete(&state.store.pg, id).await?.ok_or_else(|| {
        ApiError::NotFound(state.i18n.tr(&lang, "Abnormal recipient not found", &[]))
    })?;
    audit
        .record(
            LogType::AbnormalRecipient,
            &format!("Delete abnormal recipient :{recipient} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "The exception recipient was removed successfully",
            &[],
        ),
        (),
    ))
}

async fn clear(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
) -> Result<ApiResponse<()>, ApiError> {
    store::clear(&state.store.pg).await?;
    audit
        .record(
            LogType::AbnormalRecipient,
            "Clearing the abnormal email box was successful",
        )
        .await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), ()))
}

async fn switch_on(state: &AppState) -> Result<bool, ApiError> {
    Ok(ferropost_store::options::get(&state.store.pg, SWITCH)
        .await?
        .is_none_or(|v| v.trim().is_empty() || v.trim() == "1"))
}

async fn check_switch(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<i32>, ApiError> {
    let on = switch_on(&state).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        i32::from(on),
    ))
}

#[derive(Debug, Deserialize)]
struct OperBody {
    #[serde(default, deserialize_with = "opt_i64")]
    oper: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
}

async fn set_check_switch(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<OperBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let oper = validate::one_of("oper", body.oper, &[0, 1])?;
    ferropost_store::options::set(&state.store.pg, SWITCH, &oper.to_string()).await?;
    let action = if oper == 1 { "Turn on" } else { "Shut down" };
    audit
        .record(
            LogType::AbnormalRecipient,
            &format!("{action} Automatic scanning of abnormal email accounts"),
        )
        .await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), ()))
}

async fn scan_log(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<String>, ApiError> {
    let content = tokio::fs::read_to_string(scan_log_path(&state))
        .await
        .unwrap_or_default();
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        content,
    ))
}

/// Checks that every subscriber's domain can receive mail, in the
/// background; the log (`get_scan_log`) shows progress. `oper` 1 only
/// checks, 2 blocks unreachable addresses, 3 removes them from the group.
async fn check_group(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<OperBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let group_id = validate::id("group_id", body.group_id)?;
    let oper = validate::one_of("oper", body.oper, &[1, 2, 3])?;
    let pg = &state.store.pg;
    let group = ferropost_store::groups::get(pg, group_id)
        .await?
        .ok_or_else(|| {
            ApiError::Rejected(state.i18n.tr(&lang, "The group does not exist.", &[]))
        })?;
    let emails = store::group_addresses(pg, group_id).await?;
    if emails.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "The contact person within the group is unavailable.",
            &[],
        )));
    }
    let path = scan_log_path(&state);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&path, "").map_err(|e| anyhow::anyhow!("scan log: {e}"))?;
    tokio::spawn(scan_group(
        state.clone(),
        group_id,
        group.name.clone(),
        emails,
        oper,
    ));
    audit
        .record(
            LogType::AbnormalRecipient,
            &format!(
                "Manually scan the abnormal email addresses in group :{} successfully",
                group.name
            ),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "The process is currently running in the background. Please check the log.",
            &[],
        ),
        (),
    ))
}

struct ScanLog(std::path::PathBuf);

impl ScanLog {
    fn line(&self, text: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
        {
            let _ = writeln!(f, "{text}");
        }
    }
}

fn stamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

async fn scan_group(state: AppState, group_id: i32, name: String, emails: Vec<String>, oper: i64) {
    let log = ScanLog(scan_log_path(&state));
    let mut by_domain: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for email in &emails {
        if let Some((_, domain)) = email.rsplit_once('@') {
            by_domain
                .entry(domain.to_ascii_lowercase())
                .or_default()
                .push(email.clone());
        }
    }
    let group = format!("Group[{name}]");
    log.line(&format!("{}: {group} start checking...", stamp()));
    log.line(&format!("Total emails to check: {}", emails.len()));
    log.line(&format!("Total domains to check: {}", by_domain.len()));

    let mut results = futures_util::stream::iter(by_domain)
        .map(|(domain, addresses)| async move { (mail_domain(&domain).await, domain, addresses) })
        .buffer_unordered(SCAN_CONCURRENCY);
    let (mut valid, mut unchecked) = (0usize, 0usize);
    let mut invalid: Vec<(String, String)> = Vec::new();
    while let Some((status, domain, addresses)) = results.next().await {
        match status {
            MailDomain::Reachable => {
                valid += addresses.len();
                log.line(&format!(
                    "{}: {domain} -----------------------------  √",
                    stamp()
                ));
            }
            MailDomain::Unreachable(reason) => {
                log.line(&format!(
                    "{}: {domain} ----------------------------- x  {reason}",
                    stamp()
                ));
                invalid.extend(addresses.into_iter().map(|a| (a, reason.clone())));
            }
            MailDomain::Unknown(reason) => {
                unchecked += addresses.len();
                log.line(&format!(
                    "{}: {domain} ----------------------------- ?  {reason} (left as is)",
                    stamp()
                ));
            }
        }
    }

    let pg = &state.store.pg;
    let outcome = match oper {
        2 => {
            log.line("Adding invalid emails to blocklist with details...");
            store::record_failures(
                pg,
                &invalid,
                source::GROUP_SCAN,
                "Manual scanning group (MX check)",
                now(),
            )
            .await
            .map(|_| ())
        }
        3 => {
            log.line("Removing invalid emails from group...");
            let addresses: Vec<String> = invalid.iter().map(|(a, _)| a.clone()).collect();
            store::remove_from_group(pg, group_id, &addresses)
                .await
                .map(|_| ())
        }
        _ => Ok(()),
    };
    if let Err(err) = outcome {
        log.line(&format!("Failed: {err:#}"));
    }
    let rule =
        "---------------------------------------------------------------------------------------";
    log.line(rule);
    log.line(&format!("Results for [{group}]:"));
    log.line(&format!("Tested: {}", emails.len()));
    log.line(&format!("Normal: {valid}"));
    log.line(&format!("Abnormal:  {}", invalid.len()));
    log.line(&format!("Not checked (DNS failed): {unchecked}"));
    let listed: Vec<&str> = invalid.iter().map(|(a, _)| a.as_str()).collect();
    log.line(&format!("Abnormal emails: {}", listed.join(", ")));
    log.line(rule);
    log.line(&format!("{}:  Check finished", stamp()));
}
