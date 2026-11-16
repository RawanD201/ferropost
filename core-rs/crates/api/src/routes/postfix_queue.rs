//! `/api/postfix_queue/*` (Go: `controller/mail_services`, queue): the
//! deferred queue on the overview page and Postfix's queue settings.
//!
//! Differences from Go: the domain filter is applied here (Go passed it to
//! `sh -c "postqueue -j | grep -i '<domain>'"`, so the request could run
//! any command as root in the Postfix container); queue IDs are checked (Go
//! passed `ALL` straight to `postsuper -d`, emptying the whole queue);
//! failures are reported (Go ignored `postsuper`'s exit status); queue
//! settings must be Postfix time values (Go wrote any text into `main.cf`,
//! where a line break added other settings) and replace every definition
//! of the setting (Go changed the first, which Postfix ignores when a later
//! one exists); one `docker exec` serves a whole batch of IDs.

use std::collections::HashMap;

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::postfix::{
    self as rules, QUEUE_PARAMETERS, QueueEntry, deferred_entries, valid_queue_id, valid_time,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/postfix_queue/list", get(list))
        .route("/api/postfix_queue/queue_info", get(queue_info))
        .route("/api/postfix_queue/delete_by_id", post(delete_by_id))
        .route("/api/postfix_queue/delete", post(delete_deferred))
        .route("/api/postfix_queue/flush", post(flush))
        .route("/api/postfix_queue/flush_by_id", post(flush_by_id))
        .route("/api/postfix_queue/set_config", post(set_config))
        .route("/api/postfix_queue/set_all_config", post(set_all_config))
        .route("/api/postfix_queue/get_config", get(get_config))
}

fn container_error(state: &AppState, lang: &str, err: &anyhow::Error) -> ApiError {
    ApiError::Rejected(state.i18n.tr(
        lang,
        "Failed to execute command in container: {}",
        &[&format!("{err:#}")],
    ))
}

/// `postqueue -j`, failing on a non-zero exit.
async fn queue_json(state: &AppState, lang: &str) -> Result<String, ApiError> {
    let (stdout, stderr, code) =
        crate::docker::exec_status(&state.config.postfix_container, &["postqueue", "-j"])
            .await
            .map_err(|e| container_error(state, lang, &e))?;
    if code != Some(0) {
        return Err(ApiError::Rejected(state.i18n.tr(
            lang,
            "Command execution failed, exit code: {}, output: {}",
            &[&code.unwrap_or(-1), &stderr.trim()],
        )));
    }
    Ok(stdout)
}

fn domain_filter(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    match raw.map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase()) {
        None => Ok(None),
        Some(d) if d.is_empty() => Ok(None),
        Some(d) if ferropost_domain::settings::is_valid_hostname(&d) => Ok(Some(d)),
        Some(_) => Err(ApiError::Validation(
            "domain must be a domain name".to_owned(),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct DomainQuery {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<DomainQuery>,
) -> Result<ApiResponse<Value>, ApiError> {
    let domain = domain_filter(q.domain.as_deref())?;
    let output = queue_json(&state, &lang).await?;
    let list: Vec<QueueEntry> = deferred_entries(&output, domain.as_deref());
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "get postfix queue list success", &[]),
        json!({"total": list.len(), "list": list}),
    ))
}

fn queue_id(state: &AppState, lang: &str, raw: &str) -> Result<String, ApiError> {
    let id = raw.trim();
    if id.is_empty() {
        return Err(ApiError::Validation(state.i18n.tr(
            lang,
            "queue_id required",
            &[],
        )));
    }
    if !valid_queue_id(id) {
        return Err(ApiError::Validation(format!("invalid queue ID: {id}")));
    }
    Ok(id.to_owned())
}

#[derive(Debug, Deserialize)]
struct InfoQuery {
    #[serde(default)]
    queue_id: String,
}

/// Largest message shown in full.
const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

async fn queue_info(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<InfoQuery>,
) -> Result<ApiResponse<String>, ApiError> {
    let id = queue_id(&state, &lang, &q.queue_id)?;
    let (mut stdout, stderr, code) =
        crate::docker::exec_status(&state.config.postfix_container, &["postcat", "-q", &id])
            .await
            .map_err(|e| container_error(&state, &lang, &e))?;
    if code != Some(0) {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Command execution failed, exit code: {}, output: {}",
            &[&code.unwrap_or(-1), &stderr.trim()],
        )));
    }
    if stdout.len() > MAX_MESSAGE_BYTES {
        let mut cut = MAX_MESSAGE_BYTES;
        while !stdout.is_char_boundary(cut) {
            cut -= 1;
        }
        stdout.truncate(cut);
        stdout.push_str("\n... (message too large, the rest is not shown)\n");
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        stdout,
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct IdsBody {
    queue_ids: Vec<String>,
}

fn queue_ids(
    state: &AppState,
    lang: &str,
    raw: &[String],
    empty: &str,
) -> Result<Vec<String>, ApiError> {
    if raw.is_empty() {
        return Err(ApiError::Validation(state.i18n.tr(lang, empty, &[])));
    }
    let mut ids: Vec<String> = Vec::with_capacity(raw.len());
    for id in raw {
        let id = queue_id(state, lang, id)?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Runs `command` per ID; reports the failures, logs the rest.
async fn per_id(
    state: &AppState,
    lang: &str,
    audit: &Audit,
    command: &str,
    ids: &[String],
    verb: &str,
) -> Result<(), ApiError> {
    let failed = crate::postfix::per_queue_id(state, command, ids)
        .await
        .map_err(|e| container_error(state, lang, &e))?;
    let done: Vec<&str> = ids
        .iter()
        .filter(|id| !failed.contains(id))
        .map(String::as_str)
        .collect();
    if !done.is_empty() {
        audit
            .record(
                LogType::PostfixQueue,
                &format!(
                    "{verb} postfix queue mail [{}] successfully",
                    done.join(",")
                ),
            )
            .await;
    }
    if !failed.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            lang,
            &format!(
                "Failed to {} some queue mails: {{}}",
                verb.to_ascii_lowercase()
            ),
            &[&failed.join(", ")],
        )));
    }
    Ok(())
}

async fn delete_by_id(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<IdsBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let ids = queue_ids(&state, &lang, &body.queue_ids, "No queue IDs provided")?;
    per_id(&state, &lang, &audit, "postsuper -d", &ids, "Delete").await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "delete postfix queue mails success", &[]),
        (),
    ))
}

async fn flush_by_id(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<IdsBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let ids = queue_ids(&state, &lang, &body.queue_ids, "queue_ids required")?;
    per_id(&state, &lang, &audit, "postqueue -i", &ids, "Flush").await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "flush postfix queue mails by id success", &[]),
        (),
    ))
}

async fn delete_deferred(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
) -> Result<ApiResponse<()>, ApiError> {
    crate::postfix::run(&state, &["postsuper", "-d", "ALL", "deferred"])
        .await
        .map_err(|e| container_error(&state, &lang, &e))?;
    audit
        .record(
            LogType::PostfixQueue,
            "Delete all deferred queue mail successfully",
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "delete all deferred queue mail success", &[]),
        (),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct FlushBody {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
}

/// Retries the whole queue now, or only mail from one sender domain.
async fn flush(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<FlushBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let Some(domain) = domain_filter(body.domain.as_deref())? else {
        crate::postfix::run(&state, &["postqueue", "-f"])
            .await
            .map_err(|e| {
                ApiError::Rejected(state.i18n.tr(
                    &lang,
                    "flush all postfix queue failed: {}",
                    &[&format!("{e:#}")],
                ))
            })?;
        audit
            .record(
                LogType::PostfixQueue,
                "Flush all postfix queue mail successfully",
            )
            .await;
        return Ok(ApiResponse::ok(
            state.i18n.tr(&lang, "flush all postfix queue success", &[]),
            (),
        ));
    };
    let output = queue_json(&state, &lang).await?;
    let mut ids: Vec<String> = Vec::new();
    for entry in deferred_entries(&output, None) {
        let from_domain = entry
            .sender
            .rsplit_once('@')
            .is_some_and(|(_, d)| d.eq_ignore_ascii_case(&domain));
        if from_domain && valid_queue_id(&entry.queue_id) && !ids.contains(&entry.queue_id) {
            ids.push(entry.queue_id);
        }
    }
    if ids.is_empty() {
        return Ok(ApiResponse::ok(
            state
                .i18n
                .tr(&lang, "no deferred mail found for sender domain", &[]),
            (),
        ));
    }
    per_id(&state, &lang, &audit, "postqueue -i", &ids, "Flush").await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "flush postfix queue success", &[]),
        (),
    ))
}

async fn get_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<HashMap<&'static str, String>>, ApiError> {
    let path = crate::postfix::conf(&state, "main.cf");
    let content = tokio::task::spawn_blocking(move || std::fs::read_to_string(path).ok())
        .await
        .map_err(|e| anyhow::anyhow!("read main.cf: {e}"))?;
    let values = content
        .as_deref()
        .map(rules::main_cf_values)
        .unwrap_or_default();
    let config: HashMap<&'static str, String> = QUEUE_PARAMETERS
        .iter()
        .map(|(key, default)| {
            (
                *key,
                values
                    .get(*key)
                    .cloned()
                    .unwrap_or_else(|| (*default).to_owned()),
            )
        })
        .collect();
    let msg = if content.is_some() {
        "Success"
    } else {
        "Success (default values used)"
    };
    Ok(ApiResponse::ok(state.i18n.tr(&lang, msg, &[]), config))
}

/// Writes queue settings to `main.cf` and reloads Postfix when they
/// changed.
async fn apply(
    state: &AppState,
    lang: &str,
    audit: &Audit,
    changes: Vec<(&'static str, String)>,
) -> Result<(), ApiError> {
    let pairs = changes.clone();
    let changed = crate::postfix::edit_main_cf(state, move |content| {
        let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        rules::set_main_cf(content, &refs)
    })
    .await?;
    if changed
        && crate::postfix::run(state, &["postfix", "reload"])
            .await
            .is_err()
    {
        return Err(ApiError::Rejected(state.i18n.tr(
            lang,
            "set config success but reload failed, please check service status",
            &[],
        )));
    }
    let shown: Vec<String> = changes.iter().map(|(k, v)| format!("{k}={v}")).collect();
    audit
        .record(
            LogType::Settings,
            &format!("Set postfix configs [{}] successfully", shown.join(", ")),
        )
        .await;
    Ok(())
}

fn checked(key: &str, value: &str) -> Result<(&'static str, String), ApiError> {
    let name = QUEUE_PARAMETERS
        .iter()
        .map(|(k, _)| *k)
        .find(|k| *k == key)
        .ok_or_else(|| ApiError::Validation(format!("config key not allowed to modify: {key}")))?;
    let value = value.trim();
    if !valid_time(value) {
        return Err(ApiError::Validation(format!(
            "{name} must be a Postfix time such as 300s or 5d"
        )));
    }
    Ok((name, value.to_owned()))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct KeyBody {
    key: String,
    value: String,
}

async fn set_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<KeyBody>,
) -> Result<ApiResponse<()>, ApiError> {
    if body.key.trim().is_empty() || body.value.trim().is_empty() {
        return Err(ApiError::Validation(state.i18n.tr(
            &lang,
            "key and value required",
            &[],
        )));
    }
    let change = checked(body.key.trim(), &body.value)?;
    apply(&state, &lang, &audit, vec![change]).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "set postfix config success", &[]),
        (),
    ))
}

async fn set_all_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<HashMap<String, Value>>,
) -> Result<ApiResponse<()>, ApiError> {
    let mut changes = Vec::new();
    for (key, _) in QUEUE_PARAMETERS {
        let value = match body.get(key) {
            Some(Value::String(s)) => s.trim().to_owned(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        };
        if !value.is_empty() {
            changes.push(checked(key, &value)?);
        }
    }
    if changes.is_empty() {
        return Ok(ApiResponse::ok(
            state
                .i18n
                .tr(&lang, "No valid configurations to update", &[]),
            (),
        ));
    }
    apply(&state, &lang, &audit, changes).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "set postfix configs success", &[]),
        (),
    ))
}
