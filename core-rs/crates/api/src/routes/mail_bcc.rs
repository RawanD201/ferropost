//! `/api/mail_bcc/*` (Go: `controller/mail_services`, BCC): copy mail from
//! or to an address or domain to another address, through Postfix's
//! `sender_bcc_maps` and `recipient_bcc_maps`.
//!
//! Differences from Go: addresses are checked before they reach the Postfix
//! map (Go wrote any text, where a space or line break added rules); an
//! address keeps one active rule per type, since Postfix copies to one
//! address per key (Go accepted a second, which Postfix then ignored); the
//! list's search narrows the type and domain filters (Go's replaced them)
//! and reads the console's `page` and `keyword` (Go expected `page_num` and
//! `search_key`, so paging and search did nothing).

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::contacts::is_valid_email;
use ferropost_domain::mail_services::{bcc_address, domain_of};
use ferropost_domain::paging::Page;
use ferropost_store::mail_services::{self as store, BccRule, NewBcc};
use serde::Deserialize;

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/mail_bcc/list", get(list))
        .route("/api/mail_bcc/add", post(add))
        .route("/api/mail_bcc/edit", post(edit))
        .route("/api/mail_bcc/delete", post(delete))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, rename = "type", deserialize_with = "opt_string")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    search_key: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_num: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<BccRule>>, ApiError> {
    let page = q.page.or(q.page_num).filter(|p| *p > 0).unwrap_or(1);
    let page_size = q.page_size.filter(|p| *p > 0).unwrap_or(20).min(1000);
    let keyword = q.keyword.or(q.search_key);
    let (total, list) = store::bcc_list(
        &state.store.pg,
        q.kind.as_deref(),
        q.domain.as_deref(),
        keyword.as_deref(),
        page,
        page_size,
    )
    .await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "get bcc list success", &[]),
        Page { total, list },
    ))
}

#[derive(Debug, Default, Deserialize)]
struct RuleBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
    #[serde(default, rename = "type", deserialize_with = "opt_string")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    address: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    goto: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
}

/// A complete rule from the request: type, address and copy address.
fn rule(body: &RuleBody) -> Result<(String, String, String), ApiError> {
    let kind = match body.kind.as_deref().map(str::trim) {
        Some(k @ ("sender" | "recipient")) => k.to_owned(),
        _ => {
            return Err(ApiError::Validation(
                "type must be sender or recipient".to_owned(),
            ));
        }
    };
    let address = body
        .address
        .as_deref()
        .and_then(bcc_address)
        .ok_or_else(|| {
            ApiError::Validation("address must be an email address or a domain".to_owned())
        })?;
    let goto = body
        .goto
        .as_deref()
        .map(|g| g.trim().to_ascii_lowercase())
        .filter(|g| is_valid_email(g))
        .ok_or_else(|| ApiError::Validation("goto must be an email address".to_owned()))?;
    Ok((kind, address, goto))
}

fn active(value: Option<i64>, default: i16) -> Result<i16, ApiError> {
    match value {
        None => Ok(default),
        Some(v @ (0 | 1)) => Ok(v as i16),
        Some(_) => Err(ApiError::Validation("active must be 0 or 1".to_owned())),
    }
}

async fn ensure_free(
    state: &AppState,
    lang: &str,
    kind: &str,
    address: &str,
    except: i32,
) -> Result<(), ApiError> {
    if store::bcc_taken(&state.store.pg, kind, address, except).await? {
        return Err(ApiError::Conflict(state.i18n.tr(
            lang,
            "{} already has an active {} BCC rule: Postfix copies to one address per rule",
            &[&address, &kind],
        )));
    }
    Ok(())
}

/// Writes the maps; a failure keeps the change and says so (as Go did).
async fn sync(state: &AppState, lang: &str, done: &str) -> Result<(), ApiError> {
    crate::postfix::sync_bcc(state).await.map_err(|err| {
        tracing::error!(error = %format!("{err:#}"), "BCC sync to Postfix failed");
        ApiError::Rejected(state.i18n.tr(
            lang,
            &format!("{done} but sync config failed: {{}}"),
            &[&format!("{err:#}")],
        ))
    })
}

async fn add(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<RuleBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let (kind, address, goto) = rule(&body)?;
    let active = active(body.active, 1)?;
    if active == 1 {
        ensure_free(&state, &lang, &kind, &address, 0).await?;
    }
    let domain = domain_of(&address).to_owned();
    store::bcc_insert(
        &state.store.pg,
        &NewBcc {
            kind: &kind,
            address: &address,
            goto: &goto,
            domain: &domain,
            active,
        },
        chrono::Utc::now().timestamp(),
    )
    .await?;
    sync(&state, &lang, "add success").await?;
    audit
        .record(
            LogType::Bcc,
            &format!("Add bcc rule :{address} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "add bcc rule success", &[]),
        (),
    ))
}

async fn edit(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<RuleBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = body
        .id
        .filter(|id| *id > 0)
        .and_then(|id| i32::try_from(id).ok())
        .ok_or_else(|| ApiError::Validation("id is required".to_owned()))?;
    let pg = &state.store.pg;
    let current = store::bcc_get(pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "record not found", &[])))?;
    // A full edit sends the whole rule; otherwise only the switch changes.
    let full = body.kind.is_some() && body.address.is_some() && body.goto.is_some();
    let (kind, address, goto) = if full {
        rule(&body)?
    } else {
        (
            current.kind.clone(),
            current.address.to_ascii_lowercase(),
            current.goto.clone(),
        )
    };
    let active = active(body.active, current.active as i16)?;
    if active == 1 {
        ensure_free(&state, &lang, &kind, &address, id).await?;
    }
    let domain = domain_of(&address).to_owned();
    store::bcc_update(
        pg,
        id,
        &NewBcc {
            kind: &kind,
            address: &address,
            goto: &goto,
            domain: &domain,
            active,
        },
        chrono::Utc::now().timestamp(),
    )
    .await?;
    sync(&state, &lang, "modify success").await?;
    let (log, msg) = if full {
        (
            format!("Modify bcc rule :{address} successfully"),
            "modify bcc rule success",
        )
    } else if active == 1 {
        (format!("Bcc rule:{address} enabled"), "bcc rule enabled")
    } else {
        (format!("Bcc rule:{address} disabled"), "bcc rule disabled")
    };
    audit.record(LogType::Bcc, &log).await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, msg, &[]), ()))
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<RuleBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = body
        .id
        .filter(|id| *id > 0)
        .and_then(|id| i32::try_from(id).ok())
        .ok_or_else(|| ApiError::Validation("id is required".to_owned()))?;
    let address = store::bcc_delete(&state.store.pg, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "record not found", &[])))?;
    sync(&state, &lang, "delete success").await?;
    audit
        .record(
            LogType::Bcc,
            &format!("Delete bcc rule :{address} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "delete bcc rule success", &[]),
        (),
    ))
}
