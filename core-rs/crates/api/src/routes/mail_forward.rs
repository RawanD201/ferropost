//! `/api/mail_forward/*` (Go: `controller/mail_services`, forwarding):
//! the `alias` table Postfix reads, one address forwarded to a list of
//! others (`@domain` forwards a whole domain, as the domain's catch-all).
//!
//! Differences from Go: target addresses are checked; an edit changes only
//! what it sends (Go switched a forward off whenever `active` was missing);
//! the list reads the console's `keyword` (Go expected `search_key`, so
//! search did nothing); targets may be separated by lines or commas (the
//! console sends the stored, comma-separated list back when it toggles a
//! forward).

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::mail_services::{domain_of, forward_address, forward_targets};
use ferropost_domain::paging::Page;
use ferropost_store::mail_services::{self as store, Forward};
use serde::Deserialize;

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/mail_forward/list", get(list))
        .route("/api/mail_forward/add", post(add))
        .route("/api/mail_forward/edit", post(edit))
        .route("/api/mail_forward/delete", post(delete))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    search_key: Option<String>,
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
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<Forward>>, ApiError> {
    let page = q.page.filter(|p| *p > 0).unwrap_or(1);
    let page_size = q.page_size.filter(|p| *p > 0).unwrap_or(20).min(1000);
    let keyword = q.keyword.or(q.search_key);
    let (total, list) = store::forward_list(
        &state.store.pg,
        q.domain.as_deref(),
        keyword.as_deref(),
        page,
        page_size,
    )
    .await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Get email forwarding list successfully", &[]),
        Page { total, list },
    ))
}

#[derive(Debug, Default, Deserialize)]
struct ForwardBody {
    #[serde(default, deserialize_with = "opt_string")]
    address: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    goto: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
}

fn address(state: &AppState, lang: &str, raw: Option<&str>) -> Result<String, ApiError> {
    let raw = raw.unwrap_or_default();
    forward_address(raw).ok_or_else(|| {
        ApiError::Validation(state.i18n.tr(lang, "invalid email format: {}", &[&raw]))
    })
}

fn targets(state: &AppState, lang: &str, raw: &str) -> Result<String, ApiError> {
    forward_targets(raw)
        .map(|t| t.join(","))
        .map_err(|e| ApiError::Validation(state.i18n.tr(lang, &e, &[])))
}

fn switch(value: Option<i64>) -> Result<Option<i16>, ApiError> {
    match value {
        None => Ok(None),
        Some(v @ (0 | 1)) => Ok(Some(v as i16)),
        Some(_) => Err(ApiError::Validation("active must be 0 or 1".to_owned())),
    }
}

async fn add(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ForwardBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let address = address(&state, &lang, body.address.as_deref())?;
    let domain = domain_of(&address).to_owned();
    let pg = &state.store.pg;
    if !ferropost_store::domains::exists(pg, &domain).await? {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "domain not found in mail server",
            &[],
        )));
    }
    let goto = targets(&state, &lang, body.goto.as_deref().unwrap_or_default())?;
    let active = switch(body.active)?.unwrap_or(1);
    let added = store::forward_insert(
        pg,
        &address,
        &goto,
        &domain,
        active,
        chrono::Utc::now().timestamp(),
    )
    .await?;
    if !added {
        return Err(ApiError::Conflict(state.i18n.tr(
            &lang,
            "forward address already exists",
            &[],
        )));
    }
    audit
        .record(
            LogType::MailForward,
            &format!("Add mail forward :{address} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "add mail forward success", &[]),
        (),
    ))
}

async fn edit(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ForwardBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let address = body.address.as_deref().unwrap_or_default().trim();
    let pg = &state.store.pg;
    let current = store::forward_get(pg, address).await?.ok_or_else(|| {
        ApiError::NotFound(state.i18n.tr(&lang, "forward address not found", &[]))
    })?;
    let goto = match body.goto.as_deref() {
        Some(raw) => Some(targets(&state, &lang, raw)?),
        None => None,
    };
    store::forward_update(
        pg,
        &current.address,
        goto.as_deref(),
        switch(body.active)?,
        chrono::Utc::now().timestamp(),
    )
    .await?;
    audit
        .record(
            LogType::MailForward,
            &format!("Modify mail forward :{} successfully", current.address),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "modify mail forward success", &[]),
        (),
    ))
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ForwardBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let address = body.address.as_deref().unwrap_or_default().trim();
    if !store::forward_delete(&state.store.pg, address).await? {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "forward address not found",
            &[],
        )));
    }
    audit
        .record(
            LogType::MailForward,
            &format!("Delete mail forward :{address} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "delete mail forward success", &[]),
        (),
    ))
}
