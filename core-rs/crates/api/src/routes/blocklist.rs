//! `/api/domain_blocklist/*` (Go: `controller/domains`, blocklist): check
//! a mail host on the DNS blocklists, and read the check's log. See
//! `crate::blocklist`.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/domain_blocklist/check", post(check))
        .route("/api/domain_blocklist/logs", get(logs))
}

#[derive(Debug, Default, Deserialize)]
struct CheckBody {
    #[serde(default, deserialize_with = "opt_string")]
    a_record: Option<String>,
}

async fn check(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<CheckBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let host = body
        .a_record
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| ferropost_domain::settings::is_valid_hostname(h))
        .ok_or_else(|| ApiError::Validation("a_record must be a host name".to_owned()))?;
    let ip = crate::blocklist::address_of(&state, &host)
        .await
        .map_err(|e| ApiError::Rejected(format!("{e:#}")))?;
    let task_state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = crate::blocklist::check(&task_state, &host, ip).await {
            tracing::warn!(%host, error = %format!("{err:#}"), "blocklist check failed");
        }
    });
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "The test will take two minutes, so please be patient",
            &[],
        ),
        (),
    ))
}

#[derive(Debug, Deserialize)]
struct LogQuery {
    #[serde(default, deserialize_with = "opt_string")]
    path: Option<String>,
}

async fn logs(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<LogQuery>,
) -> Result<ApiResponse<String>, ApiError> {
    let path = q
        .path
        .ok_or_else(|| ApiError::Validation("path is required".to_owned()))?;
    let content = crate::blocklist::read_log(&state, &path)
        .await
        .map_err(|e| ApiError::Validation(format!("{e:#}")))?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        content,
    ))
}
