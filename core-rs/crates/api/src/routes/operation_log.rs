//! `/api/operation_log/*` (Go: `internal/controller/operation_log`).
//!
//! Fully ported: `list`, `type_list`, `output/list`, `output/latest`.

use std::path::{Path, PathBuf};

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use chrono::NaiveDate;
use ferropost_common::tail::newest_lines;
use ferropost_domain::audit::{LogEntry, LogType};
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_store::audit::LogFilter;
use serde::Deserialize;

use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/operation_log/list", get(list))
        .route("/api/operation_log/type_list", get(type_list))
        .route("/api/operation_log/output/list", get(output_list))
        .route("/api/operation_log/output/latest", get(output_latest))
}

/// Lines returned when the caller does not choose a page size (Go's default).
const DEFAULT_LINES: usize = 1000;
const MAX_LINES: usize = 10_000;

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_string", rename = "type")]
    log_type: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    end_time: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<LogEntry>>, ApiError> {
    let page = validate::id("page", q.page)?;
    let page_size = validate::id("page_size", q.page_size)?;

    let start_time = q.start_time.filter(|t| *t > 0);
    let mut end_time = q.end_time.filter(|t| *t > 0);
    if start_time.is_some() && end_time.is_none() {
        end_time = Some(chrono::Utc::now().timestamp());
    }
    let filter = LogFilter {
        keyword: q.keyword,
        log_type: q.log_type.filter(|t| t != "all"),
        start_time,
        end_time,
    };

    let data = ferropost_store::audit::list(
        &state.store.pg,
        &filter,
        PageRequest::new(page.into(), page_size.into()),
    )
    .await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Get operation logs successfully", &[]),
        data,
    ))
}

/// Category keys and labels (Go's `consts.GetLogTypeMap`).
async fn type_list(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> ApiResponse<serde_json::Map<String, serde_json::Value>> {
    let types = LogType::ALL
        .iter()
        .map(|t| (t.key().to_owned(), t.as_str().into()))
        .collect();
    ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Get operation types successfully", &[]),
        types,
    )
}

#[derive(Debug, Deserialize)]
struct OutputQuery {
    #[serde(default)]
    start_date: Option<String>,
    #[serde(default)]
    end_date: Option<String>,
    #[serde(default)]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
}

/// Lines of the core's daily output logs between two dates, newest page
/// first, joined with `\n`.
async fn output_list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<OutputQuery>,
) -> Result<ApiResponse<String>, ApiError> {
    let start = validate::required("start_date", &q.start_date)?;
    let end = validate::required("end_date", &q.end_date)?;
    let page = usize::try_from(q.page.unwrap_or(1).max(1)).unwrap_or(1);
    let take = match q.page_size {
        Some(size) if size > 0 => usize::try_from(size).unwrap_or(MAX_LINES).min(MAX_LINES),
        _ => DEFAULT_LINES,
    };
    let keyword = q.keyword.as_deref().unwrap_or_default().trim().to_owned();
    let not_found = || {
        ApiError::Rejected(
            state
                .i18n
                .tr(&lang, "No log files found in the given date range", &[]),
        )
    };

    let (Ok(start), Ok(end)) = (
        NaiveDate::parse_from_str(start, "%Y-%m-%d"),
        NaiveDate::parse_from_str(end, "%Y-%m-%d"),
    ) else {
        return Err(not_found());
    };
    if end < start {
        return Err(not_found());
    }

    let dir = output_dir(&state);
    let files = log_files(&dir, |date| (start..=end).contains(&date));
    if files.is_empty() {
        return Err(not_found());
    }
    let skip = (page - 1).saturating_mul(take);
    let lines = tokio::task::spawn_blocking(move || newest_lines(&files, &keyword, skip, take))
        .await
        .map_err(|e| anyhow::anyhow!("read output logs: {e}"))?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        lines.join("\n"),
    ))
}

/// The newest 1000 lines across all output logs.
async fn output_latest(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<String>, ApiError> {
    let files = log_files(&output_dir(&state), |_| true);
    if files.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "No log files found",
            &[],
        )));
    }
    let lines = tokio::task::spawn_blocking(move || newest_lines(&files, "", 0, DEFAULT_LINES))
        .await
        .map_err(|e| anyhow::anyhow!("read output logs: {e}"))?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        lines.join("\n"),
    ))
}

/// Where the Go core writes `YYYY-MM-DD.log` (`logger.path: logs/out`).
fn output_dir(state: &AppState) -> PathBuf {
    state.config.root.join("../logs/core/out")
}

/// `YYYY-MM-DD.log` files in `dir` accepted by `keep`, newest first.
/// Listing the directory (rather than probing each day like Go) keeps wide
/// date ranges cheap.
fn log_files(dir: &Path, keep: impl Fn(NaiveDate) -> bool) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<(NaiveDate, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let date = NaiveDate::parse_from_str(name.strip_suffix(".log")?, "%Y-%m-%d").ok()?;
            keep(date).then(|| (date, e.path()))
        })
        .collect();
    files.sort_by_key(|(date, _)| std::cmp::Reverse(*date));
    files.into_iter().map(|(_, path)| path).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_dated_logs_newest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in [
            "2026-11-13.log",
            "2026-11-15.log",
            "2026-11-14.log",
            "notes.txt",
            "x.log",
        ] {
            std::fs::write(dir.path().join(name), "").expect("write");
        }
        let names = |files: Vec<PathBuf>| -> Vec<String> {
            files
                .iter()
                .map(|p| p.file_name().expect("name").to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(
            names(log_files(dir.path(), |_| true)),
            ["2026-11-15.log", "2026-11-14.log", "2026-11-13.log"]
        );
        let from = NaiveDate::from_ymd_opt(2026, 11, 14).expect("date");
        assert_eq!(
            names(log_files(dir.path(), |d| d >= from)),
            ["2026-11-15.log", "2026-11-14.log"]
        );
        assert!(log_files(&dir.path().join("missing"), |_| true).is_empty());
    }
}
