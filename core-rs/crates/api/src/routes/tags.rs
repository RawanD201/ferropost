//! `/api/tags/*` (Go: `internal/controller/tags`).
//!
//! Ported: `list`, `all`. Still served by Go: `create`, `update`, `delete`,
//! `batch_contacts`.

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_domain::tags::Tag;
use ferropost_store::tags::TagFilter;
use serde::Deserialize;

use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/tags/list", get(list))
        .route("/api/tags/all", get(all))
}

const LIST_OK: &str = "Get tag list successfully";

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    group_id: Option<i64>,
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
    ApiQuery(query): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<Tag>>, ApiError> {
    let filter = TagFilter {
        keyword: query.keyword,
        group_id: group_filter(query.group_id)?,
    };
    let page = PageRequest::new(query.page.unwrap_or(1), query.page_size.unwrap_or(20));
    let data = ferropost_store::tags::list(&state.store.pg, &filter, page).await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, LIST_OK, &[]), data))
}

async fn all(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Page<Tag>>, ApiError> {
    let list = ferropost_store::tags::all(&state.store.pg).await?;
    let data = Page {
        total: i64::try_from(list.len()).unwrap_or(i64::MAX),
        list,
    };
    Ok(ApiResponse::ok(state.i18n.tr(&lang, LIST_OK, &[]), data))
}

/// `0` or absent means "all groups"; negatives fail like Go's `min:1` rule.
fn group_filter(group_id: Option<i64>) -> Result<Option<i32>, ApiError> {
    match group_id {
        None | Some(0) => Ok(None),
        Some(id) if id < 0 => Err(ApiError::Validation(format!(
            "The group_id value `{id}` must be equal or greater than 1"
        ))),
        Some(id) => i32::try_from(id).map(Some).map_err(|_| {
            ApiError::Validation(format!("The group_id value `{id}` is out of range"))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_filter_rules() {
        assert_eq!(group_filter(None).expect("ok"), None);
        assert_eq!(group_filter(Some(0)).expect("ok"), None);
        assert_eq!(group_filter(Some(7)).expect("ok"), Some(7));
        assert!(matches!(
            group_filter(Some(-1)),
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            group_filter(Some(i64::MAX)),
            Err(ApiError::Validation(_))
        ));
    }
}
