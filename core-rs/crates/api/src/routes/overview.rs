//! `/api/overview` and `/api/overview/failed` (Go: `controller/overview`,
//! `maillog_stat/overview.go`). Both read the `mailstat_*` tables the
//! mail-log job fills.

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use ferropost_domain::mail::is_safe_hostname;
use ferropost_domain::overview::{Bucket, Charts, Dashboard, ProviderRow, charts, clamp_window};
use ferropost_store::overview::{FailedDelivery, Scope};
use serde::{Deserialize, Serialize};

use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/overview", get(overview))
        .route("/api/overview/failed", get(failed))
}

#[derive(Debug, Deserialize)]
pub(crate) struct OverviewQuery {
    #[serde(default, deserialize_with = "opt_i64")]
    pub(crate) campaign_id: Option<i64>,
    #[serde(default, deserialize_with = "opt_string")]
    pub(crate) domain: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    pub(crate) start_time: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    pub(crate) end_time: Option<i64>,
}

/// Validates the query like Go and turns it into a scope of at most a year.
pub(crate) fn scope(q: OverviewQuery) -> Result<Scope, ApiError> {
    let start = q
        .start_time
        .ok_or_else(|| ApiError::Validation("The start_time field is required".to_owned()))?;
    let end = match q.end_time {
        None => {
            return Err(ApiError::Validation(
                "The end_time field is required".to_owned(),
            ));
        }
        Some(0) => chrono::Utc::now().timestamp(),
        Some(end) => end,
    };
    if end < start {
        return Err(ApiError::Validation(
            "start time must be greater or equal to end time".to_owned(),
        ));
    }
    if let Some(domain) = &q.domain
        && !(is_safe_hostname(domain) && domain.contains('.'))
    {
        return Err(ApiError::Validation(format!(
            "The domain value `{domain}` is not a valid domain format"
        )));
    }
    let (start, end) = clamp_window(start, end);
    Ok(Scope {
        campaign_id: validate::optional_id("campaign_id", q.campaign_id)?.map(i64::from),
        domain: q.domain,
        start,
        end,
    })
}

#[derive(Serialize)]
pub(crate) struct Overview {
    dashboard: Dashboard,
    mail_providers: Vec<ProviderRow>,
    #[serde(flatten)]
    charts: Charts,
}

async fn overview(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<OverviewQuery>,
) -> Result<ApiResponse<Overview>, ApiError> {
    let data = build(&state, &scope(q)?).await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), data))
}

/// The dashboard for a scope (also `task/stat_chart` for one campaign).
pub(crate) async fn build(state: &AppState, scope: &Scope) -> Result<Overview, ApiError> {
    let pg = &state.store.pg;
    let bucket = Bucket::for_window(scope.start, scope.end);
    let tz = ferropost_store::overview::chart_timezone(pg, &state.config.timezone).await?;

    // Go ran each tile and chart as its own query; three cover all of it.
    let (totals, providers, series) = tokio::try_join!(
        ferropost_store::overview::totals(pg, scope),
        ferropost_store::overview::by_provider(pg, scope),
        ferropost_store::overview::series(pg, scope, bucket, &tz),
    )?;

    let container = state.config.postfix_container.clone();
    let delayed_queue = if container == "none" {
        0
    } else {
        state
            .caches
            .deferred_queue
            .get_with((), async move {
                crate::postfix_queue::deferred_count(&container)
                    .await
                    .unwrap_or_else(|err| {
                        tracing::debug!(error = %format!("{err:#}"), "deferred queue unavailable");
                        0
                    })
            })
            .await
    };

    let data = Overview {
        dashboard: Dashboard::new(totals, delayed_queue),
        mail_providers: providers
            .into_iter()
            .map(|(provider, counts)| ProviderRow::new(provider, counts))
            .collect(),
        charts: charts(bucket, &series, totals),
    };
    Ok(data)
}

/// Deliveries in the window that did not succeed, newest first.
async fn failed(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<OverviewQuery>,
) -> Result<ApiResponse<Vec<FailedDelivery>>, ApiError> {
    let scope = scope(q)?;
    let list = ferropost_store::overview::failed(&state.store.pg, &scope).await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), list))
}
