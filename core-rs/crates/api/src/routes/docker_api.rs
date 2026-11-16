//! `/api/docker_api/*` (Go: `controller/dockerapi`): the platform's
//! containers on the settings page.
//!
//! Differences from Go: only the platform's own containers are listed,
//! inspected or restarted (Go restarted or read any container ID on the
//! host); an unknown ID is an error instead of a restart that fails
//! silently in the background; CPU and memory figures match `docker stats`.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use serde::Deserialize;

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_string};
use crate::docker::{self, Container, Stats};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/docker_api/list", get(list))
        .route("/api/docker_api/state", get(stats))
        .route("/api/docker_api/restart", post(restart))
}

#[derive(Debug, Default, Deserialize)]
struct IdParams {
    #[serde(default, deserialize_with = "opt_string")]
    container_id: Option<String>,
}

fn unavailable(e: anyhow::Error) -> ApiError {
    ApiError::Rejected(format!("Docker is unavailable: {e:#}"))
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Vec<Container>>, ApiError> {
    let containers = docker::platform_containers(&state.config)
        .await
        .map_err(unavailable)?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        containers,
    ))
}

async fn platform_container(
    state: &AppState,
    lang: &str,
    id: Option<&str>,
) -> Result<Container, ApiError> {
    let id = id
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| ApiError::Validation("container_id is required".to_owned()))?;
    docker::platform_container(&state.config, id)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(lang, "The container does not exist", &[])))
}

async fn stats(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(params): ApiQuery<IdParams>,
) -> Result<ApiResponse<Stats>, ApiError> {
    let container = platform_container(&state, &lang, params.container_id.as_deref()).await?;
    let stats = docker::stats(&state.config, &container.id)
        .await
        .map_err(unavailable)?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), stats))
}

/// The console posts `{container_id}`; Go also read it from the query.
async fn restart(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiQuery(query): ApiQuery<IdParams>,
    ApiBody(body): ApiBody<IdParams>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = body.container_id.or(query.container_id);
    let container = platform_container(&state, &lang, id.as_deref()).await?;
    let name = container
        .names
        .first()
        .map(|n| n.trim_start_matches('/').to_owned())
        .unwrap_or_else(|| container.id.clone());
    docker::restart_soon(&state.config, container.id);
    audit
        .record(
            LogType::DockerApi,
            &format!("Restart container: {name} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), ()))
}
