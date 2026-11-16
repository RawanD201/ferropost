//! `/api/services/*` (Go: `controller/mail_services`, config files): the
//! console's editor for Postfix's `main.cf`, Dovecot's `dovecot.conf` and
//! rspamd's `rspamd.conf`. See `crate::service_config` for how a save is
//! checked and undone.

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use ferropost_domain::audit::LogType;
use ferropost_domain::mail_services::{MAX_CONFIG_BYTES, Service};
use serde::Deserialize;
use serde_json::json;

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::service_config::{self as files, ConfigFile, SaveError, Saved};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/services/get_config", post(get_config))
        .route("/api/services/save_config", post(save_config))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ServiceBody {
    service_type: String,
    content: Option<String>,
}

fn service(state: &AppState, lang: &str, raw: &str) -> Result<Service, ApiError> {
    Service::from_type(raw)
        .ok_or_else(|| ApiError::Validation(state.i18n.tr(lang, "Invalid service type", &[])))
}

async fn get_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiBody(body): ApiBody<ServiceBody>,
) -> Result<ApiResponse<ConfigFile>, ApiError> {
    let service = service(&state, &lang, &body.service_type)?;
    let path = files::path(&state, service);
    let shown = path.display().to_string();
    let file = tokio::task::spawn_blocking(move || files::read(&path))
        .await
        .map_err(|e| anyhow::anyhow!("read config: {e}"))??
        .ok_or_else(|| ApiError::NotFound(format!("config file not found: {shown}")))?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "config file get success", &[]),
        file,
    ))
}

async fn save_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ServiceBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let service = service(&state, &lang, &body.service_type)?;
    let content = body
        .content
        .ok_or_else(|| ApiError::Validation("content is required".to_owned()))?;
    if content.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ApiError::Validation(
            "The configuration file is larger than 3 MB".to_owned(),
        ));
    }
    if content.contains('\0') {
        return Err(ApiError::Validation(
            "The configuration file cannot contain NUL characters".to_owned(),
        ));
    }
    let path = files::path(&state, service);
    let check_state = state.clone();
    let saved = files::save_checked(&path, &content, || async move {
        files::check(&check_state, service).await
    })
    .await;
    let msg = match saved {
        Ok(Saved::Checked) => {
            state
                .i18n
                .tr(&lang, "The configuration file was saved successfully", &[])
        }
        Ok(Saved::Unchecked(why)) => state.i18n.tr(
            &lang,
            "The configuration file was saved, but {} could not check it: {}",
            &[&service.name(), &why],
        ),
        Err(SaveError::Rejected(output)) => {
            return Err(ApiError::Rejected(state.i18n.tr(
                &lang,
                "The configuration was not saved: {} rejected it: {}",
                &[&service.name(), &output],
            )));
        }
        Err(SaveError::Failed(err)) => return Err(err.into()),
    };
    audit
        .record_with(
            LogType::Service,
            &format!(
                "The {} configuration file was saved successfully",
                service.name()
            ),
            &json!({"service_type": body.service_type, "size": content.len()}),
        )
        .await;
    Ok(ApiResponse::ok(msg, ()))
}
