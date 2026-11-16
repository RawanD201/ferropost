//! `/api/multi_ip_domain/*` (Go: `controller/domains`, multi-IP): apply
//! the dedicated sending IPs, and check one's DNS. See `crate::multi_ip`.

use std::net::Ipv4Addr;

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use ferropost_domain::audit::LogType;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::opt_string;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/multi_ip_domain/apply", post(apply))
        .route("/api/multi_ip_domain/test", post(test))
}

async fn apply(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
) -> Result<ApiResponse<Value>, ApiError> {
    let applied = crate::multi_ip::apply(&state).await.map_err(|e| {
        ApiError::Rejected(state.i18n.tr(
            &lang,
            "Failed to apply configuration: {}",
            &[&format!("{e:#}")],
        ))
    })?;
    audit
        .record_with(
            LogType::Domain,
            "Applied multi-IP domain configuration",
            &json!({"applied": applied.domains}),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Configuration applied successfully", &[]),
        json!({
            "applied_configs": applied.domains,
            "failed_configs": [],
            "warnings": [],
            "command": applied.command,
            "fix_command": applied.fix_command,
        }),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct TestBody {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    outbound_ip: Option<String>,
}

async fn test(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<TestBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = body
        .domain
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| ferropost_domain::settings::is_valid_hostname(d))
        .ok_or_else(|| ApiError::Validation("invalid domain format".to_owned()))?;
    let ip: Ipv4Addr = body
        .outbound_ip
        .as_deref()
        .and_then(|ip| ip.trim().parse().ok())
        .ok_or_else(|| ApiError::Validation("invalid IP address format".to_owned()))?;
    let outcome = crate::multi_ip::test(&state, &domain, ip).await;
    let (msg, detail) = match outcome {
        Ok(None) => (
            state
                .i18n
                .tr(&lang, "Configuration test passed successfully", &[]),
            "Success".to_owned(),
        ),
        Ok(Some(advice)) => (
            state.i18n.tr(
                &lang,
                "Configuration test passed with warnings: {}",
                &[&advice],
            ),
            format!("Warning: {advice}"),
        ),
        Err(err) => {
            return Err(ApiError::Rejected(state.i18n.tr(
                &lang,
                "Test configuration failed: {}",
                &[&format!("{err:#}")],
            )));
        }
    };
    audit
        .record(
            LogType::Domain,
            &format!("Test domain {domain} -> {ip} ({detail})"),
        )
        .await;
    Ok(ApiResponse::ok(msg, ()))
}
