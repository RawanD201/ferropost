//! How the console is reached: the reverse-proxy URL, the API token and
//! the API documentation switch.
//!
//! Differences from Go: the reverse-proxy URL must be an `http(s)` URL
//! without credentials, query or fragment; regenerating the API token
//! revokes the previous one (Go left every token it ever issued working)
//! and is reserved to admins, as the token acts with admin rights.

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use ferropost_domain::audit::LogType;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit::Audit;
use crate::auth::CurrentUser;
use crate::body::ApiBody;
use crate::de::opt_bool;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub const REVERSE_PROXY: &str = "reverse_proxy_domain";
pub const API_DOC_ENABLED: &str = "API_DOC_ENABLED";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/settings/set_reverse_proxy_domain", post(set_proxy))
        .route(
            "/api/settings/delete_reverse_proxy_domain",
            post(delete_proxy),
        )
        .route("/api/settings/regenerate_api_token", post(regenerate_token))
        .route("/api/settings/set_api_doc_swagger", post(set_api_doc))
}

/// `https://host[:port][/path]` without a trailing slash.
fn proxy_url(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    let fine = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|h| !h.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    fine.then(|| url.as_str().trim_end_matches('/').to_owned())
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ProxyBody {
    domain: String,
}

async fn set_proxy(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ProxyBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let tr = |msg: &str, args: &[&dyn std::fmt::Display]| state.i18n.tr(&lang, msg, args);
    let domain = proxy_url(&body.domain).ok_or_else(|| {
        ApiError::Validation(tr(
            "The reverse proxy domain must be a URL such as https://mail.example.com",
            &[],
        ))
    })?;

    // The console must answer through the proxy before links point there.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|e| anyhow::anyhow!("http client: {e}"))?;
    let reply = client
        .get(format!("{domain}/api/languages/get"))
        .send()
        .await
        .map_err(|e| {
            ApiError::Rejected(tr(
                "Failed to connect to reverse proxy domain: {}",
                &[&e.without_url()],
            ))
        })?;
    let text = reply.text().await.unwrap_or_default();
    if text.trim().is_empty() {
        return Err(ApiError::Rejected(tr(
            "Reverse proxy domain test failed: received empty response",
            &[],
        )));
    }
    let code = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.get("code").and_then(Value::as_i64))
        .ok_or_else(|| {
            ApiError::Rejected(tr(
                "Reverse proxy domain test failed: invalid response format, missing code field",
                &[],
            ))
        })?;
    if code != 0 {
        return Err(ApiError::Rejected(tr(
            "Reverse proxy domain test failed: response code is {}, expected 0",
            &[&code],
        )));
    }

    ferropost_store::options::set_string(&state.store.pg, REVERSE_PROXY, &domain).await?;
    state.caches.base_urls.invalidate_all();
    audit
        .record(
            LogType::Settings,
            &format!("Reverse proxy domain set successfully :[{domain}]"),
        )
        .await;
    Ok(ApiResponse::ok(
        tr("Reverse proxy domain set successfully", &[]),
        (),
    ))
}

async fn delete_proxy(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
) -> Result<ApiResponse<()>, ApiError> {
    ferropost_store::options::set_string(&state.store.pg, REVERSE_PROXY, "").await?;
    state.caches.base_urls.invalidate_all();
    let msg = "The reverse proxy domain configuration has been successfully deleted.";
    audit.record(LogType::Settings, msg).await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, msg, &[]), ()))
}

async fn regenerate_token(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
    audit: Audit,
) -> Result<ApiResponse<Value>, ApiError> {
    if !user.is_admin() {
        return Err(ApiError::Forbidden);
    }
    let token = state.jwt.issue_api_token(user.account_id, &user.username);
    ferropost_store::options::set_string(&state.store.pg, crate::auth::API_TOKEN_OPTION, &token)
        .await?;
    state.caches.api_token.invalidate_all();
    audit
        .record_with(
            LogType::Settings,
            "Regenerated API token",
            &json!({"user": user.username, "user_id": user.account_id}),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "API token regenerated successfully", &[]),
        json!({"api_token": token}),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct ApiDocBody {
    #[serde(default, deserialize_with = "opt_bool")]
    api_doc_enabled: Option<bool>,
}

async fn set_api_doc(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ApiDocBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let enabled = body.api_doc_enabled.unwrap_or(false);
    let pg = &state.store.pg;
    if ferropost_store::options::get_bool(pg, API_DOC_ENABLED).await? == Some(enabled) {
        return Ok(ApiResponse::ok(
            state.i18n.tr(&lang, "No configuration changes needed", &[]),
            (),
        ));
    }
    ferropost_store::options::set_bool(pg, API_DOC_ENABLED, enabled).await?;
    audit
        .record_with(
            LogType::Settings,
            "Updated API documentation and Swagger UI configuration",
            &json!({"api_doc_enabled": enabled}),
        )
        .await;
    // Go serves the documentation and only reads the switch at start-up.
    crate::docker::restart_core_soon(&state.config).await;
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "API documentation and Swagger UI configuration updated successfully, service restarted",
            &[],
        ),
        (),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_urls() {
        assert_eq!(
            proxy_url(" https://mail.example.com/ ").as_deref(),
            Some("https://mail.example.com")
        );
        assert_eq!(
            proxy_url("http://x.test:8080/bm/").as_deref(),
            Some("http://x.test:8080/bm")
        );
        for bad in [
            "mail.example.com",
            "ftp://x.test",
            "https://u:p@x.test",
            "https://x.test/?a=1",
            "javascript:alert(1)",
        ] {
            assert_eq!(proxy_url(bad), None, "{bad}");
        }
    }
}
