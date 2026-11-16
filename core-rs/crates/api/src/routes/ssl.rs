//! Mail host and console certificates (Go: `controller/domains`, SSL):
//! `/api/ssl/apply_cert`, `/api/ssl/console_apply_cert`,
//! `/api/ssl/get_cert_list`, `/api/domains/set_ssl`, `/api/domains/get_ssl`.
//!
//! Differences from Go: a key is only installed with its certificate, and
//! an empty key keeps the stored one when it belongs to the new
//! certificate; `get_ssl` never sends the private key (Go sent every
//! domain's key to anyone allowed to read domains), nor is it written to
//! the audit log (Go logged the whole request); certificates are only
//! requested for the server's own domains. See `crate::mail_tls` for how
//! certificates are installed and renewed.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use serde::Deserialize;

use crate::audit::Audit;
use crate::auth::CurrentUser;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::mail_tls::{self, CertSummary};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/ssl/apply_cert", post(apply_cert))
        .route("/api/ssl/console_apply_cert", post(console_apply_cert))
        .route("/api/ssl/get_cert_list", post(cert_list))
        .route("/api/domains/set_ssl", post(set_ssl))
        .route("/api/domains/get_ssl", get(get_ssl))
}

#[derive(Debug, Default, Deserialize)]
struct DomainBody {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default)]
    certificate: String,
    #[serde(default)]
    key: String,
}

/// One of the server's domains, lower-cased.
async fn our_domain(state: &AppState, lang: &str, raw: Option<&str>) -> Result<String, ApiError> {
    let domain = raw.unwrap_or_default().trim().to_ascii_lowercase();
    if !ferropost_domain::settings::is_valid_hostname(&domain) {
        return Err(ApiError::Validation(
            "domain must be a domain name".to_owned(),
        ));
    }
    if !ferropost_store::domains::exists(&state.store.pg, &domain).await? {
        return Err(ApiError::Rejected(state.i18n.tr(
            lang,
            "domain {} does not exist",
            &[&domain],
        )));
    }
    Ok(domain)
}

async fn email(state: &AppState, user: &CurrentUser) -> Result<String, ApiError> {
    Ok(
        ferropost_store::rbac::email_of(&state.store.pg, user.account_id)
            .await?
            .unwrap_or_default(),
    )
}

async fn apply_cert(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = our_domain(&state, &lang, body.domain.as_deref()).await?;
    let email = email(&state, &user).await?;
    mail_tls::obtain_for_domain(&state, &domain, user.account_id, &email)
        .await
        .map_err(|e| ApiError::Rejected(format!("{e:#}")))?;
    audit
        .record(
            LogType::Domain,
            &format!("Apply certificate for domain :{domain} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Certificate applied successfully", &[]),
        (),
    ))
}

async fn console_apply_cert(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
    audit: Audit,
) -> Result<ApiResponse<()>, ApiError> {
    let email = email(&state, &user).await?;
    mail_tls::obtain_for_console(&state, user.account_id, &email)
        .await
        .map_err(|e| {
            ApiError::Rejected(state.i18n.tr(&lang, "Failed : {}", &[&format!("{e:#}")]))
        })?;
    audit
        .record(
            LogType::Domain,
            "Apply certificate for console successfully",
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Certificate applied successfully", &[]),
        (),
    ))
}

/// Declared by Go and never implemented.
async fn cert_list() -> ApiError {
    ApiError::Coded(501, "Not Implemented".to_owned())
}

async fn set_ssl(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = our_domain(&state, &lang, body.domain.as_deref()).await?;
    let host = ferropost_store::domains::format_mx(&state.store.pg, &domain).await?;
    let chain = body.certificate.trim();
    if chain.is_empty() {
        return Err(ApiError::Validation("certificate is required".to_owned()));
    }
    crate::certs::info(chain.as_bytes(), 0).map_err(|e| {
        ApiError::Validation(format!("fail to set ssl: certificate is invalid: {e:#}"))
    })?;
    let key = match body.key.trim() {
        "" => tokio::fs::read_to_string(state.config.ssl_dir.join(&host).join("privkey.pem"))
            .await
            .map_err(|_| ApiError::Validation("key is required".to_owned()))?,
        key => format!("{key}\n"),
    };
    crate::certs::check_pair(chain.as_bytes(), key.as_bytes())
        .map_err(|e| ApiError::Validation(format!("fail to set ssl: {e:#}")))?;
    mail_tls::install(&state, &host, &format!("{chain}\n"), &key)
        .await
        .map_err(|e| ApiError::Rejected(format!("fail to set ssl: {e:#}")))?;
    audit
        .record(
            LogType::Domain,
            &format!("Set SSL for domain :{domain} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), ()))
}

#[derive(Debug, Deserialize)]
struct DomainQuery {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
}

async fn get_ssl(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<DomainQuery>,
) -> Result<ApiResponse<CertSummary>, ApiError> {
    let domain = q.domain.unwrap_or_default().trim().to_ascii_lowercase();
    if !ferropost_domain::settings::is_valid_hostname(&domain) {
        return Err(ApiError::Validation(
            "domain must be a domain name".to_owned(),
        ));
    }
    let host = ferropost_store::domains::format_mx(&state.store.pg, &domain).await?;
    let info = mail_tls::current(&state, &host).await?.unwrap_or_default();
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), info))
}
