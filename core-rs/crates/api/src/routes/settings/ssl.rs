//! The console's own TLS certificate (`<ssl_dir>/cert.pem`, `key.pem`).
//!
//! Differences from Go: the key must belong to the certificate (Go saved
//! any PEM block, leaving the console on a certificate it could not serve);
//! an empty key keeps the stored one when it matches the new certificate;
//! the private key is never sent back, nor written to the audit log (Go
//! logged the whole request, key included); files are replaced atomically;
//! no restart is needed, as the server reloads its default certificate
//! within a minute.

use std::path::PathBuf;

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use ferropost_domain::audit::LogType;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/settings/set_ssl_config", post(set))
}

fn paths(state: &AppState) -> (PathBuf, PathBuf) {
    let dir = &state.config.ssl_dir;
    (dir.join("cert.pem"), dir.join("key.pem"))
}

/// Go's `SSLConfig` for the console certificate, without the key.
pub(super) fn summary(state: &AppState) -> Value {
    let (cert_path, key_path) = paths(state);
    let empty = json!({
        "cert_path": "", "key_path": "", "certPem": "", "privateKey": "",
        "notAfter": "", "notBefore": "", "issuer": "", "subject": "", "dns_names": [],
        "serial_number": "", "is_ca": false, "issuer_common_name": "",
        "subject_common_name": "", "version": 0, "status": false,
    });
    let Ok(pem) = std::fs::read(&cert_path) else {
        return empty;
    };
    if !key_path.is_file() {
        return empty;
    }
    let Ok(info) = crate::certs::info(&pem, chrono::Utc::now().timestamp()) else {
        return empty;
    };
    let mut value = serde_json::to_value(&info).unwrap_or(empty);
    if let Some(map) = value.as_object_mut() {
        map.insert("cert_path".into(), json!(cert_path.display().to_string()));
        map.insert("key_path".into(), json!(key_path.display().to_string()));
        map.insert(
            "certPem".into(),
            json!(String::from_utf8_lossy(&pem).into_owned()),
        );
        map.insert("privateKey".into(), json!(""));
        map.insert("status".into(), json!(info.current));
    }
    value
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SslBody {
    #[serde(rename = "certPem")]
    cert: String,
    #[serde(rename = "privateKey")]
    key: String,
}

async fn set(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<SslBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let tr = |msg: &str, args: &[&dyn std::fmt::Display]| state.i18n.tr(&lang, msg, args);
    let (_, key_path) = paths(&state);
    let (cert, key) = (body.cert.trim(), body.key.trim());

    if cert.is_empty() && key.is_empty() {
        // Postfix and Dovecot use the console's certificate as their own
        // default: a self-signed one takes its place rather than none.
        crate::mail_tls::reset_console(&state).await?;
        audit
            .record(
                LogType::Settings,
                "SSL certificate deleted successfully (a self-signed certificate replaces it)",
            )
            .await;
        return Ok(ApiResponse::ok(
            tr("Certificate deleted successfully", &[]),
            (),
        ));
    }

    let info =
        crate::certs::info(cert.as_bytes(), chrono::Utc::now().timestamp()).map_err(|e| {
            ApiError::Validation(tr("Invalid certificate data: {}", &[&format!("{e:#}")]))
        })?;
    let key = if key.is_empty() {
        std::fs::read_to_string(&key_path).map_err(|_| {
            ApiError::Validation(tr(
                "Invalid private key data: {}",
                &[&"no private key given"],
            ))
        })?
    } else {
        format!("{key}\n")
    };
    crate::certs::check_pair(cert.as_bytes(), key.as_bytes()).map_err(|e| {
        ApiError::Validation(tr("Invalid private key data: {}", &[&format!("{e:#}")]))
    })?;
    crate::mail_tls::install_console(&state, &format!("{cert}\n"), &key).await?;

    audit
        .record(
            LogType::Settings,
            &format!(
                "SSL certificate updated successfully: {} (expires {})",
                info.subject_common_name, info.not_after
            ),
        )
        .await;
    Ok(ApiResponse::ok(
        tr("SSL certificate updated successfully", &[]),
        (),
    ))
}
