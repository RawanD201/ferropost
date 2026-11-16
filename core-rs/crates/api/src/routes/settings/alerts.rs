//! Blacklist scanning switches and the mailbox that sends blacklist alerts
//! (`<root>/data/blacklist_alert_settings.json`, read by the blacklist
//! check).
//!
//! Differences from Go: the alert mailbox password is never sent back to
//! the console, and an empty password keeps the stored one as long as the
//! server, port and sender stay the same (so it cannot be replayed to
//! another server); the login goes over verified TLS (implicit on 465,
//! STARTTLS otherwise); the settings file is readable by its owner only.

use std::path::PathBuf;

use axum::Router;
use axum::extract::State;
use axum::routing::post;
use ferropost_domain::audit::LogType;
use ferropost_domain::settings::AlertSettings;
use ferropost_sender::smtp::{Mailer, Outgoing, SmtpConfig};
use serde::Deserialize;
use serde_json::json;

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::opt_bool;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub const AUTO_SCAN: &str = "blacklist_auto_scan_enabled";
pub const ALERT: &str = "blacklist_alert_enabled";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/settings/set_blacklist_auto_scan", post(set_auto_scan))
        .route("/api/settings/set_blacklist_alert", post(set_alert))
        .route(
            "/api/settings/set_blacklist_alert_settings",
            post(set_alert_settings),
        )
}

fn path(state: &AppState) -> PathBuf {
    state.config.root.join("data/blacklist_alert_settings.json")
}

/// The saved alert settings, if any.
pub fn stored(state: &AppState) -> Option<AlertSettings> {
    let raw = std::fs::read_to_string(path(state)).ok()?;
    serde_json::from_str(&raw).ok()
}

#[derive(Debug, Default, Deserialize)]
struct SwitchBody {
    #[serde(default, deserialize_with = "opt_bool")]
    enabled: Option<bool>,
}

async fn switch(
    state: &AppState,
    audit: &Audit,
    option: &str,
    what: &str,
    enabled: Option<bool>,
) -> Result<(), ApiError> {
    let enabled = enabled.ok_or_else(|| ApiError::Validation("enabled is required".to_owned()))?;
    ferropost_store::options::set_bool(&state.store.pg, option, enabled).await?;
    audit
        .record(
            LogType::Settings,
            &format!(
                "Turned the blacklist {what} {}",
                if enabled { "on" } else { "off" }
            ),
        )
        .await;
    Ok(())
}

async fn set_auto_scan(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<SwitchBody>,
) -> Result<ApiResponse<()>, ApiError> {
    switch(&state, &audit, AUTO_SCAN, "auto scan", body.enabled).await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Auto scan switch updated successfully", &[]),
        (),
    ))
}

async fn set_alert(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<SwitchBody>,
) -> Result<ApiResponse<()>, ApiError> {
    switch(&state, &audit, ALERT, "alert", body.enabled).await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Alert switch updated successfully", &[]),
        (),
    ))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn test_mail_html(settings: &AlertSettings) -> String {
    format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Alert Settings Configured Successfully</title></head>
<body style="background:#f5f5f5;margin:0;font-family:Arial,sans-serif;color:#333">
<div style="max-width:600px;margin:24px auto;background:#fff;border-radius:8px;padding:24px">
<h2 style="margin:0 0 16px;color:#20a53a">Alert settings configured successfully</h2>
<p style="margin:0 0 12px">This test message confirms that blacklist alerts can be delivered.</p>
<p style="margin:0">Sender: {} &lt;{}&gt;<br>SMTP server: {}:{}<br>Recipients: {}</p>
</div></body></html>"#,
        escape(&settings.name),
        escape(&settings.sender_email),
        escape(&settings.smtp_server),
        settings.smtp_port,
        settings.recipient_list.len(),
    )
}

async fn set_alert_settings(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(mut body): ApiBody<AlertSettings>,
) -> Result<ApiResponse<()>, ApiError> {
    let tr = |msg: &str, args: &[&dyn std::fmt::Display]| state.i18n.tr(&lang, msg, args);
    if body.smtp_password.is_empty()
        && let Some(saved) = stored(&state)
        && saved
            .smtp_server
            .eq_ignore_ascii_case(body.smtp_server.trim())
        && saved
            .sender_email
            .eq_ignore_ascii_case(body.sender_email.trim())
        && (saved.smtp_port == body.smtp_port || body.smtp_port == 0)
    {
        body.smtp_password = saved.smtp_password;
    }
    let settings = body
        .validated()
        .map_err(|e| ApiError::Validation(tr("Parameter validation failed: {}", &[&e])))?;

    let mailer = Mailer::external(&SmtpConfig {
        host: settings.smtp_server.clone(),
        port: settings.smtp_port as u16,
        username: settings.sender_email.clone(),
        password: settings.smtp_password.clone(),
    })
    .map_err(|e| ApiError::Rejected(tr("SMTP connection test failed: {}", &[&format!("{e:#}")])))?;
    mailer.test_connection().await.map_err(|e| {
        ApiError::Rejected(tr("SMTP connection test failed: {}", &[&format!("{e:#}")]))
    })?;
    let html = test_mail_html(&settings);
    let mut failed = Vec::new();
    for to in &settings.recipient_list {
        let mail = Outgoing {
            from_email: settings.sender_email.clone(),
            from_name: Some(settings.name.clone()),
            to: vec![to.clone()],
            subject: "Blacklist Alert Test - Ferropost".to_owned(),
            html: html.clone(),
            headers: Vec::new(),
            message_id: ferropost_sender::smtp::message_id(&settings.sender_email),
        };
        if let Err(err) = mailer.send(&mail).await {
            tracing::warn!(%to, error = %format!("{err:#}"), "alert test mail not sent");
            failed.push(to.as_str());
        }
    }
    if !failed.is_empty() {
        let detail = format!(
            "failed to send test email to {} recipient(s): [{}]",
            failed.len(),
            failed.join(" ")
        );
        return Err(ApiError::Rejected(tr(
            "Failed to send test email: {}",
            &[&detail],
        )));
    }

    let file = path(&state);
    let json = serde_json::to_vec_pretty(&settings).map_err(anyhow::Error::from)?;
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::fsio::write_atomic(&file, &json, 0o600)
    })
    .await
    .map_err(|e| anyhow::anyhow!("save alert settings: {e}"))?
    .map_err(|e| anyhow::anyhow!("save alert settings: {e}"))?;

    audit
        .record_with(
            LogType::Settings,
            "Saved the blacklist alert settings",
            &json!({
                "name": settings.name,
                "sender_email": settings.sender_email,
                "smtp_server": settings.smtp_server,
                "smtp_port": settings.smtp_port,
                "recipient_list": settings.recipient_list,
            }),
        )
        .await;
    Ok(ApiResponse::ok(
        tr("Alert settings saved successfully and test email sent", &[]),
        (),
    ))
}
