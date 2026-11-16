//! `/api/settings/*` (Go: `controller/settings`): the console's system
//! settings, most of them kept in the shared `.env` file.
//!
//! Differences from Go:
//! - `get_system_config` no longer sends the admin password, the TLS
//!   private key or the alert mailbox password (Go sent all three in clear
//!   to every account allowed to read settings); the API token goes to
//!   admins only.
//! - Values are checked against a shell-safe allow-list, since `bm.sh`
//!   sources `.env` as root (see `ferropost_domain::settings`).
//! - Keys that only apply when `bm.sh` recreates the containers (ports, time
//!   zone, network, database credentials) are refused instead of written
//!   and followed by a core restart that applied none of them.
//! - Changing the admin login applies it to the account at once (Go
//!   restarted the core so its start-up sync would), and only an admin may
//!   change it.
//! - Nothing restarts the core except the API documentation switch, which
//!   Go reads at start-up.

mod access;
mod alerts;
mod ssl;
mod whitelist;

use std::collections::BTreeMap;

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::settings::{self as rules, Apply, Key};
use serde::Deserialize;
use serde_json::{Value, json};

use super::now;
use crate::audit::Audit;
use crate::auth::CurrentUser;
use crate::body::ApiBody;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/settings/get_version", get(version))
        .route("/api/settings/get_system_config", get(system_config))
        .route("/api/settings/set_system_config", post(set_system_config))
        .route("/api/settings/set_system_config_key", post(set_key))
        .route("/api/settings/get_timezone_list", get(timezones))
        .merge(ssl::routes())
        .merge(whitelist::routes())
        .merge(access::routes())
        .merge(alerts::routes())
}

/// `server.version` from GoFrame's `manifest/config/config.yaml`.
fn config_version(root: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("manifest/config/config.yaml")).ok()?;
    let mut in_server = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            in_server = trimmed.starts_with("server:");
            continue;
        }
        if in_server && let Some(value) = trimmed.strip_prefix("version:") {
            let value = value.split(" #").next().unwrap_or_default().trim();
            return Some(value.trim_matches(['"', '\'']).to_owned());
        }
    }
    None
}

async fn version(State(state): State<AppState>, Lang(lang): Lang) -> ApiResponse<Value> {
    let version = config_version(&state.config.root).unwrap_or_else(|| "0.1".to_owned());
    ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        json!({"version": version, "latest_version": "", "release_date": "", "can_update": false}),
    )
}

/// The host directory holding `docker-compose.yml` and `bm.sh`.
async fn work_dir(state: &AppState) -> String {
    let config = state.config.clone();
    let found = state
        .caches
        .compose_dir
        .get_with((), async move { crate::docker::compose_dir(&config).await })
        .await;
    found.unwrap_or_else(|| {
        state
            .config
            .root
            .parent()
            .unwrap_or(&state.config.root)
            .display()
            .to_string()
    })
}

async fn system_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
) -> Result<ApiResponse<Value>, ApiError> {
    let pg = &state.store.pg;
    let env = &state.config.env;
    let text = |key: &str| env.get(key).unwrap_or_default();
    // Go: 0 when unset, the service default when unparseable.
    let port = |key: &str, default: i64| {
        env.get(key)
            .map_or(0, |v| v.trim().parse::<i64>().unwrap_or(default))
    };
    let dir = work_dir(&state).await;
    let base = crate::base_url::global(&state).await;
    let api_token = if user.is_admin() {
        ferropost_store::options::get_string(pg, crate::auth::API_TOKEN_OPTION)
            .await?
            .unwrap_or_default()
    } else {
        String::new()
    };
    let mut alert = alerts::stored(&state).unwrap_or_default();
    alert.smtp_password.clear();
    let server_ip = crate::edge::server_public_ip(&state)
        .await
        .map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());

    let config = json!({
        "server_ip": server_ip,
        "admin_username": text("ADMIN_USERNAME"),
        "admin_password": "",
        "safe_path": text("SafePath"),
        "billionmail_hostname": text("BILLIONMAIL_HOSTNAME"),
        "db_name": text("DBNAME"),
        "db_user": text("DBUSER"),
        "db_pass": "",
        "redis_pass": "",
        "redis_port": text("REDIS_PORT"),
        "mail_ports": {
            "smtp": port("SMTP_PORT", 25),
            "smtps": port("SMTPS_PORT", 465),
            "submission": port("SUBMISSION_PORT", 587),
            "imap": port("IMAP_PORT", 143),
            "imaps": port("IMAPS_PORT", 993),
            "pop": port("POP_PORT", 110),
            "pops": port("POPS_PORT", 995),
        },
        "manage_ports": {
            "http": port("HTTP_PORT", 80),
            "https": port("HTTPS_PORT", 443),
            "command_https": format!("cd {dir} && echo \"PORT\" | bash bm.sh change-port"),
            "command_http": format!("cd {dir} && echo \"PORT\" | bash bm.sh change-apply-ssl-port"),
        },
        "manage_timezone": {
            "timezone": text("TZ"),
            "command": format!("cd {dir} && echo \"TIME ZONE\" | bash bm.sh change-tz"),
        },
        "ipv4_network": text("IPV4_NETWORK"),
        "fail2ban": text("FAIL2BAN_INIT") == "y",
        "ssl": ssl::summary(&state),
        "ip_whitelist": ferropost_store::whitelist::list(pg).await?,
        "ip_whitelist_enable": text("IP_WHITELIST_ENABLE") == "true",
        "reverse_proxy_domain": {
            "current_url": base,
            "reverse_proxy": ferropost_store::options::get_string(pg, access::REVERSE_PROXY)
                .await?
                .unwrap_or_default(),
        },
        "api_doc_swagger": {
            "api_doc_url": format!("{base}/api.json"),
            "swagger_url": format!("{base}/swagger"),
            "api_doc_enabled": ferropost_store::options::get_bool(pg, access::API_DOC_ENABLED)
                .await?
                .unwrap_or(false),
            "api_token": api_token,
        },
        "blacklist_config": {
            "auto_scan_enabled": ferropost_store::options::get_bool(pg, alerts::AUTO_SCAN)
                .await?
                .unwrap_or(true),
            "alert_enabled": ferropost_store::options::get_bool(pg, alerts::ALERT)
                .await?
                .unwrap_or(false),
            "alert_settings": alert,
        },
        "retention_days": env
            .get("RETENTION_DAYS")
            .map_or(0, |v| v.trim().parse::<i64>().unwrap_or(7)),
    });
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Successfully retrieved system configuration", &[]),
        config,
    ))
}

/// A scalar request value as text (`"30"` and `30` alike).
fn scalar<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s,
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    })
}

#[derive(Debug, Deserialize)]
struct KeyBody {
    #[serde(default, deserialize_with = "scalar")]
    key: String,
    #[serde(default, deserialize_with = "scalar")]
    value: String,
}

fn unchanged(state: &AppState, lang: &str) -> ApiError {
    ApiError::Rejected(
        state
            .i18n
            .tr(lang, "Invalid configuration item or value not changed", &[]),
    )
}

/// Checks a console value for `key`.
fn checked(
    state: &AppState,
    lang: &str,
    user: &CurrentUser,
    key: &'static Key,
    value: &str,
) -> Result<String, ApiError> {
    if key.apply == Apply::Host {
        return Err(ApiError::Rejected(state.i18n.tr(
            lang,
            "{} only changes when the containers are recreated: run bm.sh on the server instead",
            &[&key.json],
        )));
    }
    let value = rules::normalize(key.env, value).map_err(|e| {
        ApiError::Validation(
            state
                .i18n
                .tr(lang, "Parameter validation failed: {}", &[&e]),
        )
    })?;
    if matches!(key.env, "ADMIN_USERNAME" | "ADMIN_PASSWORD") && !user.is_admin() {
        return Err(ApiError::Forbidden);
    }
    Ok(value)
}

async fn set_key(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
    audit: Audit,
    caller: Option<axum::Extension<crate::conn::ClientIp>>,
    ApiBody(body): ApiBody<KeyBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let key = rules::lookup(&body.key).ok_or_else(|| unchanged(&state, &lang))?;
    let value = checked(&state, &lang, &user, key, &body.value)?;
    if key.env == "IP_WHITELIST_ENABLE" && value == "true" {
        let entries = ferropost_store::whitelist::entries(&state.store.pg).await?;
        if entries.is_empty() {
            return Err(ApiError::Rejected(state.i18n.tr(
                &lang,
                "IP whitelist list is empty. Whitelist function cannot be enabled",
                &[],
            )));
        }
        let nets: Vec<_> = entries
            .iter()
            .filter_map(|e| crate::edge::parse_net(e))
            .collect();
        whitelist::ensure_caller_allowed(&state, &lang, caller.map(|c| c.0.0), &nets).await?;
    }
    if apply(&state, &audit, &[(key, value)]).await? == 0 {
        return Err(unchanged(&state, &lang));
    }
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Configuration updated successfully", &[]),
        (),
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SystemConfigBody {
    admin_username: String,
    admin_password: String,
    safe_path: String,
    billionmail_hostname: String,
}

/// The four values Go's `set_system_config` applied; empty ones are kept.
async fn set_system_config(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
    audit: Audit,
    ApiBody(body): ApiBody<SystemConfigBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let mut changes = Vec::new();
    for (json, value) in [
        ("admin_username", &body.admin_username),
        ("admin_password", &body.admin_password),
        ("safe_path", &body.safe_path),
        ("billionmail_hostname", &body.billionmail_hostname),
    ] {
        if value.trim().is_empty() {
            continue;
        }
        let key = rules::lookup(json).expect("known key");
        changes.push((key, checked(&state, &lang, &user, key, value)?));
    }
    apply(&state, &audit, &changes).await?;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Configuration updated successfully", &[]),
        (),
    ))
}

/// Writes the values that differ from `.env`, applies the admin login to
/// its account and returns how many changed.
async fn apply(
    state: &AppState,
    audit: &Audit,
    changes: &[(&'static Key, String)],
) -> Result<usize, ApiError> {
    let env = &state.config.env;
    let changed: Vec<(&'static Key, &str)> = changes
        .iter()
        .filter(|(key, value)| env.get(key.env).unwrap_or_default() != *value)
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    if changed.is_empty() {
        return Ok(0);
    }
    let value_of = |name: &str| changed.iter().find(|(k, _)| k.env == name).map(|(_, v)| *v);
    let (username, password) = (value_of("ADMIN_USERNAME"), value_of("ADMIN_PASSWORD"));

    // The admin account, found before `.env` names someone else.
    let pg = &state.store.pg;
    let admin = if username.is_some() || password.is_some() {
        let current = env.get("ADMIN_USERNAME").unwrap_or_default();
        let admin = ferropost_store::rbac::admin_account_id(pg, &current).await?;
        if let (Some(name), Some(id)) = (username, admin)
            && ferropost_store::rbac::username_taken(pg, name, id).await?
        {
            return Err(ApiError::Conflict(format!(
                "The username {name} is already in use"
            )));
        }
        admin
    } else {
        None
    };

    // `.env` first: Go copies it into the account at every start, so it
    // must never hold the old login once the account has the new one.
    let pairs: Vec<(&str, &str)> = changed.iter().map(|(k, v)| (k.env, *v)).collect();
    env.update(&pairs)
        .map_err(|e| anyhow::anyhow!("Failed to update environment variable file: {e}"))?;

    match admin {
        Some(id) => {
            let hash = match password {
                Some(password) => {
                    let password = password.to_owned();
                    Some(
                        tokio::task::spawn_blocking(move || pwhash::bcrypt::hash(password))
                            .await
                            .map_err(|e| anyhow::anyhow!("hash: {e}"))?
                            .map_err(|e| anyhow::anyhow!("hash: {e}"))?,
                    )
                }
                None => None,
            };
            ferropost_store::rbac::set_login(pg, id, username, hash.as_deref(), now()).await?;
        }
        None if username.is_some() || password.is_some() => {
            tracing::warn!("no admin account to apply the new login to");
        }
        None => {}
    }
    if value_of("BILLIONMAIL_HOSTNAME").is_some() {
        state.caches.base_urls.invalidate_all();
    }
    for (key, value) in &changed {
        let shown = if rules::is_secret(key.env) {
            "******"
        } else {
            value
        };
        audit
            .record(
                LogType::Settings,
                &format!(
                    "Changed the configuration successfully: {} changed to {shown}",
                    key.env
                ),
            )
            .await;
    }
    Ok(changed.len())
}

const ZONE_GROUPS: [&str; 10] = [
    "Asia",
    "Africa",
    "America",
    "Antarctica",
    "Arctic",
    "Atlantic",
    "Australia",
    "Europe",
    "Indian",
    "Pacific",
];

#[derive(Debug, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZoneFile {
    #[serde(default)]
    zone_list: Vec<String>,
    #[serde(default)]
    zones: BTreeMap<String, Vec<String>>,
}

/// Zones per region from the system's tz database (files directly in each
/// region directory, as Go listed them).
fn scan_zones(root: &std::path::Path) -> BTreeMap<String, Vec<String>> {
    let mut zones = BTreeMap::new();
    for group in ZONE_GROUPS {
        let Ok(entries) = std::fs::read_dir(root.join(group)) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        zones.insert(group.to_owned(), names);
    }
    zones
}

async fn timezones(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<BTreeMap<String, Vec<String>>>, ApiError> {
    let cache = state.config.root.join("data/zoneinfo_list.json");
    let zones = tokio::task::spawn_blocking(move || {
        let cached = std::fs::read_to_string(&cache)
            .ok()
            .and_then(|raw| serde_json::from_str::<ZoneFile>(&raw).ok())
            .filter(|f| f.zones.values().any(|z| !z.is_empty()));
        if let Some(file) = cached {
            return file.zones;
        }
        let zones = scan_zones(std::path::Path::new("/usr/share/zoneinfo"));
        // Go cached an empty scan for good; this one tries again next time.
        if zones.values().any(|z| !z.is_empty()) {
            let file = ZoneFile {
                zone_list: ZONE_GROUPS.iter().map(|g| (*g).to_owned()).collect(),
                zones: zones.clone(),
            };
            if let Some(dir) = cache.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(json) = serde_json::to_vec(&file) {
                let _ = crate::fsio::write_atomic(&cache, &json, 0o644);
            }
        }
        zones
    })
    .await
    .map_err(|e| anyhow::anyhow!("zone scan: {e}"))?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Successful", &[]),
        zones,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_go_config_version() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::create_dir_all(dir.path().join("manifest/config")).expect("mkdir");
        std::fs::write(
            dir.path().join("manifest/config/config.yaml"),
            "logger:\n  version: \"no\"\nserver:\n  address: \":80\"\n  # Version\n  version: \"4.9.0\" # current\nviewer:\n  Paths: [\"template\"]\n",
        )
        .expect("write");
        assert_eq!(config_version(dir.path()).as_deref(), Some("4.9.0"));
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../core");
        assert!(config_version(&repo).is_some(), "the shipped config");
    }

    #[test]
    fn zone_scan_lists_region_files() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::create_dir_all(dir.path().join("Europe")).expect("mkdir");
        std::fs::create_dir_all(dir.path().join("America/Argentina")).expect("mkdir");
        for f in ["Europe/Paris", "Europe/Berlin", "America/New_York"] {
            std::fs::write(dir.path().join(f), "").expect("zone");
        }
        let zones = scan_zones(dir.path());
        assert_eq!(zones["Europe"], ["Berlin", "Paris"]);
        assert_eq!(zones["America"], ["New_York"], "subdirectories skipped");
    }
}
