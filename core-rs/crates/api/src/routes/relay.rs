//! `/api/relay/*` (Go: `controller/relay`): send a sender domain's mail
//! through another provider's SMTP server.
//!
//! Differences from Go:
//! - The list never sends relay passwords (Go sent them decrypted). An edit
//!   without a password keeps the stored one, and a connection test without
//!   one uses the stored password of the relay with that same server, port
//!   and user.
//! - Edits change only what they send: toggling a relay on or off no longer
//!   wipes its login (Go cleared the user and password whenever `auth_user`
//!   was missing, and disabled a relay whenever `active` was missing).
//! - Host, HELO name, user and password are checked before they reach
//!   Postfix's files (Go wrote any text, so a line break in the HELO name
//!   added options to `master.cf`); sender domains must be your domains.
//! - The list shows each relay's real connection status (Go always said
//!   "Connected") and checks SPF against the relay's configured SPF IP or
//!   include when one is set.

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::relay as rules;
use ferropost_store::relay::{self as store, NewRelay, RelayChanges, RelayRow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/relay/list", get(list))
        .route("/api/relay/add", post(create))
        .route("/api/relay/edit", post(edit))
        .route("/api/relay/delete", post(delete))
        .route("/api/relay/get_unbound_domains", get(unbound_domains))
        .route("/api/relay/test_connection", post(test_connection))
}

/// A string, number or bool as text (the console sends the port as a
/// number); `None` when missing or empty.
fn opt_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        Some(other) => Some(other.to_string()),
    })
}

/// Like [`opt_text`] but keeps an explicit empty string (`auth_user: ""`
/// switches the login off).
fn opt_raw<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Option::<Value>::deserialize(d)? {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.trim().to_owned()),
        Some(other) => Some(other.to_string()),
    })
}

#[derive(Debug, Clone, Default, Serialize)]
struct DnsRecord {
    #[serde(rename = "type")]
    kind: String,
    host: String,
    value: String,
}

/// Go put the SPF suggestion next to `data` instead of inside it.
#[derive(Serialize)]
struct WithSpf {
    success: bool,
    code: i32,
    msg: String,
    data: Option<()>,
    spf_record: DnsRecord,
}

impl IntoResponse for WithSpf {
    fn into_response(self) -> Response {
        axum::Json(self).into_response()
    }
}

fn len_ok(field: &str, value: &str, max: usize) -> Result<(), ApiError> {
    if value.chars().count() > max {
        return Err(ApiError::Validation(format!(
            "{field} must be at most {max} characters"
        )));
    }
    Ok(())
}

fn port(value: &str) -> Result<String, ApiError> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .map(|p| p.to_string())
        .ok_or_else(|| ApiError::Validation("relay_port must be between 1 and 65535".to_owned()))
}

fn host(field: &str, value: &str) -> Result<String, ApiError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if !rules::valid_host(&value) {
        return Err(ApiError::Validation(format!(
            "{field} must be a host name or IP address"
        )));
    }
    Ok(value)
}

fn auth_method(value: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_uppercase();
    match value.as_str() {
        "LOGIN" | "PLAIN" | "CRAM-MD5" | "NONE" => Ok(value),
        _ => Err(ApiError::Validation(
            "auth_method must be LOGIN, PLAIN, CRAM-MD5 or NONE".to_owned(),
        )),
    }
}

fn flag(field: &str, value: Option<i64>) -> Result<Option<i16>, ApiError> {
    match value {
        None => Ok(None),
        Some(v @ (0 | 1)) => Ok(Some(v as i16)),
        Some(_) => Err(ApiError::Validation(format!("{field} must be 0 or 1"))),
    }
}

fn spf_ip(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    value
        .trim_start_matches('+')
        .trim_start_matches("ip4:")
        .trim_start_matches("ip6:")
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| ApiError::Validation("ip must be an IP address".to_owned()))
}

fn spf_host(value: &str) -> Result<String, ApiError> {
    let value = value.trim().trim_start_matches("include:");
    if value.is_empty() {
        return Ok(String::new());
    }
    host("host", value)
}

/// Lower-cased sender domains without Go's optional `@`, each one of the
/// server's domains.
async fn sender_domains(
    state: &AppState,
    lang: &str,
    raw: &[String],
) -> Result<Vec<String>, ApiError> {
    let mut domains: Vec<String> = Vec::new();
    for d in raw {
        let d = d.trim().trim_start_matches('@').to_ascii_lowercase();
        if !d.is_empty() && !domains.contains(&d) {
            domains.push(d);
        }
    }
    let known = store::known_domains(&state.store.pg, &domains).await?;
    if let Some(unknown) = domains.iter().find(|d| !known.contains(d)) {
        return Err(ApiError::Validation(state.i18n.tr(
            lang,
            "The domain {} is not one of your domains",
            &[unknown],
        )));
    }
    Ok(domains)
}

fn domains_taken(state: &AppState, lang: &str, taken: &[String]) -> ApiError {
    ApiError::Conflict(format!(
        "{}: {}",
        state.i18n.tr(
            lang,
            "One or more sender domains are already used by another relay configuration",
            &[]
        ),
        taken.join(", ")
    ))
}

/// The SPF IP or include a relay needs: the configured ones, else the relay
/// host itself (an IP address or a name).
fn spf_target(row: &RelayRow) -> (String, String) {
    if !row.ip.is_empty() || !row.host.is_empty() {
        return (row.ip.clone(), row.host.clone());
    }
    match row.relay_host.parse::<std::net::IpAddr>() {
        Ok(_) => (row.relay_host.clone(), String::new()),
        Err(_) => (String::new(), row.relay_host.clone()),
    }
}

async fn spf_suggestion(state: &AppState, domain: &str, ip: &str, include: &str) -> DnsRecord {
    let base = rules::server_spf(crate::edge::server_public_ip(state).await);
    DnsRecord {
        kind: "TXT".to_owned(),
        host: domain.to_owned(),
        value: rules::spf_with_relay(&base, ip, include),
    }
}

async fn published_spf(state: &AppState, domain: &str) -> Option<String> {
    let domain = domain.to_owned();
    state
        .caches
        .spf_records
        .get_with(domain.clone(), async move {
            crate::dns::spf_record(&domain).await
        })
        .await
}

/// Writes the relays to Postfix; a failure is logged, as in Go (the
/// database change stands and the next sync retries).
async fn sync_logged(state: &AppState) -> Result<(), anyhow::Error> {
    let result = crate::relay::sync(state).await;
    if let Err(err) = &result {
        tracing::error!(error = %format!("{err:#}"), "relay sync to Postfix failed");
    }
    result
}

// ---- list ------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    rtype: Option<String>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Value>, ApiError> {
    let pg = &state.store.pg;
    let rows = store::list(pg, q.keyword.as_deref(), q.rtype.as_deref()).await?;
    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    let bindings = store::domains_of(pg, &ids).await?;
    let mut list = Vec::with_capacity(rows.len());
    for row in &rows {
        let domains: Vec<String> = bindings
            .iter()
            .filter(|(id, _)| *id == row.id)
            .map(|(_, d)| d.clone())
            .collect();
        let (ip, include) = spf_target(row);
        // Named providers publish their own include, which the relay host
        // is not; only check when it is known (Go: custom relays only).
        let checkable =
            !row.ip.is_empty() || !row.host.is_empty() || row.smtp_name == rules::GENERIC_NAME;
        let mut spf_records = Vec::new();
        let mut check_spf = 0;
        for domain in &domains {
            let record = spf_suggestion(&state, domain, &ip, &include).await;
            let check = if checkable {
                match published_spf(&state, domain).await {
                    Some(published) if rules::spf_covers(&published, &ip, &include) => 0,
                    _ => 1,
                }
            } else {
                0
            };
            check_spf |= check;
            spf_records.push(json!({"dns_record": record, "check": check}));
        }
        let status = crate::relay::status_of(&state, row).await;
        list.push(json!({
            "id": row.id, "remark": row.remark, "rtype": row.rtype,
            "relay_host": row.relay_host, "relay_port": row.relay_port,
            "auth_user": row.auth_user, "auth_password": "",
            "ip": row.ip, "host": row.host, "active": row.active,
            "create_time": row.create_time, "update_time": row.update_time,
            "auth_method": row.auth_method, "tls_protocol": "",
            "skip_tls_verify": row.skip_tls_verify, "helo_name": row.helo_name,
            "smtp_name": row.smtp_name, "header_json": "", "max_concurrency": 0,
            "max_retries": 0, "max_idle_time": "", "max_wait_time": "",
            "sender_domains": domains, "spf_records": spf_records,
            "smtp_status": status, "check_spf": check_spf,
        }));
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        json!({"total": list.len(), "list": list}),
    ))
}

// ---- create ------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CreateBody {
    remark: String,
    rtype: String,
    sender_domains: Vec<String>,
    #[serde(deserialize_with = "opt_text")]
    relay_host: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    relay_port: Option<String>,
    auth_user: String,
    auth_password: String,
    ip: String,
    host: String,
    #[serde(deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(deserialize_with = "opt_text")]
    auth_method: Option<String>,
    #[serde(deserialize_with = "opt_i64")]
    skip_tls_verify: Option<i64>,
    #[serde(deserialize_with = "opt_text")]
    helo_name: Option<String>,
    smtp_name: String,
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<CreateBody>,
) -> Result<WithSpf, ApiError> {
    len_ok("remark", &body.remark, 255)?;
    len_ok("rtype", &body.rtype, 30)?;
    len_ok("smtp_name", &body.smtp_name, 50)?;
    let relay_host = host(
        "relay_host",
        body.relay_host
            .as_deref()
            .ok_or_else(|| ApiError::Validation("relay_host is required".to_owned()))?,
    )?;
    let relay_port = port(
        body.relay_port
            .as_deref()
            .ok_or_else(|| ApiError::Validation("relay_port is required".to_owned()))?,
    )?;
    let domains = sender_domains(&state, &lang, &body.sender_domains).await?;
    if domains.is_empty() {
        return Err(ApiError::Validation(
            "sender_domains is required".to_owned(),
        ));
    }
    let (user, password) = (body.auth_user.trim(), body.auth_password.as_str());
    let (auth_password, method) = if user.is_empty() && password.is_empty() {
        (String::new(), "NONE".to_owned())
    } else {
        if user.is_empty() || password.is_empty() {
            return Err(ApiError::Validation(state.i18n.tr(
                &lang,
                "Both auth_user and auth_password must be provided when using authentication",
                &[],
            )));
        }
        if !rules::valid_login(user, password) {
            return Err(ApiError::Validation(
                "auth_user or auth_password contains characters Postfix cannot store".to_owned(),
            ));
        }
        (
            crate::relay::encrypt(&state, password).await?,
            "LOGIN".to_owned(),
        )
    };
    let relay = NewRelay {
        remark: body.remark.trim().to_owned(),
        rtype: body.rtype.trim().to_owned(),
        relay_host,
        relay_port,
        auth_user: user.to_owned(),
        auth_password,
        ip: spf_ip(&body.ip)?,
        host: spf_host(&body.host)?,
        active: flag("active", Some(body.active.unwrap_or(1)))?.unwrap_or(1),
        auth_method: body
            .auth_method
            .as_deref()
            .map(auth_method)
            .transpose()?
            .unwrap_or(method),
        skip_tls_verify: flag("skip_tls_verify", body.skip_tls_verify)?.unwrap_or(0),
        helo_name: body
            .helo_name
            .as_deref()
            .map(|h| host("helo_name", h))
            .transpose()?
            .unwrap_or_default(),
        smtp_name: body.smtp_name.trim().to_owned(),
    };
    let id = match store::create(&state.store.pg, &relay, &domains, now()).await? {
        Ok(id) => id,
        Err(taken) => return Err(domains_taken(&state, &lang, &taken)),
    };
    let _ = sync_logged(&state).await;
    crate::relay::check_soon(&state, id);
    audit
        .record(
            LogType::Smtp,
            &format!(
                "Created relay configuration: {} for domains: {}",
                relay.smtp_name,
                domains.join(", ")
            ),
        )
        .await;
    let spf = spf_suggestion(&state, &domains[0], &relay.ip, &relay.host).await;
    Ok(WithSpf {
        success: true,
        code: 0,
        msg: state
            .i18n
            .tr(&lang, "Relay configuration created successfully", &[]),
        data: None,
        spf_record: spf,
    })
}

// ---- edit --------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EditBody {
    #[serde(deserialize_with = "opt_i64")]
    id: Option<i64>,
    #[serde(deserialize_with = "opt_text")]
    remark: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    rtype: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    relay_host: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    relay_port: Option<String>,
    #[serde(deserialize_with = "opt_raw")]
    auth_user: Option<String>,
    #[serde(deserialize_with = "opt_raw")]
    auth_password: Option<String>,
    #[serde(deserialize_with = "opt_raw")]
    ip: Option<String>,
    #[serde(deserialize_with = "opt_raw")]
    host: Option<String>,
    #[serde(deserialize_with = "opt_i64")]
    active: Option<i64>,
    sender_domains: Option<Vec<String>>,
    #[serde(deserialize_with = "opt_text")]
    auth_method: Option<String>,
    #[serde(deserialize_with = "opt_i64")]
    skip_tls_verify: Option<i64>,
    #[serde(deserialize_with = "opt_raw")]
    helo_name: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    smtp_name: Option<String>,
}

fn not_found(state: &AppState, lang: &str) -> ApiError {
    ApiError::NotFound(
        state
            .i18n
            .tr(lang, "Relay configuration does not exist", &[]),
    )
}

async fn edit(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<EditBody>,
) -> Result<WithSpf, ApiError> {
    let id = body
        .id
        .filter(|id| *id > 0)
        .ok_or_else(|| ApiError::Validation("id is required".to_owned()))?;
    let pg = &state.store.pg;
    let current = store::get(pg, id)
        .await?
        .ok_or_else(|| not_found(&state, &lang))?;
    for (field, value, max) in [
        ("remark", &body.remark, 255),
        ("rtype", &body.rtype, 30),
        ("smtp_name", &body.smtp_name, 50),
    ] {
        if let Some(value) = value {
            len_ok(field, value, max)?;
        }
    }
    let mut changes = RelayChanges {
        remark: body.remark.clone(),
        rtype: body.rtype.clone(),
        relay_host: body
            .relay_host
            .as_deref()
            .map(|h| host("relay_host", h))
            .transpose()?,
        relay_port: body.relay_port.as_deref().map(port).transpose()?,
        ip: body.ip.as_deref().map(spf_ip).transpose()?,
        host: body.host.as_deref().map(spf_host).transpose()?,
        active: flag("active", body.active)?,
        skip_tls_verify: flag("skip_tls_verify", body.skip_tls_verify)?,
        helo_name: body
            .helo_name
            .as_deref()
            .map(|h| {
                if h.is_empty() {
                    Ok(String::new())
                } else {
                    host("helo_name", h)
                }
            })
            .transpose()?,
        smtp_name: body.smtp_name.clone(),
        auth_method: body.auth_method.as_deref().map(auth_method).transpose()?,
        ..RelayChanges::default()
    };

    // The login: an empty user switches it off; a new password replaces
    // the stored one; no password keeps it.
    let password = body.auth_password.as_deref().unwrap_or_default();
    match body.auth_user.as_deref() {
        Some("") => {
            changes.auth_user = Some(String::new());
            changes.auth_password = Some(String::new());
            changes.auth_method = Some("NONE".to_owned());
        }
        Some(user) => {
            let has_password = !password.is_empty() || !current.auth_password.is_empty();
            if !has_password {
                return Err(ApiError::Validation(state.i18n.tr(
                    &lang,
                    "Both auth_user and auth_password must be provided when using authentication",
                    &[],
                )));
            }
            if !rules::valid_login(user, password) {
                return Err(ApiError::Validation(
                    "auth_user or auth_password contains characters Postfix cannot store"
                        .to_owned(),
                ));
            }
            changes.auth_user = Some(user.to_owned());
            if changes.auth_method.is_none() && current.auth_method.eq_ignore_ascii_case("NONE") {
                changes.auth_method = Some("LOGIN".to_owned());
            }
        }
        None => {}
    }
    if !password.is_empty() && body.auth_user.as_deref() != Some("") {
        if !rules::valid_login("x", password) {
            return Err(ApiError::Validation(
                "auth_user or auth_password contains characters Postfix cannot store".to_owned(),
            ));
        }
        changes.auth_password = Some(crate::relay::encrypt(&state, password).await?);
    }

    let domains = match body.sender_domains.as_deref() {
        Some(list) if !list.is_empty() => Some(sender_domains(&state, &lang, list).await?),
        _ => None,
    };
    if let Err(taken) = store::update(pg, id, &changes, domains.as_deref(), now()).await? {
        return Err(domains_taken(&state, &lang, &taken));
    }
    let _ = sync_logged(&state).await;
    crate::relay::check_soon(&state, id);
    let updated = store::get(pg, id).await?.unwrap_or(current);
    audit
        .record(
            LogType::Smtp,
            &format!("Updated relay configuration : {}", updated.relay_host),
        )
        .await;
    let first = store::domains_of(pg, &[id]).await?.into_iter().next();
    let spf_record = match first {
        Some((_, domain)) => {
            let (ip, include) = spf_target(&updated);
            spf_suggestion(&state, &domain, &ip, &include).await
        }
        None => DnsRecord::default(),
    };
    Ok(WithSpf {
        success: true,
        code: 0,
        msg: state
            .i18n
            .tr(&lang, "Relay configuration updated successfully", &[]),
        data: None,
        spf_record,
    })
}

// ---- delete, domains, test ---------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct IdBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<IdBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = body
        .id
        .filter(|id| *id > 0)
        .ok_or_else(|| ApiError::Validation("id is required".to_owned()))?;
    let (name, domains) = store::delete(&state.store.pg, id)
        .await?
        .ok_or_else(|| not_found(&state, &lang))?;
    state.caches.relay_status.invalidate(&id).await;
    if let Err(err) = sync_logged(&state).await {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Deleted successfully but failed to sync configuration: {}",
            &[&format!("{err:#}")],
        )));
    }
    audit
        .record(
            LogType::Smtp,
            &format!(
                "Relay configuration deleted successfully: {name} for domains: {}",
                domains.join(", ")
            ),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Relay configuration deleted successfully", &[]),
        (),
    ))
}

async fn unbound_domains(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Vec<Value>>, ApiError> {
    let list = store::domain_bindings(&state.store.pg)
        .await?
        .into_iter()
        .map(|(domain, bound)| json!({"domain": domain, "is_bound": bound}))
        .collect();
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Get the domain list successfully", &[]),
        list,
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TestBody {
    #[serde(deserialize_with = "opt_text")]
    relay_host: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    relay_port: Option<String>,
    auth_user: String,
    auth_password: String,
}

async fn test_connection(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<TestBody>,
) -> Result<ApiResponse<Value>, ApiError> {
    let relay_host = body
        .relay_host
        .as_deref()
        .map(|h| host("relay_host", h))
        .transpose()?
        .unwrap_or_default();
    let relay_port = body.relay_port.unwrap_or_default();
    let user = body.auth_user.trim();
    // The edit form has no password to send: use the one stored for this
    // exact server and login, so it never goes to another server.
    let mut password = body.auth_password.clone();
    if password.is_empty()
        && !user.is_empty()
        && let Some(row) =
            store::find_login(&state.store.pg, &relay_host, relay_port.trim(), user).await?
    {
        password = crate::relay::decrypt(&state, &row.auth_password).await?;
    }
    let probe = crate::relay::test(&state, &relay_host, &relay_port, user, &password)
        .await
        .map_err(|msg| ApiError::Rejected(state.i18n.tr(&lang, &msg, &[])))?;
    audit
        .record(
            LogType::Smtp,
            &format!("The SMTP connection test was successful :{relay_host}:{relay_port}"),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "The SMTP connection test was successful", &[]),
        json!({
            "server_info": probe.server_info,
            "tls_status": probe.tls_status,
            "auth_status": probe.auth_status,
            "connection_time": probe.connection_time_ms,
            "supported_auth": probe.supported_auth,
            "recommend_config": probe.connection_time_ms < 1000,
        }),
    ))
}
