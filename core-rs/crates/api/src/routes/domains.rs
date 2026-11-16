//! `/api/domains/*` (Go: `controller/domains`): the server's sending
//! domains. See `crate::domains` for their records and job, `crate::dkim`
//! for their keys.
//!
//! Differences from Go:
//! - The list no longer sends every domain's TLS private key, and `all`
//!   marks the default domain (Go never did, so the campaign form could
//!   not preselect it).
//! - An update changes only what it is given: Go set `active` to 1 and
//!   `hasbrandinfo` to 0 unless sent (the console sends neither, so every
//!   edit cleared the brand flag), and could not turn the catch-all off.
//! - A dedicated address is checked before the domain is created, so a
//!   failed check no longer leaves a half-made domain behind.
//! - Deleting a domain also removes its BCC rules, dedicated address and
//!   default-domain setting, and stops rspamd signing for it; unknown
//!   domains are refused instead of "updated" or "deleted".

use std::collections::HashMap;
use std::net::Ipv4Addr;

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::blocklist::{CheckResult, Listing};
use ferropost_domain::contacts::is_valid_email;
use ferropost_domain::domains::{self as rules, DnsRecords};
use ferropost_domain::mail::mx_hostname_fallback;
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_store::domains::{self as store, DomainChanges, DomainRow, NewDomain};
use ferropost_store::multi_ip::{self as multi_ip_store, DedicatedIpRow};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit::Audit;
use crate::auth::CurrentUser;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::mail_tls::CertSummary;
use crate::state::AppState;
use crate::validate;

const FLAG: &[i64] = &[0, 1];
const DEFAULT_OPTION: &str = "default_sender_domain";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/domains/create", post(create))
        .route("/api/domains/update", post(update))
        .route("/api/domains/update_brandinfo", post(update_brandinfo))
        .route("/api/domains/delete", post(delete))
        .route("/api/domains/list", get(list))
        .route("/api/domains/all", get(all))
        .route("/api/domains/fresh_dns_records", post(fresh_dns_records))
        .route("/api/domains/set_default_domain", post(set_default_domain))
}

#[derive(Debug, Default, Deserialize)]
struct DomainBody {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    hostname: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    mailboxes: Option<i64>,
    #[serde(default, rename = "mailboxQuota", deserialize_with = "opt_i64")]
    mailbox_quota: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    quota: Option<i64>,
    #[serde(default, rename = "rateLimit", deserialize_with = "opt_i64")]
    rate_limit: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    /// The catch-all address; empty turns it off.
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    urls: Option<Vec<String>>,
    #[serde(default, deserialize_with = "opt_i64")]
    hasbrandinfo: Option<i64>,
    /// The dedicated sending address; empty removes it.
    #[serde(default)]
    outbound_ip: Option<String>,
}

/// A domain name from a request, lower-cased.
fn domain_name(field: &str, raw: Option<&str>) -> Result<String, ApiError> {
    let name = raw
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if name.is_empty() {
        return Err(ApiError::Validation(format!(
            "The {field} field is required"
        )));
    }
    if !rules::is_domain_name(&name) {
        return Err(ApiError::Validation(format!(
            "The {field} value `{name}` is not a valid domain format"
        )));
    }
    Ok(name)
}

/// A changed number: zero or absent keeps the value (as in Go).
fn positive(field: &str, value: Option<i64>) -> Result<Option<i64>, ApiError> {
    match value {
        Some(v) if v < 0 => Err(ApiError::Validation(format!(
            "The {field} value `{v}` must be equal or greater than 1"
        ))),
        Some(0) | None => Ok(None),
        Some(v) => Ok(Some(v)),
    }
}

/// A number of at least 1 for a new domain, `None` when absent.
fn at_least_one(field: &str, value: Option<i64>) -> Result<Option<i64>, ApiError> {
    match value {
        Some(v) if v < 1 => Err(ApiError::Validation(format!(
            "The {field} value `{v}` must be equal or greater than 1"
        ))),
        other => Ok(other),
    }
}

/// The catch-all address: `None` turns it off.
fn catchall(raw: &str) -> Result<Option<String>, ApiError> {
    let address = raw.trim().to_ascii_lowercase();
    if address.is_empty() {
        return Ok(None);
    }
    if !is_valid_email(&address) {
        return Err(ApiError::Validation(format!(
            "The email value `{address}` is not a valid email address"
        )));
    }
    Ok(Some(address))
}

/// The dedicated sending address: `None` for none.
fn dedicated_ip(raw: &str) -> Result<Option<Ipv4Addr>, ApiError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    raw.parse().map(Some).map_err(|_| {
        ApiError::Validation(format!(
            "The outbound_ip value `{raw}` is not a valid IPv4 address"
        ))
    })
}

fn urls(raw: &[String]) -> Result<Vec<String>, ApiError> {
    rules::clean_urls(raw).map_err(ApiError::Validation)
}

async fn known(state: &AppState, lang: &str, domain: &str) -> Result<DomainRow, ApiError> {
    store::get(&state.store.pg, domain).await?.ok_or_else(|| {
        ApiError::NotFound(state.i18n.tr(lang, "domain {} does not exist", &[&domain]))
    })
}

/// Checks a dedicated address before anything is written.
async fn check_dedicated(
    state: &AppState,
    lang: &str,
    domain: &str,
    host: &str,
    ip: Ipv4Addr,
) -> Result<(), ApiError> {
    crate::multi_ip::check_address(domain, host, ip)
        .await
        .map(|_| ())
        .map_err(|e| {
            ApiError::Rejected(state.i18n.tr(
                lang,
                "Failed to add dedicated IP: {}",
                &[&format!("{e:#}")],
            ))
        })
}

/// Requests the mail host's certificate in the background (Go did, half
/// a second after creating the domain).
fn obtain_certificate(state: &AppState, domain: &str, account_id: i64) {
    let (state, domain) = (state.clone(), domain.to_owned());
    tokio::spawn(async move {
        let email = ferropost_store::rbac::email_of(&state.store.pg, account_id)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if let Err(err) =
            crate::mail_tls::obtain_for_domain(&state, &domain, account_id, &email).await
        {
            tracing::info!(%domain, error = %format!("{err:#}"), "certificate not obtained yet");
        }
    });
}

/// Writes rspamd's signing configuration in the background.
fn sync_signing_soon(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = crate::dkim::sync_signing(&state).await {
            tracing::warn!(error = %format!("{err:#}"), "DKIM signing config not updated");
        }
    });
}

/// What the audit log keeps of a new domain.
#[derive(Serialize)]
struct Created<'a> {
    domain: &'a str,
    a_record: &'a str,
    mailboxes: i64,
    mailbox_quota: i64,
    quota: i64,
    rate_limit: i64,
    email: Option<&'a str>,
    urls: &'a [String],
    hasbrandinfo: i32,
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = domain_name("domain", body.domain.as_deref())?;
    let host = match body.hostname.as_deref() {
        Some(raw) => domain_name("hostname", Some(raw))?,
        None => mx_hostname_fallback(&domain),
    };
    let mailboxes = at_least_one("mailboxes", body.mailboxes)?.unwrap_or(rules::DEFAULT_MAILBOXES);
    let mailbox_quota =
        at_least_one("mailboxQuota", body.mailbox_quota)?.unwrap_or(rules::DEFAULT_MAILBOX_QUOTA);
    let quota = match body.quota {
        Some(q) if q < 0 => {
            return Err(ApiError::Validation(format!(
                "The quota value `{q}` must be equal or greater than 0"
            )));
        }
        Some(q) => q,
        None => rules::DEFAULT_QUOTA,
    };
    let rate_limit =
        at_least_one("rateLimit", body.rate_limit)?.unwrap_or(rules::DEFAULT_RATE_LIMIT);
    let catchall = catchall(body.email.as_deref().unwrap_or_default())?;
    let urls = urls(body.urls.as_deref().unwrap_or_default())?;
    let hasbrandinfo =
        validate::optional_one_of("hasbrandinfo", body.hasbrandinfo, FLAG, 0)? as i32;
    let outbound_ip = dedicated_ip(body.outbound_ip.as_deref().unwrap_or_default())?;

    let pg = &state.store.pg;
    let exists =
        || ApiError::Conflict(state.i18n.tr(&lang, "domain {} already exists", &[&domain]));
    if store::exists(pg, &domain).await? {
        return Err(exists());
    }
    if let Some(ip) = outbound_ip {
        check_dedicated(&state, &lang, &domain, &host, ip).await?;
    }
    let inserted = store::insert(
        pg,
        &NewDomain {
            domain: &domain,
            a_record: &host,
            mailboxes,
            mailbox_quota,
            quota,
            rate_limit,
            urls: &urls,
            hasbrandinfo,
            now: crate::routes::now(),
        },
    )
    .await?;
    if !inserted {
        return Err(exists());
    }
    if let Err(err) = crate::domains::create_system_mailboxes(&state, &domain).await {
        tracing::warn!(%domain, error = %format!("{err:#}"), "system mailboxes not created");
    }
    if let Some(goto) = &catchall {
        store::set_catchall(pg, &domain, Some(goto), crate::routes::now()).await?;
    }
    // The keys now, so the records shown next include them; rspamd learns
    // of them in the background.
    if let Err(err) = crate::dkim::ensure_keys(&state, &domain).await {
        tracing::warn!(%domain, error = %format!("{err:#}"), "DKIM keys not made");
    }
    sync_signing_soon(&state);
    match crate::domains::adopt_hostname(&state, &host).await {
        Ok(true) => {
            let (st, h) = (state.clone(), host.clone());
            tokio::spawn(async move {
                if let Err(err) = crate::domains::tell_postfix_hostname(&st, &h).await {
                    tracing::warn!(error = %format!("{err:#}"), "Postfix host name not updated");
                }
            });
        }
        Ok(false) => {}
        Err(err) => tracing::warn!(error = %format!("{err:#}"), "host name not set"),
    }
    obtain_certificate(&state, &domain, user.account_id);
    crate::domains::forget(&state, &domain).await;
    audit
        .record_with(
            LogType::Domain,
            &format!("Add domain :{domain} successfully"),
            &Created {
                domain: &domain,
                a_record: &host,
                mailboxes,
                mailbox_quota,
                quota,
                rate_limit,
                email: catchall.as_deref(),
                urls: &urls,
                hasbrandinfo,
            },
        )
        .await;
    if let Some(ip) = outbound_ip {
        crate::multi_ip::add_config(&state, &domain, ip)
            .await
            .map_err(|e| {
                ApiError::Rejected(state.i18n.tr(
                    &lang,
                    "Failed to add dedicated IP: {}",
                    &[&format!("{e:#}")],
                ))
            })?;
        audit
            .record(
                LogType::Domain,
                &format!("Added dedicated sending IP for domain: {domain} -> {ip}"),
            )
            .await;
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Domain added successfully", &[]),
        (),
    ))
}

#[derive(Serialize)]
struct Updated<'a> {
    domain: &'a str,
    #[serde(flatten)]
    changes: &'a DomainChanges,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
}

async fn update(
    State(state): State<AppState>,
    Lang(lang): Lang,
    user: CurrentUser,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = domain_name("domain", body.domain.as_deref())?;
    let host = body
        .hostname
        .as_deref()
        .map(|raw| domain_name("hostname", Some(raw)))
        .transpose()?;
    let catchall = body.email.as_deref().map(catchall).transpose()?;
    let dedicated = body.outbound_ip.as_deref().map(dedicated_ip).transpose()?;
    let mut changes = DomainChanges {
        a_record: None,
        mailboxes: positive("mailboxes", body.mailboxes)?,
        mailbox_quota: positive("mailboxQuota", body.mailbox_quota)?,
        quota: positive("quota", body.quota)?,
        rate_limit: positive("rateLimit", body.rate_limit)?,
        active: body
            .active
            .map(|a| validate::one_of("active", Some(a), FLAG))
            .transpose()?
            .map(|a| a as i32),
        urls: body.urls.as_deref().map(urls).transpose()?,
        hasbrandinfo: body
            .hasbrandinfo
            .map(|h| validate::one_of("hasbrandinfo", Some(h), FLAG))
            .transpose()?
            .map(|h| h as i32),
    };

    let pg = &state.store.pg;
    let current = known(&state, &lang, &name).await?;
    let domain = current.domain.clone();
    changes.a_record = host.filter(|h| *h != current.a_record);
    let mail_host = crate::domains::mail_host(
        &domain,
        changes.a_record.as_deref().unwrap_or(&current.a_record),
    );
    let existing_ip = multi_ip_store::for_domain(pg, &domain).await?;
    let new_ip = match dedicated {
        Some(Some(ip))
            if existing_ip
                .as_ref()
                .is_none_or(|row| row.outbound_ip != ip.to_string()) =>
        {
            check_dedicated(&state, &lang, &domain, &mail_host, ip).await?;
            Some(ip)
        }
        _ => None,
    };

    store::update(pg, &domain, &changes).await?;
    if let Some(goto) = &catchall {
        store::set_catchall(pg, &domain, goto.as_deref(), crate::routes::now()).await?;
    }
    if changes.a_record.is_some() {
        obtain_certificate(&state, &domain, user.account_id);
    }
    crate::domains::forget(&state, &domain).await;
    audit
        .record_with(
            LogType::Domain,
            &format!("Update domain :{domain} successfully"),
            &Updated {
                domain: &domain,
                changes: &changes,
                email: catchall.as_ref().map(|c| c.as_deref().unwrap_or_default()),
            },
        )
        .await;

    // Absent: kept (Go removed it, and the console's form never filled
    // the field in).
    match (dedicated, new_ip, existing_ip) {
        (Some(None), _, Some(_)) => {
            multi_ip_store::delete_for_domain(pg, &domain).await?;
            audit
                .record(
                    LogType::Domain,
                    &format!("Deleted multi-IP domain configuration: {domain}"),
                )
                .await;
            crate::domains::forget(&state, &domain).await;
        }
        (_, Some(ip), existing) => {
            if existing.is_some() {
                multi_ip_store::delete_for_domain(pg, &domain).await?;
            }
            crate::multi_ip::add_config(&state, &domain, ip)
                .await
                .map_err(|e| {
                    ApiError::Rejected(state.i18n.tr(
                        &lang,
                        "Failed to add dedicated IP: {}",
                        &[&format!("{e:#}")],
                    ))
                })?;
            let verb = if existing.is_some() {
                "Updated"
            } else {
                "Added"
            };
            audit
                .record(
                    LogType::Domain,
                    &format!("{verb} dedicated sending IP for domain: {domain} -> {ip}"),
                )
                .await;
            crate::domains::forget(&state, &domain).await;
        }
        _ => {}
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Domain updated successfully", &[]),
        (),
    ))
}

async fn update_brandinfo(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = domain_name("domain", body.domain.as_deref())?;
    let flag = validate::optional_one_of("hasbrandinfo", body.hasbrandinfo, FLAG, 0)? as i32;
    let domain = known(&state, &lang, &name).await?.domain;
    store::update(
        &state.store.pg,
        &domain,
        &DomainChanges {
            hasbrandinfo: Some(flag),
            ..DomainChanges::default()
        },
    )
    .await?;
    audit
        .record(
            LogType::Domain,
            &format!("Update domain :{domain} brandinfo : {flag} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Domain updated brandinfo status successfully", &[]),
        (),
    ))
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = domain_name("domain", body.domain.as_deref())?;
    let domain = known(&state, &lang, &name).await?.domain;
    let Some(removed) = store::delete(&state.store.pg, &domain).await? else {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "domain {} does not exist",
            &[&domain],
        )));
    };
    sync_signing_soon(&state);
    if removed.bcc_rules > 0 {
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(err) = crate::postfix::sync_bcc(&st).await {
                tracing::warn!(error = %format!("{err:#}"), "BCC maps not updated");
            }
        });
    }
    crate::domains::forget(&state, &domain).await;
    audit
        .record_with(
            LogType::Domain,
            &format!("Delete domain :{domain} successfully"),
            &removed,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Domain deleted successfully", &[]),
        (),
    ))
}

/// Go's `BlacklistCheckResult`.
#[derive(Debug, Default, Serialize)]
struct BlockCheck {
    time: i64,
    results: String,
    ip: String,
    tested: i64,
    passed: i64,
    invalid: i64,
    blacklisted: i64,
    black_list: Vec<Listing>,
}

impl From<CheckResult> for BlockCheck {
    fn from(r: CheckResult) -> Self {
        Self {
            time: r.time,
            results: r.domain,
            ip: r.ip,
            tested: r.tested,
            passed: r.passed,
            invalid: r.invalid,
            blacklisted: r.blacklisted,
            black_list: r.black_list,
        }
    }
}

/// A domain as the console lists it (Go's `Domain`).
#[derive(Serialize)]
struct DomainView {
    #[serde(flatten)]
    row: DomainRow,
    dns_records: DnsRecords,
    cert_info: CertSummary,
    email: String,
    default: i32,
    multi_ip_domains: Option<DedicatedIpRow>,
    black_check_result: BlockCheck,
    black_check_log: String,
}

async fn default_domain(state: &AppState) -> Result<String, ApiError> {
    Ok(
        ferropost_store::options::get_string(&state.store.pg, DEFAULT_OPTION)
            .await?
            .unwrap_or_default(),
    )
}

async fn describe(
    state: &AppState,
    row: DomainRow,
    default: &str,
    catchalls: &HashMap<String, String>,
    dedicated: &HashMap<String, DedicatedIpRow>,
) -> DomainView {
    let host = crate::domains::mail_host(&row.domain, &row.a_record);
    let (dns_records, cert, check) = tokio::join!(
        crate::domains::records(state, &row.domain),
        crate::mail_tls::current(state, &host),
        crate::blocklist::result_for(state, &host),
    );
    DomainView {
        dns_records,
        cert_info: cert.ok().flatten().unwrap_or_default(),
        email: catchalls.get(&row.domain).cloned().unwrap_or_default(),
        default: i32::from(row.domain.eq_ignore_ascii_case(default)),
        multi_ip_domains: dedicated.get(&row.domain.to_ascii_lowercase()).cloned(),
        black_check_result: check.map(BlockCheck::from).unwrap_or_default(),
        black_check_log: crate::blocklist::log_path(state, &host),
        row,
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<DomainView>>, ApiError> {
    let page_size = match q.page_size {
        None => 20,
        Some(n) if n <= 0 => 10,
        Some(n) => n,
    };
    let paging = PageRequest::new(q.page.unwrap_or(1), page_size);
    let keyword = q
        .keyword
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty());
    let pg = &state.store.pg;
    let (total, rows) = store::list(pg, keyword, paging.offset, paging.limit).await?;
    let default = default_domain(&state).await?;
    let names: Vec<String> = rows.iter().map(|r| r.domain.clone()).collect();
    let catchalls = store::catchalls(pg, &names).await?;
    let mut dedicated: HashMap<String, DedicatedIpRow> = HashMap::new();
    for row in multi_ip_store::active(pg).await? {
        dedicated
            .entry(row.domain.to_ascii_lowercase())
            .or_insert(row);
    }
    let list = futures_util::stream::iter(rows)
        .map(|row| describe(&state, row, &default, &catchalls, &dedicated))
        .buffered(crate::domains::CHECKS_AT_ONCE)
        .collect()
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        Page { total, list },
    ))
}

#[derive(Serialize)]
struct Listed {
    #[serde(flatten)]
    row: DomainRow,
    default: i32,
}

async fn all(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Vec<Listed>>, ApiError> {
    let default = default_domain(&state).await?;
    let rows = store::all(&state.store.pg).await?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        rows.into_iter()
            .map(|row| Listed {
                default: i32::from(row.domain.eq_ignore_ascii_case(&default)),
                row,
            })
            .collect(),
    ))
}

async fn fresh_dns_records(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<DnsRecords>, ApiError> {
    let name = domain_name("domain", body.domain.as_deref())?;
    let domain = known(&state, &lang, &name).await?.domain;
    let records = crate::domains::refresh(&state, &domain).await;
    audit
        .record_with(
            LogType::Domain,
            &format!("Fresh DNS records for domain :{domain} successfully"),
            &records,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        records,
    ))
}

async fn set_default_domain(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DomainBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let name = domain_name("domain", body.domain.as_deref())?;
    let row = store::get(&state.store.pg, &name)
        .await?
        .filter(|row| row.active == 1)
        .ok_or_else(|| {
            ApiError::NotFound(state.i18n.tr(
                &lang,
                "Domain does not exist or is not activated",
                &[],
            ))
        })?;
    ferropost_store::options::set_string(&state.store.pg, DEFAULT_OPTION, &row.domain).await?;
    audit
        .record_with(
            LogType::Domain,
            &format!("Set default sender domain :{} successfully", row.domain),
            &json!({"domain": row.domain}),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Default sender domain set successfully", &[]),
        (),
    ))
}
