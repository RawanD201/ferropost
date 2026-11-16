//! `/api/mailbox/*` (Go: `controller/mail_boxes`).
//!
//! Differences from Go: new and changed passwords are hashed with
//! SHA512-CRYPT (Go wrote MD5-CRYPT); an imported mailbox without a
//! password gets a random one (Go set `123456` on every such mailbox,
//! readable by anyone over IMAP and SMTP) and the default quota (Go: 1000
//! bytes); `mailbox/all` no longer returns password hashes and the list
//! leaves out the reversible copy; the audit log never records passwords
//! (Go logged the reversible copy); `update` keeps fields it is not given
//! (Go reset them to the defaults); the domain must exist and local parts
//! are validated (Go's pattern was unanchored); batch creation uses a
//! secure random generator (Go seeded `math/rand` with the time) and only
//! reports mailboxes it actually created.

use axum::Router;
use axum::extract::State;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_domain::contacts::is_valid_email;
use ferropost_domain::mail::{is_safe_hostname, mx_hostname_fallback};
use ferropost_domain::mailboxes::{
    DEFAULT_QUOTA, ImportEntry, Mailbox, export, local_part_valid, parse_import,
};
use ferropost_domain::paging::Page;
use ferropost_sender::smtp::{decode_mailbox_password, mailbox_credentials, random_password};
use ferropost_store::Write;
use ferropost_store::mailboxes::{self as store, MailboxChanges, NewMailbox};
use serde::{Deserialize, Serialize};

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::{ApiQuery, opt_i64, opt_string};
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/mailbox/create", post(create))
        .route("/api/mailbox/batch_create", post(batch_create))
        .route("/api/mailbox/update", post(update))
        .route("/api/mailbox/delete", post(delete))
        .route("/api/mailbox/list", get(list))
        .route("/api/mailbox/all", get(all))
        .route("/api/mailbox/all_email", get(all_email))
        .route("/api/mailbox/export", post(export_file))
        .route("/api/mailbox/import", post(import))
}

const FLAG: &[i64] = &[0, 1];
const MIN_PASSWORD: usize = 8;
const MAX_BATCH: i64 = 5000;

/// A domain field: a hostname this server handles, lower-cased.
async fn known_domain(
    state: &AppState,
    lang: &str,
    value: &Option<String>,
) -> Result<String, ApiError> {
    let domain = validate::required("domain", value)?.to_ascii_lowercase();
    if !(is_safe_hostname(&domain) && domain.contains('.')) {
        return Err(ApiError::Validation(format!(
            "The domain value `{domain}` is not a valid domain format"
        )));
    }
    if !store::domain_exists(&state.store.pg, &domain).await? {
        return Err(ApiError::Rejected(state.i18n.tr(
            lang,
            "Domain not found",
            &[],
        )));
    }
    Ok(domain)
}

/// An optional domain filter.
fn domain_filter(value: &Option<String>) -> Result<Option<String>, ApiError> {
    match value.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        None => Ok(None),
        Some(d) if is_safe_hostname(d) && d.contains('.') => Ok(Some(d.to_ascii_lowercase())),
        Some(d) => Err(ApiError::Validation(format!(
            "The domain value `{d}` is not a valid domain format"
        ))),
    }
}

fn check_password(password: &str) -> Result<(), ApiError> {
    // GoFrame echoed the password in this message; it is left out.
    if password.chars().count() < MIN_PASSWORD {
        return Err(ApiError::Validation(format!(
            "The password length must be equal or greater than {MIN_PASSWORD}"
        )));
    }
    Ok(())
}

fn credentials(password: &str) -> Result<(String, String), ApiError> {
    Ok(mailbox_credentials(password)?)
}

/// Prepares the maildir and has Dovecot recount usage.
fn prepare_maildir(
    state: &AppState,
    username: &str,
    domain: &str,
    local: &str,
    quota: i64,
    quota_active: bool,
) {
    let dir = crate::maildir::dir(state, domain, local);
    match crate::maildir::ensure(&dir, quota, quota_active) {
        Ok(true) => crate::maildir::recalc(state, username),
        Ok(false) => {}
        Err(err) => tracing::warn!(%username, path = %dir.display(), %err, "maildir not prepared"),
    }
}

/// What the audit log records of a mailbox: never its passwords.
#[derive(Serialize)]
struct Logged<'a> {
    username: &'a str,
    full_name: &'a str,
    is_admin: i32,
    quota: i64,
    quota_active: i32,
    active: i32,
}

impl<'a> From<&'a Mailbox> for Logged<'a> {
    fn from(m: &'a Mailbox) -> Self {
        Self {
            username: &m.username,
            full_name: &m.full_name,
            is_admin: m.is_admin,
            quota: m.quota,
            quota_active: m.quota_active,
            active: m.active,
        }
    }
}

#[derive(Debug, Deserialize)]
struct MailboxBody {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    full_name: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    local_part: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    password: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    active: Option<i64>,
    #[serde(default, rename = "isAdmin", deserialize_with = "opt_i64")]
    is_admin: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    quota: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    quota_active: Option<i64>,
}

fn local_part(value: &Option<String>) -> Result<String, ApiError> {
    let local = validate::required("local_part", value)?.to_ascii_lowercase();
    if !local_part_valid(&local) {
        return Err(ApiError::Validation(format!(
            "The local_part value `{local}` is not a valid mailbox name"
        )));
    }
    Ok(local)
}

fn quota(value: Option<i64>) -> Result<Option<i64>, ApiError> {
    match value {
        Some(q) if q < 0 => Err(ApiError::Validation(format!(
            "The quota value `{q}` must be equal or greater than 0"
        ))),
        other => Ok(other),
    }
}

async fn create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<MailboxBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = known_domain(&state, &lang, &body.domain).await?;
    let local = local_part(&body.local_part)?;
    let password = validate::required("password", &body.password)?;
    check_password(password)?;
    let username = format!("{local}@{domain}");
    if !is_valid_email(&username) {
        return Err(ApiError::Validation(format!(
            "`{username}` is not a valid email address"
        )));
    }
    let active = validate::optional_one_of("active", body.active, FLAG, 1)? as i32;
    let is_admin = validate::optional_one_of("isAdmin", body.is_admin, FLAG, 0)? as i32;
    let quota_active =
        validate::optional_one_of("quota_active", body.quota_active, FLAG, 1)? as i32;
    let quota = quota(body.quota)?.unwrap_or(DEFAULT_QUOTA);
    let full_name = body
        .full_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or(&local)
        .to_owned();
    let (hash, encoded) = credentials(password)?;
    let written = store::create(
        &state.store.pg,
        &NewMailbox {
            username: &username,
            local_part: &local,
            domain: &domain,
            full_name: &full_name,
            password_hash: &hash,
            password_encoded: &encoded,
            quota,
            quota_active,
            is_admin,
            active,
            now: now(),
        },
    )
    .await?;
    if written == Write::Duplicate {
        return Err(ApiError::Conflict(state.i18n.tr(
            &lang,
            "mailbox {} already exists",
            &[&username],
        )));
    }
    prepare_maildir(&state, &username, &domain, &local, quota, quota_active == 1);
    let logged = Logged {
        username: &username,
        full_name: &full_name,
        is_admin,
        quota,
        quota_active,
        active,
    };
    audit
        .record_with(
            LogType::Mailboxes,
            &format!("Add email address :{username} successfully"),
            &logged,
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Mailbox added successfully", &[]),
        (),
    ))
}

async fn update(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<MailboxBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let domain = validate::required("domain", &body.domain)?.to_ascii_lowercase();
    let local = local_part(&body.local_part)?;
    let username = format!("{local}@{domain}");
    let new_credentials = match body
        .password
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        Some(password) => {
            check_password(password)?;
            Some(credentials(password)?)
        }
        None => None,
    };
    let opt_flag = |field: &str, value: Option<i64>| -> Result<Option<i32>, ApiError> {
        value
            .map(|v| validate::one_of(field, Some(v), FLAG).map(|v| v as i32))
            .transpose()
    };
    let changes = MailboxChanges {
        full_name: Some(
            body.full_name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(&local)
                .to_owned(),
        ),
        credentials: new_credentials,
        is_admin: opt_flag("isAdmin", body.is_admin)?,
        quota: quota(body.quota)?,
        active: opt_flag("active", body.active)?,
        quota_active: opt_flag("quota_active", body.quota_active)?,
    };
    let (before, after) = store::update(&state.store.pg, &username, &changes, now())
        .await?
        .ok_or_else(|| ApiError::NotFound(state.i18n.tr(&lang, "Mailbox not found", &[])))?;
    if (before.quota, before.quota_active) != (after.quota, after.quota_active) {
        prepare_maildir(
            &state,
            &username,
            &after.domain,
            &after.local_part,
            after.quota,
            after.quota_active == 1,
        );
    }
    audit
        .record_with(
            LogType::Mailboxes,
            &format!("Updated mailbox:{username} successfully"),
            &Logged::from(&after),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Mailbox updated successfully", &[]),
        (),
    ))
}

#[derive(Debug, Deserialize)]
struct BatchBody {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    quota: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    count: Option<i64>,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    quota_active: Option<i64>,
}

fn random_letters(n: usize) -> String {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    (0..n)
        .map(|_| char::from(rng.gen_range(b'a'..=b'z')))
        .collect()
}

async fn batch_create(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<BatchBody>,
) -> Result<ApiResponse<Vec<String>>, ApiError> {
    let domain = known_domain(&state, &lang, &body.domain).await?;
    let count = body
        .count
        .ok_or_else(|| ApiError::Validation("The count field is required".to_owned()))?;
    if count < 2 {
        return Err(ApiError::Validation(format!(
            "The count value `{count}` must be equal or greater than 2"
        )));
    }
    if count > MAX_BATCH {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "You cannot create more than 5000 batches",
            &[],
        )));
    }
    let prefix = match body.prefix.as_deref().map(str::trim) {
        None | Some("") => random_letters(4),
        Some(p)
            if p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            p.to_ascii_lowercase()
        }
        Some(_) => {
            return Err(ApiError::Rejected(state.i18n.tr(
                &lang,
                "Prefixes can contain only letters, numbers, underscores, and hyphens",
                &[],
            )));
        }
    };
    let quota = quota(body.quota)?.unwrap_or(DEFAULT_QUOTA);
    let quota_active =
        validate::optional_one_of("quota_active", body.quota_active, FLAG, 1)? as i32;

    // Hashing thousands of passwords is CPU work: spread it over threads.
    let names: Vec<String> = (0..count)
        .map(|i| format!("{prefix}{i}{}", random_letters(2)))
        .collect();
    let hashed = tokio::task::spawn_blocking(move || {
        let threads = std::thread::available_parallelism().map_or(2, usize::from);
        let chunk = names.len().div_ceil(threads).max(1);
        std::thread::scope(|scope| {
            let handles: Vec<_> = names
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        part.iter()
                            .map(|local| {
                                let (hash, encoded) = mailbox_credentials(&random_password())?;
                                Ok::<_, anyhow::Error>((local.clone(), hash, encoded))
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .map_err(|_| anyhow::anyhow!("hashing thread panicked"))?
                })
                .collect::<Result<Vec<Vec<_>>, _>>()
                .map(|parts| parts.concat())
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))??;

    let usernames: Vec<String> = hashed
        .iter()
        .map(|(local, ..)| format!("{local}@{domain}"))
        .collect();
    let rows: Vec<NewMailbox> = hashed
        .iter()
        .zip(&usernames)
        .map(|((local, hash, encoded), username)| NewMailbox {
            username,
            local_part: local,
            domain: &domain,
            full_name: local,
            password_hash: hash,
            password_encoded: encoded,
            quota,
            quota_active,
            is_admin: 0,
            active: 1,
            now: now(),
        })
        .collect();
    let created = store::insert_many(&state.store.pg, &rows).await?;
    if created.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Failed to create any mailbox",
            &[],
        )));
    }
    if quota_active == 1 && quota > 0 {
        let (state, created, domain) = (state.clone(), created.clone(), domain.clone());
        tokio::spawn(async move {
            for username in created {
                let local = username.split('@').next().unwrap_or_default().to_owned();
                prepare_maildir(&state, &username, &domain, &local, quota, true);
            }
        });
    }
    audit
        .record_with(
            LogType::Mailboxes,
            "Batch email creation was successful",
            &serde_json::json!({"domain": domain, "count": count, "prefix": prefix, "quota": quota}),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "{} email accounts were successfully created",
            &[&created.len()],
        ),
        created,
    ))
}

#[derive(Debug, Deserialize)]
struct DeleteBody {
    #[serde(default)]
    emails: Option<Vec<String>>,
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<DeleteBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let emails = body.emails.unwrap_or_default();
    if emails.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Email addresses cannot be empty",
            &[],
        )));
    }
    let emails: Vec<String> = emails
        .iter()
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .collect();
    if emails.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "No valid email addresses provided",
            &[],
        )));
    }
    let deleted = store::delete_many(&state.store.pg, &emails).await?;
    for email in &deleted {
        audit
            .record(
                LogType::Mailboxes,
                &format!("Deleted mailbox:{email} successfully"),
            )
            .await;
    }
    let msg = if deleted.is_empty() {
        state
            .i18n
            .tr(&lang, "No mailboxes were deleted (they may not exist)", &[])
    } else {
        state.i18n.tr(
            &lang,
            "Successfully deleted {} mailbox(es)",
            &[&deleted.len()],
        )
    };
    Ok(ApiResponse::ok(msg, ()))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default, deserialize_with = "opt_string")]
    keyword: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_i64")]
    page: Option<i64>,
    #[serde(default, deserialize_with = "opt_i64")]
    page_size: Option<i64>,
}

#[derive(Serialize)]
struct Listed {
    #[serde(flatten)]
    mailbox: Mailbox,
    /// The mail host name to point MX records at.
    mx: String,
}

/// Mailboxes with their password in clear, which the console shows (as in
/// Go); the reversible copy itself is not sent.
async fn list(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> Result<ApiResponse<Page<Listed>>, ApiError> {
    let pg = &state.store.pg;
    let domain = domain_filter(&q.domain)?;
    let page = q.page.filter(|p| *p > 0).unwrap_or(1);
    let page_size = q.page_size.filter(|p| *p > 0).unwrap_or(10).min(1000);
    let (total, rows) =
        store::list(pg, domain.as_deref(), q.keyword.as_deref(), page, page_size).await?;
    let mut hosts = std::collections::HashMap::new();
    let mut list = Vec::with_capacity(rows.len());
    for mut mailbox in rows {
        if !hosts.contains_key(&mailbox.domain) {
            let host = ferropost_store::domains::mail_hostname(pg, &mailbox.domain)
                .await?
                .unwrap_or_else(|| mx_hostname_fallback(&mailbox.domain));
            hosts.insert(mailbox.domain.clone(), host);
        }
        mailbox.password = decode_mailbox_password(&mailbox.password_encode).unwrap_or_default();
        mailbox.password_encode = String::new();
        list.push(Listed {
            mx: hosts[&mailbox.domain].clone(),
            mailbox,
        });
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        Page { total, list },
    ))
}

#[derive(Debug, Deserialize)]
struct DomainQuery {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
}

async fn all(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<DomainQuery>,
) -> Result<ApiResponse<Vec<Mailbox>>, ApiError> {
    let domain = domain_filter(&q.domain)?;
    let mut rows = store::all(&state.store.pg, domain.as_deref()).await?;
    for m in &mut rows {
        m.password.clear();
        m.password_encode.clear();
    }
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), rows))
}

async fn all_email(
    State(state): State<AppState>,
    Lang(lang): Lang,
    ApiQuery(q): ApiQuery<DomainQuery>,
) -> Result<ApiResponse<Vec<String>>, ApiError> {
    let domain = domain_filter(&q.domain)?;
    let rows = store::usernames(&state.store.pg, domain.as_deref()).await?;
    Ok(ApiResponse::ok(state.i18n.tr(&lang, "Success", &[]), rows))
}

#[derive(Debug, Deserialize)]
struct ExportBody {
    #[serde(default, deserialize_with = "opt_string")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    file_type: Option<String>,
}

/// A file with the mailboxes, for moving them to another server: the CSV
/// and JSON files hold the hashes and reversible passwords, as in Go.
async fn export_file(
    State(state): State<AppState>,
    audit: Audit,
    ApiQuery(q): ApiQuery<ExportBody>,
    ApiBody(body): ApiBody<ExportBody>,
) -> Result<Response, ApiError> {
    let domain = domain_filter(&body.domain.or(q.domain))?;
    let file_type = body
        .file_type
        .or(q.file_type)
        .unwrap_or_else(|| "csv".to_owned());
    validate::str_one_of(
        "file_type",
        &Some(file_type.clone()),
        &["csv", "txt", "json"],
    )?;
    let rows = store::all(&state.store.pg, domain.as_deref()).await?;
    let (content, _kind, name) = export(&file_type, &rows)
        .ok_or_else(|| ApiError::Rejected("Unsupported export type".to_owned()))?;
    audit
        .record_with(
            LogType::Mailboxes,
            "Exporting the email box was successful.",
            &serde_json::json!({"domain": domain, "file_type": file_type, "count": rows.len()}),
        )
        .await;
    Ok((
        [
            (CONTENT_TYPE, "application/octet-stream".to_owned()),
            (CONTENT_DISPOSITION, format!("attachment; filename={name}")),
        ],
        content,
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
struct ImportBody {
    #[serde(default)]
    file_data: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    file_type: Option<String>,
}

/// Credentials of an imported mailbox: Go's export carries the hash and
/// the reversible copy; otherwise a plaintext password or a random one.
fn import_credentials(e: &ImportEntry) -> anyhow::Result<(String, String)> {
    match (e.password.is_empty(), e.password_encode.is_empty()) {
        (false, false) => Ok((e.password.clone(), e.password_encode.clone())),
        (true, false) => mailbox_credentials(&decode_mailbox_password(&e.password_encode)?),
        (false, true) => mailbox_credentials(&e.password),
        (true, true) => mailbox_credentials(&random_password()),
    }
}

async fn import(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<ImportBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let content = body.file_data.unwrap_or_default();
    if content.trim().is_empty() {
        return Err(ApiError::Validation(
            "The file_data field is required".to_owned(),
        ));
    }
    let file_type = body.file_type.unwrap_or_else(|| "csv".to_owned());
    let entries = parse_import(&file_type, &content)
        .map_err(|msg| ApiError::Rejected(state.i18n.tr(&lang, msg, &[])))?;
    if entries.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Failed to parse valid email data",
            &[],
        )));
    }
    let pg = &state.store.pg;
    let total = entries.len();
    let mut failed = Vec::new();
    let mut imported = 0usize;
    for entry in entries.into_iter().map(ImportEntry::normalise) {
        let valid = is_valid_email(&entry.username)
            && local_part_valid(&entry.local_part)
            && store::domain_exists(pg, &entry.domain).await?;
        let creds = if valid {
            import_credentials(&entry).ok()
        } else {
            None
        };
        let Some((hash, encoded)) = creds else {
            failed.push(entry.username);
            continue;
        };
        let inserted = store::insert(
            pg,
            &NewMailbox {
                username: &entry.username,
                local_part: &entry.local_part,
                domain: &entry.domain,
                full_name: &entry.full_name,
                password_hash: &hash,
                password_encoded: &encoded,
                quota: entry.quota,
                quota_active: 1,
                is_admin: entry.is_admin.clamp(0, 1),
                active: entry.active.clamp(0, 1),
                now: now(),
            },
        )
        .await?;
        if inserted {
            imported += 1;
            prepare_maildir(
                &state,
                &entry.username,
                &entry.domain,
                &entry.local_part,
                entry.quota,
                true,
            );
        } else {
            failed.push(entry.username);
        }
    }
    audit
        .record_with(
            LogType::Mailboxes,
            &format!(
                "Import of email account was successful. Total: {total}, Success: {imported}, Failed: {}",
                failed.len()
            ),
            &serde_json::json!({"total": total, "success": imported, "failed": failed.len(), "failed_list": failed}),
        )
        .await;
    if !failed.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "The import is complete, but {} email addresses failed to be imported",
            &[&failed.len()],
        )));
    }
    Ok(ApiResponse::ok(
        state.i18n.tr(
            &lang,
            "Import completed. A total of {} email addresses were imported.",
            &[&imported],
        ),
        (),
    ))
}
