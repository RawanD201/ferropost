//! The send API: keys (`api_templates`, `api_ip_whitelist`) and the mail
//! queued through them (`api_mail_logs`).
//!
//! The queue works like the campaign queue: rows are claimed (status 1)
//! with `FOR UPDATE SKIP LOCKED` and settled one by one, and claims are
//! released when the sender starts. Go's queue lock was a plain `SETEX`
//! that never excluded anyone, and its 15-second deadline cut runs short
//! after sending but before recording, so mail could go out twice.

use std::collections::HashMap;

use anyhow::Result;
use ferropost_domain::send_api::{api_group_name, campaign_id, status};
use ferropost_domain::tracking::API_CAMPAIGN_FLOOR;
use sqlx::PgPool;

use crate::like_contains;

/// A row of `api_templates`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct ApiKey {
    pub id: i32,
    pub api_key: String,
    pub api_name: String,
    pub template_id: i32,
    pub group_id: i32,
    pub subject: String,
    pub addresser: String,
    pub full_name: String,
    pub unsubscribe: i32,
    pub track_open: i32,
    pub track_click: i32,
    pub active: i32,
    pub create_time: i32,
    pub update_time: i32,
    pub expire_time: i32,
    pub last_key_update_time: i32,
}

const COLUMNS: &str = "id, api_key, api_name, template_id, group_id, subject, addresser,
    COALESCE(full_name, '') AS full_name, unsubscribe::int AS unsubscribe,
    track_open::int AS track_open, track_click::int AS track_click, active::int AS active,
    create_time, update_time, COALESCE(expire_time, 0) AS expire_time,
    COALESCE(last_key_update_time, 0) AS last_key_update_time";

pub async fn get(pg: &PgPool, id: i32) -> Result<Option<ApiKey>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM api_templates WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pg)
    .await?)
}

/// An active API by its key.
pub async fn by_key(pg: &PgPool, key: &str) -> Result<Option<ApiKey>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM api_templates WHERE api_key = $1 AND active = 1"
    ))
    .bind(key)
    .fetch_optional(pg)
    .await?)
}

/// Whether `ip` may use the API: always when it has no whitelist.
pub async fn ip_allowed(pg: &PgPool, api_id: i32, ip: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM api_ip_whitelist WHERE api_id = $1)
             OR EXISTS (SELECT 1 FROM api_ip_whitelist WHERE api_id = $1 AND ip = $2)",
    )
    .bind(api_id)
    .bind(ip)
    .fetch_one(pg)
    .await?)
}

pub async fn list(
    pg: &PgPool,
    keyword: Option<&str>,
    active: Option<i32>,
    page: i64,
    page_size: i64,
) -> Result<(i64, Vec<ApiKey>)> {
    let pattern = keyword.map(like_contains);
    let filter = "($1::text IS NULL OR api_name LIKE $1) AND ($2::int IS NULL OR active = $2)";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM api_templates WHERE {filter}"
    ))
    .bind(&pattern)
    .bind(active)
    .fetch_one(pg)
    .await?;
    let list = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM api_templates WHERE {filter} ORDER BY id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(&pattern)
    .bind(active)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pg)
    .await?;
    Ok((total, list))
}

pub async fn whitelists(pg: &PgPool, ids: &[i32]) -> Result<HashMap<i32, Vec<String>>> {
    let rows: Vec<(i32, String)> = sqlx::query_as(
        "SELECT api_id, ip FROM api_ip_whitelist WHERE api_id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(pg)
    .await?;
    let mut out: HashMap<i32, Vec<String>> = HashMap::new();
    for (id, ip) in rows {
        out.entry(id).or_default().push(ip);
    }
    Ok(out)
}

/// Delivery results of an API's sent mail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApiStats {
    pub sends: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub opened: i64,
    pub clicked: i64,
}

/// Results per API in a window (0 means unbounded), in three queries.
/// Go ran four per API, and filtered opens and clicks by `[0, 0]` when no
/// window was given, so its list always showed 0% opened.
pub async fn stats(
    pg: &PgPool,
    ids: &[i32],
    start: i64,
    end: i64,
) -> Result<HashMap<i32, ApiStats>> {
    let window = "($2::bigint <= 0 OR {t}.log_time_millis > $2 * 1000 - 1)
                  AND ($3::bigint <= 0 OR {t}.log_time_millis < $3 * 1000 + 1)";
    let sent: Vec<(i32, i64, i64, i64)> = sqlx::query_as(&format!(
        "SELECT aml.api_id, COUNT(*),
                COUNT(*) FILTER (WHERE sm.status = 'sent' AND sm.dsn LIKE '2.%'),
                COUNT(*) FILTER (WHERE sm.status = 'bounced')
           FROM api_mail_logs aml
           LEFT JOIN mailstat_message_ids mi ON mi.message_id = aml.message_id
           LEFT JOIN mailstat_send_mails sm ON sm.postfix_message_id = mi.postfix_message_id
          WHERE aml.api_id = ANY($1) AND aml.status = 2
            AND {}
          GROUP BY aml.api_id",
        window.replace("{t}", "sm")
    ))
    .bind(ids)
    .bind(start)
    .bind(end)
    .fetch_all(pg)
    .await?;
    let campaigns: Vec<i64> = ids.iter().map(|&id| campaign_id(id)).collect();
    let events = |table: &str| {
        format!(
            "SELECT (campaign_id - {API_CAMPAIGN_FLOOR})::int, COUNT(DISTINCT postfix_message_id)
               FROM {table} t WHERE campaign_id = ANY($1) AND {}
              GROUP BY campaign_id",
            window.replace("{t}", "t")
        )
    };
    let mut counts = Vec::new();
    for table in ["mailstat_opened", "mailstat_clicked"] {
        let rows: Vec<(i32, i64)> = sqlx::query_as(&events(table))
            .bind(&campaigns)
            .bind(start)
            .bind(end)
            .fetch_all(pg)
            .await?;
        counts.push(rows);
    }
    let clicked = counts.pop().unwrap_or_default();
    let opened = counts.pop().unwrap_or_default();

    let mut out: HashMap<i32, ApiStats> = HashMap::new();
    for (id, sends, delivered, bounced) in sent {
        let s = out.entry(id).or_default();
        (s.sends, s.delivered, s.bounced) = (sends, delivered, bounced);
    }
    for (id, n) in opened {
        out.entry(id).or_default().opened = n;
    }
    for (id, n) in clicked {
        out.entry(id).or_default().clicked = n;
    }
    Ok(out)
}

pub async fn all_ids(pg: &PgPool) -> Result<Vec<i32>> {
    Ok(
        sqlx::query_scalar("SELECT id FROM api_templates ORDER BY id")
            .fetch_all(pg)
            .await?,
    )
}

/// Settings of an API key.
#[derive(Debug, Clone)]
pub struct ApiSettings<'a> {
    pub api_name: &'a str,
    pub template_id: i32,
    pub group_id: i32,
    pub subject: &'a str,
    pub addresser: &'a str,
    pub full_name: &'a str,
    pub unsubscribe: i32,
    pub track_open: i32,
    pub track_click: i32,
    pub active: i32,
    pub expire_time: i32,
    pub ip_whitelist: &'a [String],
}

async fn replace_whitelist(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    api_id: i32,
    ips: &[String],
    now: i32,
) -> Result<()> {
    sqlx::query("DELETE FROM api_ip_whitelist WHERE api_id = $1")
        .bind(api_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO api_ip_whitelist (api_id, ip, create_time)
         SELECT $1, ip, $3 FROM unnest($2::text[]) AS ip",
    )
    .bind(api_id)
    .bind(ips)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn create(pg: &PgPool, s: &ApiSettings<'_>, key: &str, now: i32) -> Result<i32> {
    let mut tx = pg.begin().await?;
    let id: i32 = sqlx::query_scalar(
        "INSERT INTO api_templates (api_key, api_name, template_id, group_id, subject, addresser,
             full_name, unsubscribe, track_open, track_click, active, create_time, update_time,
             expire_time, last_key_update_time)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, 0, $12) RETURNING id",
    )
    .bind(key)
    .bind(s.api_name)
    .bind(s.template_id)
    .bind(s.group_id)
    .bind(s.subject)
    .bind(s.addresser)
    .bind(s.full_name)
    .bind(s.unsubscribe as i16)
    .bind(s.track_open as i16)
    .bind(s.track_click as i16)
    .bind(s.active as i16)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    replace_whitelist(&mut tx, id, s.ip_whitelist, now).await?;
    tx.commit().await?;
    Ok(id)
}

/// Replaces the settings (as Go did), and the key when `new_key` is given.
pub async fn update(
    pg: &PgPool,
    id: i32,
    s: &ApiSettings<'_>,
    new_key: Option<&str>,
    now: i32,
) -> Result<()> {
    let mut tx = pg.begin().await?;
    sqlx::query(
        "UPDATE api_templates SET api_name = $2, template_id = $3, group_id = $4, subject = $5,
            addresser = $6, full_name = $7, unsubscribe = $8, track_open = $9, track_click = $10,
            active = $11, expire_time = $12, update_time = $13,
            api_key = COALESCE($14, api_key),
            last_key_update_time = CASE WHEN $14::text IS NULL THEN last_key_update_time ELSE $13 END
          WHERE id = $1",
    )
    .bind(id)
    .bind(s.api_name)
    .bind(s.template_id)
    .bind(s.group_id)
    .bind(s.subject)
    .bind(s.addresser)
    .bind(s.full_name)
    .bind(s.unsubscribe as i16)
    .bind(s.track_open as i16)
    .bind(s.track_click as i16)
    .bind(s.active as i16)
    .bind(s.expire_time)
    .bind(now)
    .bind(new_key)
    .execute(&mut *tx)
    .await?;
    replace_whitelist(&mut tx, id, s.ip_whitelist, now).await?;
    tx.commit().await?;
    Ok(())
}

/// Deletes an API with its whitelist and queue.
pub async fn delete(pg: &PgPool, id: i32) -> Result<Option<ApiKey>> {
    let mut tx = pg.begin().await?;
    sqlx::query("DELETE FROM api_mail_logs WHERE api_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM api_ip_whitelist WHERE api_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query_as(&format!(
        "DELETE FROM api_templates WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(deleted)
}

/// The contact group an API's recipients go to: its own, or
/// `api_group_<id>` created on first use (Go: `ensureContactAndGroup`).
pub async fn recipient_group(
    pg: &PgPool,
    api: &ApiKey,
    description: &str,
    now: i32,
) -> Result<i32> {
    if api.group_id > 0 {
        return Ok(api.group_id);
    }
    let name = api_group_name(api.id);
    sqlx::query(
        "INSERT INTO bm_contact_groups (name, description, create_time, update_time)
         VALUES ($1, $2, $3, $3) ON CONFLICT (name) DO NOTHING",
    )
    .bind(&name)
    .bind(description)
    .bind(now)
    .execute(pg)
    .await?;
    Ok(
        sqlx::query_scalar("SELECT id FROM bm_contact_groups WHERE name = $1")
            .bind(&name)
            .fetch_one(pg)
            .await?,
    )
}

/// Adds the addresses to the group as confirmed subscribers when new and
/// returns those that may be mailed: not unsubscribed from it. Go mailed
/// people who had unsubscribed when the API had its own group.
pub async fn accept_recipients(
    pg: &PgPool,
    group_id: i32,
    emails: &[String],
    now: i32,
) -> Result<Vec<String>> {
    sqlx::query(
        "INSERT INTO bm_contacts (email, group_id, active, status, create_time)
         SELECT e, $1, 1, 1, $3 FROM unnest($2::text[]) AS e
         ON CONFLICT (group_id, email) DO NOTHING",
    )
    .bind(group_id)
    .bind(emails)
    .bind(now)
    .execute(pg)
    .await?;
    let unsubscribed: Vec<String> = sqlx::query_scalar(
        "SELECT email FROM bm_contacts WHERE group_id = $1 AND email = ANY($2) AND active = 0",
    )
    .bind(group_id)
    .bind(emails)
    .fetch_all(pg)
    .await?;
    Ok(emails
        .iter()
        .filter(|e| !unsubscribed.contains(e))
        .cloned()
        .collect())
}

/// Queues messages: `(recipient, message ID without brackets)`.
pub async fn enqueue(
    pg: &PgPool,
    api_id: i32,
    addresser: &str,
    messages: &[(String, String)],
    attribs: &serde_json::Value,
    now: i32,
) -> Result<u64> {
    let mut queued = 0;
    for chunk in messages.chunks(5000) {
        let recipients: Vec<&str> = chunk.iter().map(|(r, _)| r.as_str()).collect();
        let ids: Vec<&str> = chunk.iter().map(|(_, m)| m.as_str()).collect();
        queued += sqlx::query(
            "INSERT INTO api_mail_logs (api_id, recipient, message_id, addresser, status,
                 error_message, send_time, create_time, attribs)
             SELECT $1, r, m, $2, 0, '', 0, $3, $4 FROM unnest($5::text[], $6::text[]) AS q(r, m)",
        )
        .bind(api_id)
        .bind(addresser)
        .bind(now)
        .bind(attribs)
        .bind(&recipients)
        .bind(&ids)
        .execute(pg)
        .await?
        .rows_affected();
    }
    Ok(queued)
}

/// A queued message.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Queued {
    pub id: i32,
    pub api_id: i32,
    pub recipient: String,
    pub addresser: String,
    pub message_id: String,
    pub attribs: serde_json::Value,
}

pub async fn claim(pg: &PgPool, limit: i64) -> Result<Vec<Queued>> {
    let mut rows: Vec<Queued> = sqlx::query_as(
        "UPDATE api_mail_logs l SET status = 1
           FROM (SELECT id FROM api_mail_logs WHERE status = 0 ORDER BY id LIMIT $1
                 FOR UPDATE SKIP LOCKED) c
          WHERE l.id = c.id
         RETURNING l.id, l.api_id, l.recipient, l.addresser, l.message_id,
                   COALESCE(l.attribs, '{}'::jsonb) AS attribs",
    )
    .bind(limit)
    .fetch_all(pg)
    .await?;
    rows.sort_by_key(|r| r.id);
    Ok(rows)
}

pub async fn release_claims(pg: &PgPool) -> Result<u64> {
    Ok(
        sqlx::query("UPDATE api_mail_logs SET status = 0 WHERE status = 1")
            .execute(pg)
            .await?
            .rows_affected(),
    )
}

/// Records the outcome of a queued message.
pub async fn settle(pg: &PgPool, id: i32, error: Option<&str>, now: i64) -> Result<()> {
    let state = if error.is_some() {
        status::FAILED
    } else {
        status::SENT
    };
    sqlx::query(
        "UPDATE api_mail_logs SET status = $2, error_message = $3, send_time = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(state as i16)
    .bind(error.unwrap_or_default())
    .bind(now as i32)
    .execute(pg)
    .await?;
    Ok(())
}

/// Group ID of an API's recipients, if it has one yet.
pub async fn existing_recipient_group(pg: &PgPool, api: &ApiKey) -> Result<Option<i32>> {
    if api.group_id > 0 {
        return Ok(Some(api.group_id));
    }
    Ok(
        sqlx::query_scalar("SELECT id FROM bm_contact_groups WHERE name = $1")
            .bind(api_group_name(api.id))
            .fetch_optional(pg)
            .await?,
    )
}
