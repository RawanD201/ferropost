//! Recipients that keep failing (`abnormal_recipient`). Campaigns skip an
//! address once its count reaches 3 (see `campaigns::audience`).

use anyhow::Result;
use sqlx::PgPool;

use crate::like_contains;

/// A row of `abnormal_recipient`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct AbnormalRecipient {
    pub id: i32,
    pub recipient: String,
    pub create_time: i32,
    pub description: String,
    pub count: i32,
    pub add_type: i32,
}

/// How an entry was added (`add_type`).
pub mod source {
    pub const MANUAL: i32 = 1;
    pub const BOUNCES: i32 = 2;
    pub const GROUP_SCAN: i32 = 3;
}

/// The count from which campaigns skip an address.
pub const BLOCKING_COUNT: i32 = 3;

pub async fn list(
    pg: &PgPool,
    keyword: Option<&str>,
    add_type: Option<i32>,
    page: i64,
    page_size: i64,
) -> Result<(i64, Vec<AbnormalRecipient>)> {
    let pattern = keyword.map(like_contains);
    let filter = "($1::text IS NULL OR recipient LIKE $1) AND ($2::int IS NULL OR add_type = $2)";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM abnormal_recipient WHERE {filter}"
    ))
    .bind(&pattern)
    .bind(add_type)
    .fetch_one(pg)
    .await?;
    let list = sqlx::query_as(&format!(
        "SELECT id, recipient, create_time, description, count, add_type::int AS add_type
           FROM abnormal_recipient WHERE {filter}
          ORDER BY create_time DESC, id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(&pattern)
    .bind(add_type)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pg)
    .await?;
    Ok((total, list))
}

/// Blocks an address by hand. An address already recorded is raised to the
/// blocking count too (Go left an existing entry as it was, so a manual
/// block of an address seen once did not block it).
pub async fn add_manual(pg: &PgPool, recipient: &str, now: i32) -> Result<()> {
    sqlx::query(
        "INSERT INTO abnormal_recipient (recipient, count, add_type, description, create_time)
         VALUES ($1, $2, $3, 'Manually added', $4)
         ON CONFLICT (recipient) DO UPDATE
            SET count = GREATEST(abnormal_recipient.count, EXCLUDED.count),
                add_type = EXCLUDED.add_type, description = EXCLUDED.description",
    )
    .bind(recipient)
    .bind(BLOCKING_COUNT)
    .bind(source::MANUAL as i16)
    .bind(now)
    .execute(pg)
    .await?;
    Ok(())
}

/// Deletes an entry and returns its address.
pub async fn delete(pg: &PgPool, id: i32) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("DELETE FROM abnormal_recipient WHERE id = $1 RETURNING recipient")
            .bind(id)
            .fetch_optional(pg)
            .await?,
    )
}

pub async fn clear(pg: &PgPool) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM abnormal_recipient")
        .execute(pg)
        .await?
        .rows_affected())
}

/// Counts one more failure for each `(address, reason)`, in one statement
/// (Go: `BatchUpsertAbnormalRecipientsWithDetails`).
pub async fn record_failures(
    pg: &PgPool,
    failures: &[(String, String)],
    add_type: i32,
    base_description: &str,
    now: i32,
) -> Result<u64> {
    if failures.is_empty() {
        return Ok(0);
    }
    let (emails, reasons): (Vec<&str>, Vec<String>) = failures
        .iter()
        // `description` is VARCHAR(255); a long bounce text failed Go's
        // whole batch.
        .map(|(e, r)| {
            let d: String = format!("{base_description} - {r}")
                .chars()
                .take(255)
                .collect();
            (e.as_str(), d)
        })
        .unzip();
    Ok(sqlx::query(
        "INSERT INTO abnormal_recipient (recipient, count, add_type, description, create_time)
         SELECT e, 1, $3, d, $4 FROM unnest($1::text[], $2::text[]) AS f(e, d)
         ON CONFLICT (recipient) DO UPDATE
            SET count = abnormal_recipient.count + 1, add_type = EXCLUDED.add_type,
                description = EXCLUDED.description",
    )
    .bind(&emails)
    .bind(&reasons)
    .bind(add_type as i16)
    .bind(now)
    .execute(pg)
    .await?
    .rows_affected())
}

/// Addresses that bounced in `(since, until]` (Unix seconds) with the
/// latest reason each (Go kept the oldest).
pub async fn bounced_between(pg: &PgPool, since: i64, until: i64) -> Result<Vec<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT DISTINCT ON (recipient) recipient, description
           FROM mailstat_send_mails
          WHERE status = 'bounced' AND recipient <> ''
            AND log_time_millis > $1 * 1000 AND log_time_millis <= $2 * 1000
          ORDER BY recipient, log_time_millis DESC",
    )
    .bind(since)
    .bind(until)
    .fetch_all(pg)
    .await?)
}

/// Subscribed addresses of a group.
pub async fn group_addresses(pg: &PgPool, group_id: i32) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT email FROM bm_contacts WHERE group_id = $1 AND active = 1 ORDER BY email",
    )
    .bind(group_id)
    .fetch_all(pg)
    .await?)
}

/// Removes addresses from a group.
pub async fn remove_from_group(pg: &PgPool, group_id: i32, emails: &[String]) -> Result<u64> {
    Ok(
        sqlx::query("DELETE FROM bm_contacts WHERE group_id = $1 AND email = ANY($2)")
            .bind(group_id)
            .bind(emails)
            .execute(pg)
            .await?
            .rows_affected(),
    )
}
