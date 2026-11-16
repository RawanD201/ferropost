//! BCC rules (`bm_bcc`) and mail forwarding (`alias`, which Postfix reads
//! directly; it also holds each domain's catch-all, `@domain`).

use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;

fn like(keyword: Option<&str>) -> Option<String> {
    keyword.map(|k| {
        format!(
            "%{}%",
            k.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    })
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct BccRule {
    pub id: i32,
    #[serde(rename = "type")]
    #[sqlx(rename = "type")]
    pub kind: String,
    pub address: String,
    pub goto: String,
    pub domain: String,
    pub create_time: i64,
    pub update_time: i64,
    pub active: i32,
}

const BCC_COLUMNS: &str = "id, type, address, goto, domain, create_time::bigint AS create_time,
    update_time::bigint AS update_time, active::int AS active";

/// Newest first. Unlike Go, the search narrows the type and domain filters
/// instead of replacing them.
pub async fn bcc_list(
    pg: &PgPool,
    kind: Option<&str>,
    domain: Option<&str>,
    keyword: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(i64, Vec<BccRule>)> {
    let filter = "($1::text IS NULL OR type = $1) AND ($2::text IS NULL OR domain = $2)
                  AND ($3::text IS NULL OR address ILIKE $3 OR goto ILIKE $3)";
    let pattern = like(keyword);
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM bm_bcc WHERE {filter}"))
        .bind(kind)
        .bind(domain)
        .bind(&pattern)
        .fetch_one(pg)
        .await?;
    let list = sqlx::query_as(&format!(
        "SELECT {BCC_COLUMNS} FROM bm_bcc WHERE {filter} ORDER BY id DESC LIMIT $4 OFFSET $5"
    ))
    .bind(kind)
    .bind(domain)
    .bind(&pattern)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pg)
    .await?;
    Ok((total, list))
}

pub async fn bcc_get(pg: &PgPool, id: i32) -> Result<Option<BccRule>> {
    Ok(
        sqlx::query_as(&format!("SELECT {BCC_COLUMNS} FROM bm_bcc WHERE id = $1"))
            .bind(id)
            .fetch_optional(pg)
            .await?,
    )
}

/// Another active rule for the same type and address (Postfix keeps one
/// copy address per key).
pub async fn bcc_taken(pg: &PgPool, kind: &str, address: &str, except: i32) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM bm_bcc WHERE type = $1 AND lower(address) = $2
                          AND active = 1 AND id <> $3)",
    )
    .bind(kind)
    .bind(address)
    .bind(except)
    .fetch_one(pg)
    .await?)
}

pub struct NewBcc<'a> {
    pub kind: &'a str,
    pub address: &'a str,
    pub goto: &'a str,
    pub domain: &'a str,
    pub active: i16,
}

pub async fn bcc_insert(pg: &PgPool, rule: &NewBcc<'_>, now: i64) -> Result<i32> {
    Ok(sqlx::query_scalar(
        "INSERT INTO bm_bcc (type, address, goto, domain, create_time, update_time, active)
         VALUES ($1, $2, $3, $4, $5, $5, $6) RETURNING id",
    )
    .bind(rule.kind)
    .bind(rule.address)
    .bind(rule.goto)
    .bind(rule.domain)
    .bind(now as i32)
    .bind(rule.active)
    .fetch_one(pg)
    .await?)
}

pub async fn bcc_update(pg: &PgPool, id: i32, rule: &NewBcc<'_>, now: i64) -> Result<()> {
    sqlx::query(
        "UPDATE bm_bcc SET type = $2, address = $3, goto = $4, domain = $5, active = $6,
                update_time = $7 WHERE id = $1",
    )
    .bind(id)
    .bind(rule.kind)
    .bind(rule.address)
    .bind(rule.goto)
    .bind(rule.domain)
    .bind(rule.active)
    .bind(now as i32)
    .execute(pg)
    .await?;
    Ok(())
}

/// The deleted rule's address.
pub async fn bcc_delete(pg: &PgPool, id: i32) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("DELETE FROM bm_bcc WHERE id = $1 RETURNING address")
            .bind(id)
            .fetch_optional(pg)
            .await?,
    )
}

/// `(address, goto)` of the active rules of a type, oldest first.
pub async fn bcc_active(pg: &PgPool, kind: &str) -> Result<Vec<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT lower(address), goto FROM bm_bcc WHERE type = $1 AND active = 1 ORDER BY id",
    )
    .bind(kind)
    .fetch_all(pg)
    .await?)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Forward {
    pub address: String,
    pub goto: String,
    pub domain: String,
    pub create_time: i64,
    pub update_time: i64,
    pub active: i32,
}

const FORWARD_COLUMNS: &str = "address, goto, domain, create_time::bigint AS create_time,
    update_time::bigint AS update_time, active::int AS active";

pub async fn forward_list(
    pg: &PgPool,
    domain: Option<&str>,
    keyword: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(i64, Vec<Forward>)> {
    let filter = "($1::text IS NULL OR domain = $1)
                  AND ($2::text IS NULL OR address ILIKE $2 OR goto ILIKE $2)";
    let pattern = like(keyword);
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM alias WHERE {filter}"))
        .bind(domain)
        .bind(&pattern)
        .fetch_one(pg)
        .await?;
    let list = sqlx::query_as(&format!(
        "SELECT {FORWARD_COLUMNS} FROM alias WHERE {filter}
          ORDER BY create_time DESC, address LIMIT $3 OFFSET $4"
    ))
    .bind(domain)
    .bind(&pattern)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pg)
    .await?;
    Ok((total, list))
}

pub async fn forward_get(pg: &PgPool, address: &str) -> Result<Option<Forward>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {FORWARD_COLUMNS} FROM alias WHERE lower(address) = lower($1)"
    ))
    .bind(address)
    .fetch_optional(pg)
    .await?)
}

/// `false` when the address already forwards.
pub async fn forward_insert(
    pg: &PgPool,
    address: &str,
    goto: &str,
    domain: &str,
    active: i16,
    now: i64,
) -> Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO alias (address, goto, domain, create_time, update_time, active)
         VALUES ($1, $2, $3, $4, $4, $5) ON CONFLICT (address) DO NOTHING",
    )
    .bind(address)
    .bind(goto)
    .bind(domain)
    .bind(now as i32)
    .bind(active)
    .execute(pg)
    .await?
    .rows_affected();
    Ok(inserted > 0)
}

/// Changes the targets and/or the switch; `None` keeps the stored value.
pub async fn forward_update(
    pg: &PgPool,
    address: &str,
    goto: Option<&str>,
    active: Option<i16>,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE alias SET goto = COALESCE($2, goto), active = COALESCE($3, active),
                update_time = $4 WHERE lower(address) = lower($1)",
    )
    .bind(address)
    .bind(goto)
    .bind(active)
    .bind(now as i32)
    .execute(pg)
    .await?;
    Ok(())
}

pub async fn forward_delete(pg: &PgPool, address: &str) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM alias WHERE lower(address) = lower($1)")
            .bind(address)
            .execute(pg)
            .await?
            .rows_affected()
            > 0,
    )
}
