//! Console IP whitelist (`bm_console_ip_whitelist`).

use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Entry {
    pub id: i32,
    pub ip: String,
}

pub async fn entries(pg: &PgPool) -> Result<Vec<String>> {
    let ips = sqlx::query_scalar::<_, String>("SELECT ip FROM bm_console_ip_whitelist")
        .fetch_all(pg)
        .await?;
    Ok(ips)
}

pub async fn list(pg: &PgPool) -> Result<Vec<Entry>> {
    Ok(
        sqlx::query_as::<_, Entry>("SELECT id, ip FROM bm_console_ip_whitelist ORDER BY id")
            .fetch_all(pg)
            .await?,
    )
}

/// `ip_type`: 1 for IPv4, 2 for IPv6. `false` when it is already listed.
pub async fn add(pg: &PgPool, ip: &str, ip_type: i16, now: i32) -> Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO bm_console_ip_whitelist (ip, ip_type, create_time) VALUES ($1, $2, $3)
         ON CONFLICT (ip) DO NOTHING",
    )
    .bind(ip)
    .bind(ip_type)
    .bind(now)
    .execute(pg)
    .await?
    .rows_affected();
    Ok(inserted > 0)
}

/// The removed address, if the entry existed.
pub async fn delete(pg: &PgPool, id: i32) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, String>(
        "DELETE FROM bm_console_ip_whitelist WHERE id = $1 RETURNING ip",
    )
    .bind(id)
    .fetch_optional(pg)
    .await?)
}

/// Replaces the list with `ips` (`(ip, ip_type)`) in one transaction,
/// keeping the IDs of entries that stay.
pub async fn replace(pg: &PgPool, ips: &[(String, i16)], now: i32) -> Result<()> {
    let mut tx = pg.begin().await?;
    let keep: Vec<&str> = ips.iter().map(|(ip, _)| ip.as_str()).collect();
    sqlx::query("DELETE FROM bm_console_ip_whitelist WHERE NOT (ip = ANY($1))")
        .bind(&keep)
        .execute(&mut *tx)
        .await?;
    for (ip, ip_type) in ips {
        sqlx::query(
            "INSERT INTO bm_console_ip_whitelist (ip, ip_type, create_time) VALUES ($1, $2, $3)
             ON CONFLICT (ip) DO NOTHING",
        )
        .bind(ip)
        .bind(ip_type)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
