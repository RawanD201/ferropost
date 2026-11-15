//! Operation log rows (`bm_operation_logs`).

use anyhow::Result;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct NewEntry<'a> {
    pub user_id: i64,
    pub log_type: &'a str,
    pub log: &'a str,
    pub ip: &'a str,
    /// Path of the JSON snapshot file, or empty.
    pub info: &'a str,
    pub addtime: i64,
}

pub async fn insert(pg: &PgPool, entry: &NewEntry<'_>) -> Result<()> {
    sqlx::query(
        "INSERT INTO bm_operation_logs (user_id, type, log, ip, info, addtime)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT DO NOTHING",
    )
    .bind(entry.user_id)
    .bind(entry.log_type)
    .bind(entry.log)
    .bind(entry.ip)
    .bind(entry.info)
    .bind(i32::try_from(entry.addtime).unwrap_or(i32::MAX))
    .execute(pg)
    .await?;
    Ok(())
}
