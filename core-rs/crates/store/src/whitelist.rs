//! Console IP whitelist (`bm_console_ip_whitelist`).

use anyhow::Result;
use sqlx::PgPool;

pub async fn entries(pg: &PgPool) -> Result<Vec<String>> {
    let ips = sqlx::query_scalar::<_, String>("SELECT ip FROM bm_console_ip_whitelist")
        .fetch_all(pg)
        .await?;
    Ok(ips)
}
