//! Dedicated sending IPs (`bm_multi_ip_domain`).

use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Clone, Default, Serialize, sqlx::FromRow)]
pub struct DedicatedIpRow {
    pub id: i32,
    pub domain: String,
    pub outbound_ip: String,
    pub network_name: String,
    pub subnet: String,
    pub postfix_ip: String,
    pub aliases: String,
    pub smtp_server_name: String,
    pub active: i32,
    pub create_time: i64,
    pub update_time: i64,
    pub status: String,
}

const COLUMNS: &str = "id, domain, outbound_ip, network_name, subnet, postfix_ip, aliases,
    smtp_server_name, active::int AS active, create_time::bigint AS create_time,
    update_time::bigint AS update_time, status";

pub async fn active(pg: &PgPool) -> Result<Vec<DedicatedIpRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM bm_multi_ip_domain WHERE active = 1 ORDER BY id"
    ))
    .fetch_all(pg)
    .await?)
}

/// The active configuration of a domain.
pub async fn for_domain(pg: &PgPool, domain: &str) -> Result<Option<DedicatedIpRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM bm_multi_ip_domain WHERE active = 1 AND domain = $1 ORDER BY id LIMIT 1"
    ))
    .bind(domain)
    .fetch_optional(pg)
    .await?)
}

pub async fn set_status(pg: &PgPool, ids: &[i32], status: &str) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query("UPDATE bm_multi_ip_domain SET status = $2 WHERE id = ANY($1)")
        .bind(ids)
        .bind(status)
        .execute(pg)
        .await?;
    Ok(())
}

/// Subnets taken by any configuration.
pub async fn used_subnets(pg: &PgPool) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT subnet FROM bm_multi_ip_domain WHERE active >= 0")
            .fetch_all(pg)
            .await?,
    )
}

pub struct NewDedicatedIp<'a> {
    pub domain: &'a str,
    pub outbound_ip: &'a str,
    pub network_name: &'a str,
    pub subnet: &'a str,
    pub postfix_ip: &'a str,
    pub aliases: &'a str,
    pub smtp_server_name: &'a str,
}

pub async fn add(pg: &PgPool, row: &NewDedicatedIp<'_>, now: i64) -> Result<i32> {
    Ok(sqlx::query_scalar(
        "INSERT INTO bm_multi_ip_domain (domain, outbound_ip, network_name, subnet, postfix_ip,
             aliases, smtp_server_name, active, create_time, update_time, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $8, 'pending') RETURNING id",
    )
    .bind(row.domain)
    .bind(row.outbound_ip)
    .bind(row.network_name)
    .bind(row.subnet)
    .bind(row.postfix_ip)
    .bind(row.aliases)
    .bind(row.smtp_server_name)
    .bind(now as i32)
    .fetch_one(pg)
    .await?)
}

/// Removes a domain's configurations and their transport (Go's
/// `DeleteConfig`).
pub async fn delete_for_domain(pg: &PgPool, domain: &str) -> Result<bool> {
    let mut tx = pg.begin().await?;
    let removed = sqlx::query("DELETE FROM bm_multi_ip_domain WHERE domain = $1")
        .bind(domain)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    sqlx::query(
        "DELETE FROM bm_domain_smtp_transport WHERE atype = 'dedicated_ip'
           AND domain IN ($1, '@' || $1)",
    )
    .bind(domain)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(removed > 0)
}
