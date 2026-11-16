//! Certificates obtained from Let's Encrypt (`letsencrypts`).

use anyhow::Result;
use sqlx::PgPool;

#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct Issued {
    pub cert_id: i32,
    pub subject: String,
    pub status: i32,
    pub certificate: String,
    pub private_key: String,
    pub endtime: i64,
    pub error_info: String,
    pub progress: String,
}

const COLUMNS: &str = "cert_id, subject, status, certificate, private_key,
    endtime::bigint AS endtime, error_info, progress";

/// The latest record for a host, failed ones included.
pub async fn latest(pg: &PgPool, subject: &str) -> Result<Option<Issued>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM letsencrypts WHERE subject = $1 ORDER BY endtime DESC, cert_id DESC LIMIT 1"
    ))
    .bind(subject)
    .fetch_optional(pg)
    .await?)
}

/// The valid certificate covering `host` that expires last (Go:
/// `getSSLInfoFromDatabase`).
pub async fn valid_for(pg: &PgPool, host: &str, now: i64) -> Result<Option<Issued>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM letsencrypts
          WHERE status = 1 AND endtime > $2 AND (subject = $1 OR dns LIKE '%' || $3 || '%')
          ORDER BY endtime DESC LIMIT 1"
    ))
    .bind(host)
    .bind(now)
    .bind(format!("\"{host}\""))
    .fetch_optional(pg)
    .await?)
}

/// A certificate as stored.
pub struct NewCert<'a> {
    pub account_id: i64,
    pub subject: &'a str,
    pub issuer: &'a str,
    pub dns_json: &'a str,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub endtime: i64,
    pub certificate: &'a str,
    pub private_key: &'a str,
}

/// Stores a certificate over the host's earlier records (Go updated every
/// record of the subject, or inserted the first).
pub async fn save(pg: &PgPool, cert: &NewCert<'_>) -> Result<()> {
    let mut tx = pg.begin().await?;
    let updated = sqlx::query(
        "UPDATE letsencrypts SET account_id = $2, issuer = $3, dns = $4, not_before = $5,
                not_after = $6, endtime = $7, certificate = $8, private_key = $9, status = 1,
                error_info = '', progress = '', auth_type = 'http'
          WHERE subject = $1",
    )
    .bind(cert.subject)
    .bind(cert.account_id as i32)
    .bind(cert.issuer)
    .bind(cert.dns_json)
    .bind(cert.not_before)
    .bind(cert.not_after)
    .bind(cert.endtime as i32)
    .bind(cert.certificate)
    .bind(cert.private_key)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        sqlx::query(
            "INSERT INTO letsencrypts (account_id, subject, issuer, dns, not_before, not_after,
                 endtime, certificate, private_key, status, auth_type)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, 'http')",
        )
        .bind(cert.account_id as i32)
        .bind(cert.subject)
        .bind(cert.issuer)
        .bind(cert.dns_json)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(cert.endtime as i32)
        .bind(cert.certificate)
        .bind(cert.private_key)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Records a failed attempt and when it happened (in `progress`, as
/// `failed at <unix time>`). Go only updated existing records, so a host
/// that never had a certificate kept no trace of its failures, and it kept
/// no time, so a host that failed once was never tried again.
pub async fn record_failure(pg: &PgPool, subject: &str, error: &str, now: i64) -> Result<()> {
    let progress = format!("failed at {now}");
    let updated = sqlx::query(
        "UPDATE letsencrypts SET status = -1, error_info = $2, progress = $3 WHERE subject = $1",
    )
    .bind(subject)
    .bind(error)
    .bind(&progress)
    .execute(pg)
    .await?
    .rows_affected();
    if updated == 0 {
        sqlx::query(
            "INSERT INTO letsencrypts (subject, dns, status, error_info, progress, auth_type)
             VALUES ($1, '[]', -1, $2, $3, 'http')",
        )
        .bind(subject)
        .bind(error)
        .bind(&progress)
        .execute(pg)
        .await?;
    }
    Ok(())
}

/// When a failed record's attempt happened, if it says.
pub fn failed_at(progress: &str) -> Option<i64> {
    progress.strip_prefix("failed at ")?.trim().parse().ok()
}
