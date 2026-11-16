//! Sending domains (`domain`).

use anyhow::Result;
use ferropost_domain::mail::mx_hostname_fallback;
use sqlx::PgPool;

/// Resolves the configured mail hostname (`a_record`) for a domain or host
/// name, then confirms a domain uses it. Equivalent to Go's
/// `public.FormatMX(name)` followed by the `a_record` existence check done
/// when choosing a TLS certificate.
///
/// Returns `None` when no configured domain matches.
pub async fn mail_hostname(pg: &PgPool, name: &str) -> Result<Option<String>> {
    let configured = sqlx::query_scalar::<_, String>(
        "SELECT a_record FROM domain WHERE (domain = $1 OR a_record = $1) AND a_record <> '' LIMIT 1",
    )
    .bind(name)
    .fetch_optional(pg)
    .await?;
    if configured.is_some() {
        return Ok(configured);
    }

    let fallback = mx_hostname_fallback(name);
    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM domain WHERE a_record = $1)")
            .bind(&fallback)
            .fetch_one(pg)
            .await?;
    Ok(exists.then_some(fallback))
}

/// Whether `domain` is one of the server's domains.
pub async fn exists(pg: &PgPool, domain: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM domain WHERE lower(domain) = lower($1))")
            .bind(domain)
            .fetch_one(pg)
            .await?,
    )
}

/// The oldest active domain.
pub async fn first_active(pg: &PgPool) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT domain FROM domain WHERE active = 1 ORDER BY create_time, domain LIMIT 1",
    )
    .fetch_optional(pg)
    .await?)
}

/// Go's `public.FormatMX`: the configured mail host of a domain (or of a
/// mail host itself), else `mail.<domain>`.
pub async fn format_mx(pg: &PgPool, name: &str) -> Result<String> {
    let configured = sqlx::query_scalar::<_, String>(
        "SELECT a_record FROM domain WHERE (domain = $1 OR a_record = $1) AND a_record <> '' LIMIT 1",
    )
    .bind(name)
    .fetch_optional(pg)
    .await?;
    Ok(configured.unwrap_or_else(|| mx_hostname_fallback(name)))
}

/// Every domain name.
pub async fn names(pg: &PgPool) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT domain FROM domain ORDER BY create_time, domain")
            .fetch_all(pg)
            .await?,
    )
}
