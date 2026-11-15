//! Sending domains (`domain`).

use anyhow::Result;
use bm_domain::mail::mx_hostname_fallback;
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
