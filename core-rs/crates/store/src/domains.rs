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

/// A `domain` row.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct DomainRow {
    pub domain: String,
    pub a_record: String,
    pub mailboxes: i64,
    pub mailbox_quota: i64,
    pub quota: i64,
    pub rate_limit: i64,
    pub create_time: i64,
    pub active: i32,
    pub urls: Vec<String>,
    pub hasbrandinfo: i32,
    pub current_usage: i64,
}

const COLUMNS: &str = "domain, a_record, mailboxes::bigint AS mailboxes, mailbox_quota, quota,
    COALESCE(rate_limit, 12)::bigint AS rate_limit, create_time::bigint AS create_time,
    active::int AS active, COALESCE(urls, '{}'::text[]) AS urls,
    COALESCE(hasbrandinfo, 0)::int AS hasbrandinfo, COALESCE(current_usage, 0) AS current_usage";

/// A page of domains, newest first, optionally those containing `keyword`.
pub async fn list(
    pg: &PgPool,
    keyword: Option<&str>,
    offset: i64,
    limit: i64,
) -> Result<(i64, Vec<DomainRow>)> {
    let pattern = keyword.map(crate::like_contains);
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM domain WHERE ($1::text IS NULL OR domain ILIKE $1)",
    )
    .bind(&pattern)
    .fetch_one(pg)
    .await?;
    let rows = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM domain WHERE ($1::text IS NULL OR domain ILIKE $1)
         ORDER BY create_time DESC, domain LIMIT $2 OFFSET $3"
    ))
    .bind(&pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(pg)
    .await?;
    Ok((total, rows))
}

/// Every domain, oldest first.
pub async fn all(pg: &PgPool) -> Result<Vec<DomainRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM domain ORDER BY create_time, domain"
    ))
    .fetch_all(pg)
    .await?)
}

/// A domain by name, in any case.
pub async fn get(pg: &PgPool, domain: &str) -> Result<Option<DomainRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM domain WHERE lower(domain) = lower($1)
         ORDER BY domain = $1 DESC LIMIT 1"
    ))
    .bind(domain)
    .fetch_optional(pg)
    .await?)
}

pub struct NewDomain<'a> {
    pub domain: &'a str,
    pub a_record: &'a str,
    pub mailboxes: i64,
    pub mailbox_quota: i64,
    pub quota: i64,
    pub rate_limit: i64,
    pub urls: &'a [String],
    pub hasbrandinfo: i32,
    pub now: i32,
}

/// Adds a domain. `false` when it exists already (in any case).
pub async fn insert(pg: &PgPool, d: &NewDomain<'_>) -> Result<bool> {
    let done = sqlx::query(
        "INSERT INTO domain (domain, a_record, mailboxes, mailbox_quota, quota, rate_limit,
             create_time, active, urls, hasbrandinfo)
         SELECT $1, $2, $3::int, $4, $5, $6::int, $7, 1, $8, $9::smallint
         WHERE NOT EXISTS (SELECT 1 FROM domain WHERE lower(domain) = lower($1))
         ON CONFLICT (domain) DO NOTHING",
    )
    .bind(d.domain)
    .bind(d.a_record)
    .bind(d.mailboxes)
    .bind(d.mailbox_quota)
    .bind(d.quota)
    .bind(d.rate_limit)
    .bind(d.now)
    .bind(d.urls)
    .bind(d.hasbrandinfo)
    .execute(pg)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Changes to a domain; `None` keeps a value.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DomainChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a_record: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailboxes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox_quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hasbrandinfo: Option<i32>,
}

pub async fn update(pg: &PgPool, domain: &str, c: &DomainChanges) -> Result<bool> {
    let done = sqlx::query(
        "UPDATE domain SET
             a_record = COALESCE($2, a_record),
             mailboxes = COALESCE($3::int, mailboxes),
             mailbox_quota = COALESCE($4, mailbox_quota),
             quota = COALESCE($5, quota),
             rate_limit = COALESCE($6::int, rate_limit),
             active = COALESCE($7::smallint, active),
             urls = COALESCE($8, urls),
             hasbrandinfo = COALESCE($9::smallint, hasbrandinfo)
         WHERE domain = $1",
    )
    .bind(domain)
    .bind(&c.a_record)
    .bind(c.mailboxes)
    .bind(c.mailbox_quota)
    .bind(c.quota)
    .bind(c.rate_limit)
    .bind(c.active)
    .bind(&c.urls)
    .bind(c.hasbrandinfo)
    .execute(pg)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// What deleting a domain removed with it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Removed {
    pub mailboxes: u64,
    pub aliases: u64,
    pub bcc_rules: u64,
    pub dedicated_ip: bool,
    pub was_default: bool,
}

/// Deletes a domain with its mailboxes and aliases (as Go did), and its
/// BCC rules, dedicated sending address and default-domain setting, which
/// Go left behind. `None` when there was no such domain.
pub async fn delete(pg: &PgPool, domain: &str) -> Result<Option<Removed>> {
    let mut tx = pg.begin().await?;
    let gone = sqlx::query("DELETE FROM domain WHERE domain = $1")
        .bind(domain)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 0 {
        return Ok(None);
    }
    let mut count = async |sql: &str| -> Result<u64> {
        Ok(sqlx::query(sql)
            .bind(domain)
            .execute(&mut *tx)
            .await?
            .rows_affected())
    };
    let mailboxes = count("DELETE FROM mailbox WHERE lower(domain) = lower($1)").await?;
    let aliases = count("DELETE FROM alias WHERE lower(domain) = lower($1)").await?;
    let bcc_rules = count("DELETE FROM bm_bcc WHERE lower(domain) = lower($1)").await?;
    let dedicated = count("DELETE FROM bm_multi_ip_domain WHERE lower(domain) = lower($1)").await?;
    count(
        "DELETE FROM bm_domain_smtp_transport WHERE atype = 'dedicated_ip'
           AND lower(domain) IN (lower($1), '@' || lower($1))",
    )
    .await?;
    let was_default = count(
        "DELETE FROM bm_options WHERE name = 'default_sender_domain' AND lower(value) = lower($1)",
    )
    .await?;
    let removed = Removed {
        mailboxes,
        aliases,
        bcc_rules,
        dedicated_ip: dedicated > 0,
        was_default: was_default > 0,
    };
    tx.commit().await?;
    Ok(Some(removed))
}

/// The active catch-all address (`@domain` alias) of each domain given.
pub async fn catchalls(
    pg: &PgPool,
    domains: &[String],
) -> Result<std::collections::HashMap<String, String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT domain, goto FROM alias
          WHERE domain = ANY($1) AND address = '@' || domain AND active = 1",
    )
    .bind(domains)
    .fetch_all(pg)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Sets a domain's catch-all address, or turns it off (`None`).
pub async fn set_catchall(pg: &PgPool, domain: &str, goto: Option<&str>, now: i32) -> Result<()> {
    match goto {
        Some(goto) => {
            sqlx::query(
                "INSERT INTO alias (address, goto, domain, create_time, update_time, active)
                 VALUES ('@' || $1, $2, $1, $3, $3, 1)
                 ON CONFLICT (address) DO UPDATE
                   SET goto = EXCLUDED.goto, domain = EXCLUDED.domain, active = 1,
                       update_time = EXCLUDED.update_time",
            )
            .bind(domain)
            .bind(goto)
            .bind(now)
            .execute(pg)
            .await?;
        }
        None => {
            sqlx::query(
                "UPDATE alias SET active = 0, update_time = $2
                  WHERE address = '@' || $1 AND domain = $1 AND active <> 0",
            )
            .bind(domain)
            .bind(now)
            .execute(pg)
            .await?;
        }
    }
    Ok(())
}
