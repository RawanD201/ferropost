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

#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    /// Substring of the log text or the IP (matched literally).
    pub keyword: Option<String>,
    pub log_type: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
}

const FILTER: &str = "
     WHERE ($1::text IS NULL OR l.log LIKE $1 ESCAPE '\\' OR l.ip LIKE $1 ESCAPE '\\')
       AND ($2::text IS NULL OR l.type = $2)
       AND ($3::bigint IS NULL OR l.addtime >= $3)
       AND ($4::bigint IS NULL OR l.addtime <= $4)";

pub async fn list(
    pg: &PgPool,
    filter: &LogFilter,
    page: ferropost_domain::paging::PageRequest,
) -> Result<ferropost_domain::paging::Page<ferropost_domain::audit::LogEntry>> {
    let pattern = filter.keyword.as_deref().map(crate::like_contains);

    let count_sql = format!("SELECT COUNT(*) FROM bm_operation_logs l {FILTER}");
    let count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(&pattern)
        .bind(&filter.log_type)
        .bind(filter.start_time)
        .bind(filter.end_time)
        .fetch_one(pg);

    // The username comes from a join; Go loaded every account per request.
    let list_sql = format!(
        "SELECT l.id, l.user_id, l.type, l.log, l.ip, l.info, l.addtime::bigint AS addtime,
                COALESCE(a.username, 'unknown') AS username
           FROM bm_operation_logs l
           LEFT JOIN account a ON a.account_id = l.user_id
         {FILTER}
          ORDER BY l.id DESC
          LIMIT $5 OFFSET $6"
    );
    let list = sqlx::query_as::<_, ferropost_domain::audit::LogEntry>(&list_sql)
        .bind(&pattern)
        .bind(&filter.log_type)
        .bind(filter.start_time)
        .bind(filter.end_time)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pg);

    let (total, list) = tokio::try_join!(count, list)?;
    Ok(ferropost_domain::paging::Page { total, list })
}
