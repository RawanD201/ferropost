//! Contact tags (`bm_tags`).

use anyhow::Result;
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_domain::tags::Tag;
use sqlx::PgPool;

use crate::like_contains;

#[derive(Debug, Clone, Default)]
pub struct TagFilter {
    /// Substring of the tag name (matched literally).
    pub keyword: Option<String>,
    pub group_id: Option<i32>,
}

// The group name comes from a join; Go issued one extra query per tag.
// Tags whose group was deleted report the group as "Unknown", like Go.
const SELECT_TAGS: &str = "
    SELECT t.id, t.group_id, COALESCE(g.name, 'Unknown') AS group_name, t.name, t.create_time
      FROM bm_tags t
      LEFT JOIN bm_contact_groups g ON g.id = t.group_id";

const FILTER: &str = "
     WHERE ($1::text IS NULL OR t.name LIKE $1 ESCAPE '\\')
       AND ($2::int IS NULL OR t.group_id = $2)";

pub async fn list(pg: &PgPool, filter: &TagFilter, page: PageRequest) -> Result<Page<Tag>> {
    let pattern = filter.keyword.as_deref().map(like_contains);

    let count_sql = format!("SELECT COUNT(*) FROM bm_tags t {FILTER}");
    let count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(&pattern)
        .bind(filter.group_id)
        .fetch_one(pg);

    let list_sql =
        format!("{SELECT_TAGS} {FILTER} ORDER BY t.create_time DESC, t.id DESC LIMIT $3 OFFSET $4");
    let list = sqlx::query_as::<_, Tag>(&list_sql)
        .bind(&pattern)
        .bind(filter.group_id)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pg);

    let (total, list) = tokio::try_join!(count, list)?;
    Ok(Page { total, list })
}

pub async fn all(pg: &PgPool) -> Result<Vec<Tag>> {
    let sql = format!("{SELECT_TAGS} ORDER BY t.create_time DESC, t.id DESC");
    Ok(sqlx::query_as::<_, Tag>(&sql).fetch_all(pg).await?)
}
