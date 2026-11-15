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

/// Minimal tag identity used by write endpoints.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct TagRef {
    pub id: i32,
    pub group_id: i32,
    pub name: String,
}

/// Outcome of a write that can collide with `UNIQUE(group_id, name)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Write {
    Done,
    NotFound,
    Duplicate,
}

/// Inserts a tag. Returns `false` when the group already has a tag with
/// that name. The unique constraint decides, so concurrent requests cannot
/// both succeed (Go checked first and inserted second).
pub async fn create(pg: &PgPool, group_id: i32, name: &str, now: i32) -> Result<bool> {
    let id = sqlx::query_scalar::<_, i32>(
        "INSERT INTO bm_tags (group_id, name, create_time) VALUES ($1, $2, $3)
         ON CONFLICT (group_id, name) DO NOTHING
         RETURNING id",
    )
    .bind(group_id)
    .bind(name)
    .bind(now)
    .fetch_optional(pg)
    .await?;
    Ok(id.is_some())
}

pub async fn rename(pg: &PgPool, id: i32, name: &str) -> Result<Write> {
    let result = sqlx::query("UPDATE bm_tags SET name = $2 WHERE id = $1")
        .bind(id)
        .bind(name)
        .execute(pg)
        .await;
    match result {
        Ok(done) if done.rows_affected() == 0 => Ok(Write::NotFound),
        Ok(_) => Ok(Write::Done),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(Write::Duplicate),
        Err(e) => Err(e.into()),
    }
}

/// Deletes a tag and its contact assignments atomically. Returns the deleted
/// tag's name, or `None` when it did not exist.
pub async fn delete(pg: &PgPool, id: i32) -> Result<Option<String>> {
    let mut tx = pg.begin().await?;
    sqlx::query("DELETE FROM bm_contact_tags WHERE tag_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let name = sqlx::query_scalar::<_, String>("DELETE FROM bm_tags WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(name)
}

pub async fn by_ids(pg: &PgPool, ids: &[i32]) -> Result<Vec<TagRef>> {
    Ok(
        sqlx::query_as::<_, TagRef>("SELECT id, group_id, name FROM bm_tags WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(pg)
            .await?,
    )
}

/// Result of tagging contacts in bulk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkTagged {
    /// New contact–tag pairs.
    pub inserted: u64,
    /// Pairs that were already tagged, or addresses with no contact.
    pub skipped: u64,
}

/// Tags the group's contacts whose address is in `emails` (lowercase) with
/// every tag in `tag_ids`. One statement, so it is all-or-nothing.
pub async fn tag_contacts(
    pg: &PgPool,
    group_id: i32,
    tag_ids: &[i32],
    emails: &[String],
    now: i32,
) -> Result<BulkTagged> {
    let inserted = sqlx::query(
        "INSERT INTO bm_contact_tags (contact_id, tag_id, create_time)
         SELECT c.id, t.id, $4
           FROM bm_contacts c
          CROSS JOIN unnest($2::int[]) AS t(id)
          WHERE c.group_id = $1 AND lower(c.email) = ANY($3::text[])
         ON CONFLICT (contact_id, tag_id) DO NOTHING",
    )
    .bind(group_id)
    .bind(tag_ids)
    .bind(emails)
    .bind(now)
    .execute(pg)
    .await?
    .rows_affected();
    let candidates = (emails.len() * tag_ids.len()) as u64;
    Ok(BulkTagged {
        inserted,
        skipped: candidates.saturating_sub(inserted),
    })
}

/// Tags every contact of the group *except* those in `excluded` (lowercase).
pub async fn tag_contacts_except(
    pg: &PgPool,
    group_id: i32,
    tag_ids: &[i32],
    excluded: &[String],
    now: i32,
) -> Result<BulkTagged> {
    let mut tx = pg.begin().await?;
    let members =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bm_contacts WHERE group_id = $1")
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await?;
    let inserted = sqlx::query(
        "INSERT INTO bm_contact_tags (contact_id, tag_id, create_time)
         SELECT c.id, t.id, $4
           FROM bm_contacts c
          CROSS JOIN unnest($2::int[]) AS t(id)
          WHERE c.group_id = $1 AND NOT (lower(c.email) = ANY($3::text[]))
         ON CONFLICT (contact_id, tag_id) DO NOTHING",
    )
    .bind(group_id)
    .bind(tag_ids)
    .bind(excluded)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    let candidates = u64::try_from(members).unwrap_or(0) * tag_ids.len() as u64;
    Ok(BulkTagged {
        inserted,
        skipped: candidates.saturating_sub(inserted),
    })
}
