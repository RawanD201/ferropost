//! Contact groups (`bm_contact_groups`).

use anyhow::Result;
use ferropost_domain::groups::{ContactGroup, GroupBrief, GroupListItem, TagLogic};
use ferropost_domain::paging::{Page, PageRequest};
use sqlx::{PgPool, Postgres, QueryBuilder};

use crate::{Write, like_contains};

/// Most text columns are nullable in the Go schema.
const GROUP_COLUMNS: &str = "g.id, g.name, COALESCE(g.description, '') AS description,
    g.create_time, g.update_time, g.token, g.double_optin,
    COALESCE(g.welcome_mail_html, '') AS welcome_mail_html,
    COALESCE(g.welcome_mail_drag, '') AS welcome_mail_drag,
    COALESCE(g.welcome_subject, '') AS welcome_subject, g.send_welcome_email,
    COALESCE(g.confirm_subject, '') AS confirm_subject,
    COALESCE(g.confirm_mail_html, '') AS confirm_mail_html,
    COALESCE(g.confirm_mail_drag, '') AS confirm_mail_drag,
    COALESCE(g.success_url, '') AS success_url, COALESCE(g.confirm_url, '') AS confirm_url,
    COALESCE(g.already_url, '') AS already_url, COALESCE(g.subscribe_form, '') AS subscribe_form,
    COALESCE(g.unsubscribe_mail_html, '') AS unsubscribe_mail_html,
    COALESCE(g.unsubscribe_mail_drag, '') AS unsubscribe_mail_drag,
    COALESCE(g.unsubscribe_subject, '') AS unsubscribe_subject,
    COALESCE(g.unsubscribe_redirect_url, '') AS unsubscribe_redirect_url,
    g.send_unsubscribe_email";

/// Random 12-hex-character token for public subscribe links. Uses
/// `gen_random_uuid()` (cryptographically random) rather than Go's
/// time-seeded MD5.
const NEW_TOKEN: &str = "substr(replace(gen_random_uuid()::text, '-', ''), 1, 12)";

pub async fn name(pg: &PgPool, id: i32) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT name FROM bm_contact_groups WHERE id = $1")
            .bind(id)
            .fetch_optional(pg)
            .await?,
    )
}

/// `(id, name)` of the groups that exist among `ids`.
pub async fn names(pg: &PgPool, ids: &[i32]) -> Result<Vec<(i32, String)>> {
    Ok(sqlx::query_as::<_, (i32, String)>(
        "SELECT id, name FROM bm_contact_groups WHERE id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(pg)
    .await?)
}

/// Creates a group inside `tx`; `None` when the name is taken.
pub async fn create(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    name: &str,
    description: &str,
    double_optin: i16,
    now: i32,
) -> Result<Option<i32>> {
    let sql = format!(
        "INSERT INTO bm_contact_groups (name, description, create_time, update_time, token, double_optin)
         VALUES ($1, $2, $3, $3, {NEW_TOKEN}, $4)
         ON CONFLICT (name) DO NOTHING
         RETURNING id"
    );
    Ok(sqlx::query_scalar::<_, i32>(&sql)
        .bind(name)
        .bind(description)
        .bind(now)
        .bind(double_optin)
        .fetch_optional(&mut **tx)
        .await?)
}

/// Columns a group update may set. `None` leaves a column unchanged.
#[derive(Debug, Default)]
pub struct GroupChanges<'a> {
    pub text: Vec<(&'static str, &'a str)>,
    pub flags: Vec<(&'static str, i16)>,
}

impl GroupChanges<'_> {
    pub fn is_empty(&self) -> bool {
        self.text.is_empty() && self.flags.is_empty()
    }
}

/// Applies `changes` and bumps `update_time`. Column names come from the
/// callers' fixed lists, never from input.
pub async fn update(pg: &PgPool, id: i32, changes: &GroupChanges<'_>, now: i32) -> Result<Write> {
    let mut q = QueryBuilder::<Postgres>::new("UPDATE bm_contact_groups SET update_time = ");
    q.push_bind(now);
    for (column, value) in &changes.text {
        q.push(format!(", {column} = ")).push_bind(*value);
    }
    for (column, value) in &changes.flags {
        q.push(format!(", {column} = ")).push_bind(*value);
    }
    q.push(" WHERE id = ").push_bind(id);
    match q.build().execute(pg).await {
        Ok(done) if done.rows_affected() == 0 => Ok(Write::NotFound),
        Ok(_) => Ok(Write::Done),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(Write::Duplicate),
        Err(e) => Err(e.into()),
    }
}

/// Deletes a group with its contacts, its tags and every tag assignment of
/// those, atomically. Go left the group's tags and assignments behind.
/// Returns the group's name, or `None` when it did not exist.
pub async fn delete(pg: &PgPool, id: i32) -> Result<Option<String>> {
    let mut tx = pg.begin().await?;
    let Some(name) = sqlx::query_scalar::<_, String>(
        "SELECT name FROM bm_contact_groups WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(None);
    };
    for sql in [
        "DELETE FROM bm_contact_tags
          WHERE contact_id IN (SELECT id FROM bm_contacts WHERE group_id = $1)
             OR tag_id IN (SELECT id FROM bm_tags WHERE group_id = $1)",
        "DELETE FROM bm_contacts WHERE group_id = $1",
        "DELETE FROM bm_tags WHERE group_id = $1",
        "DELETE FROM bm_contact_groups WHERE id = $1",
    ] {
        sqlx::query(sql).bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Some(name))
}

/// Gives a subscribe token to groups created before tokens existed.
pub async fn backfill_tokens(pg: &PgPool) -> Result<()> {
    sqlx::query(&format!(
        "UPDATE bm_contact_groups SET token = {NEW_TOKEN} WHERE token = ''"
    ))
    .execute(pg)
    .await?;
    Ok(())
}

const KEYWORD_FILTER: &str =
    "($1::text IS NULL OR g.name LIKE $1 ESCAPE '\\' OR g.description LIKE $1 ESCAPE '\\')";

/// Paged groups with subscriber counts, computed in one query (Go ran two
/// counts per group).
pub async fn list(
    pg: &PgPool,
    keyword: Option<&str>,
    page: PageRequest,
) -> Result<Page<GroupListItem>> {
    let pattern = keyword.map(like_contains);
    let count_sql = format!("SELECT COUNT(*) FROM bm_contact_groups g WHERE {KEYWORD_FILTER}");
    let count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(&pattern)
        .fetch_one(pg);
    let list_sql = format!(
        "SELECT {GROUP_COLUMNS},
                COALESCE(s.active, 0) + COALESCE(s.inactive, 0) AS total_count,
                COALESCE(s.active, 0) AS active_count,
                COALESCE(s.inactive, 0) AS unsubscribe_count,
                '' AS subscribe_link, '' AS sender
           FROM bm_contact_groups g
           LEFT JOIN (
                SELECT group_id,
                       COUNT(*) FILTER (WHERE active = 1) AS active,
                       COUNT(*) FILTER (WHERE active = 0) AS inactive
                  FROM bm_contacts GROUP BY group_id
           ) s ON s.group_id = g.id
          WHERE {KEYWORD_FILTER}
          ORDER BY g.create_time DESC, g.id DESC
          LIMIT $2 OFFSET $3"
    );
    let list = sqlx::query_as::<_, GroupListItem>(&list_sql)
        .bind(&pattern)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pg);
    let (total, list) = tokio::try_join!(count, list)?;
    Ok(Page { total, list })
}

pub async fn all(pg: &PgPool, keyword: Option<&str>) -> Result<Vec<GroupBrief>> {
    let sql = format!(
        "SELECT g.id, g.name, COALESCE(g.description, '') AS description, g.create_time, g.update_time
           FROM bm_contact_groups g
          WHERE {KEYWORD_FILTER}
          ORDER BY g.create_time DESC, g.id DESC"
    );
    Ok(sqlx::query_as::<_, GroupBrief>(&sql)
        .bind(keyword.map(like_contains))
        .fetch_all(pg)
        .await?)
}

pub async fn get(pg: &PgPool, id: i32) -> Result<Option<ContactGroup>> {
    let sql = format!("SELECT {GROUP_COLUMNS} FROM bm_contact_groups g WHERE g.id = $1");
    Ok(sqlx::query_as::<_, ContactGroup>(&sql)
        .bind(id)
        .fetch_optional(pg)
        .await?)
}

/// Distinct subscribed addresses across `group_ids`.
pub async fn active_contact_count(pg: &PgPool, group_ids: &[i32]) -> Result<i64> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT email) FROM bm_contacts WHERE group_id = ANY($1) AND active = 1",
    )
    .bind(group_ids)
    .fetch_one(pg)
    .await?)
}

/// Subscribed and confirmed contacts of a group matching a tag filter.
pub async fn tag_contact_count(
    pg: &PgPool,
    group_id: i32,
    tag_ids: &[i32],
    logic: TagLogic,
) -> Result<i64> {
    let tag_filter = match logic {
        TagLogic::All => {
            "(SELECT COUNT(DISTINCT ct.tag_id) FROM bm_contact_tags ct
               WHERE ct.contact_id = c.id AND ct.tag_id = ANY($2)) = cardinality($2)"
        }
        TagLogic::Any => {
            "EXISTS (SELECT 1 FROM bm_contact_tags ct WHERE ct.contact_id = c.id AND ct.tag_id = ANY($2))"
        }
        TagLogic::None => {
            "NOT EXISTS (SELECT 1 FROM bm_contact_tags ct WHERE ct.contact_id = c.id AND ct.tag_id = ANY($2))"
        }
    };
    let sql = format!(
        "SELECT COUNT(*) FROM bm_contacts c
          WHERE c.group_id = $1 AND c.active = 1 AND c.status = 1 AND {tag_filter}"
    );
    Ok(sqlx::query_scalar::<_, i64>(&sql)
        .bind(group_id)
        .bind(tag_ids)
        .fetch_one(pg)
        .await?)
}

/// Copies the contacts of `sources` into `target`, one row per address.
/// An address keeps its subscription state when every source agrees and
/// becomes unsubscribed otherwise (Go's rule). Unlike Go, the confirmed
/// status (if confirmed anywhere) and the newest attributes are kept.
/// Addresses already in the target are left alone. Returns rows added.
pub async fn merge(pg: &PgPool, sources: &[i32], target: i32, now: i32) -> Result<u64> {
    Ok(sqlx::query(
        "INSERT INTO bm_contacts (email, group_id, active, status, attribs, create_time)
         SELECT email, $2,
                CASE WHEN MIN(active) = MAX(active) THEN MIN(active) ELSE 0 END,
                MAX(status),
                (ARRAY_AGG(attribs ORDER BY create_time DESC, id DESC))[1],
                $3
           FROM bm_contacts
          WHERE group_id = ANY($1)
          GROUP BY email
         ON CONFLICT (group_id, email) DO NOTHING",
    )
    .bind(sources)
    .bind(target)
    .bind(now)
    .execute(pg)
    .await?
    .rows_affected())
}
