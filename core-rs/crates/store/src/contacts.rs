//! Contacts (`bm_contacts`).

use anyhow::Result;
use ferropost_domain::contacts::{Contact, ContactTag, GroupRef, ImportedContact};
use ferropost_domain::paging::{Page, PageRequest};
use sqlx::{PgConnection, PgPool, Postgres};

use crate::like_contains;

/// One statement per import, whatever its size: columns are sent as arrays
/// and expanded with `unnest`.
struct Columns {
    emails: Vec<String>,
    active: Vec<i32>,
    attribs: Vec<String>,
}

fn columns(contacts: &[ImportedContact]) -> Columns {
    Columns {
        emails: contacts.iter().map(|c| c.email.clone()).collect(),
        active: contacts.iter().map(|c| c.active).collect(),
        attribs: contacts
            .iter()
            .map(|c| serde_json::to_string(&c.attribs).unwrap_or_else(|_| "{}".to_owned()))
            .collect(),
    }
}

/// Inserts contacts into a group, skipping addresses already in it.
/// `contacts` must not repeat an address. Returns rows inserted.
pub async fn insert_new(
    conn: &mut PgConnection,
    group_id: i32,
    status: i32,
    contacts: &[ImportedContact],
    now: i32,
) -> Result<u64> {
    let cols = columns(contacts);
    Ok(sqlx::query::<Postgres>(
        "INSERT INTO bm_contacts (email, group_id, active, task_id, status, attribs, create_time)
         SELECT email, $1, active, 0, $2, attribs::jsonb, $3
           FROM unnest($4::text[], $5::int[], $6::text[]) AS t(email, active, attribs)
         ON CONFLICT (group_id, email) DO NOTHING",
    )
    .bind(group_id)
    .bind(status)
    .bind(now)
    .bind(&cols.emails)
    .bind(&cols.active)
    .bind(&cols.attribs)
    .execute(conn)
    .await?
    .rows_affected())
}

/// Inserts contacts, or for addresses already in the group updates the
/// subscription state and (when the import has any) the attributes, like
/// Go's overwrite import. `contacts` must not repeat an address. Returns
/// rows inserted or updated.
pub async fn upsert(
    conn: &mut PgConnection,
    group_id: i32,
    status: i32,
    contacts: &[ImportedContact],
    now: i32,
) -> Result<u64> {
    let cols = columns(contacts);
    Ok(sqlx::query::<Postgres>(
        "INSERT INTO bm_contacts (email, group_id, active, task_id, status, attribs, create_time)
         SELECT email, $1, active, 0, $2, attribs::jsonb, $3
           FROM unnest($4::text[], $5::int[], $6::text[]) AS t(email, active, attribs)
         ON CONFLICT (group_id, email) DO UPDATE
            SET active = EXCLUDED.active,
                attribs = CASE WHEN EXCLUDED.attribs = '{}'::jsonb
                               THEN bm_contacts.attribs ELSE EXCLUDED.attribs END",
    )
    .bind(group_id)
    .bind(status)
    .bind(now)
    .bind(&cols.emails)
    .bind(&cols.active)
    .bind(&cols.attribs)
    .execute(conn)
    .await?
    .rows_affected())
}

/// Columns shared by both contact lists; nullable ones get defaults.
const CONTACT_COLUMNS: &str = "c.id, c.email, COALESCE(c.group_id, 0) AS group_id,
    COALESCE(c.active, 0) AS active, COALESCE(c.task_id, 0) AS task_id, c.create_time,
    COALESCE(c.status, 0) AS status, COALESCE(cg.name, '') AS group_name,
    COALESCE(c.attribs, '{}'::jsonb) AS attribs, COALESCE(c.last_active_at, 0) AS last_active_at";

#[derive(Debug, Clone, Default)]
pub struct EmailFilter {
    pub group_id: Option<i32>,
    pub keyword: Option<String>,
    pub active: Option<i32>,
}

/// One row per address (its newest), for `/contact/list`. Each contact
/// lists every group where it has the same subscription state.
pub async fn list_by_address(
    pg: &PgPool,
    filter: &EmailFilter,
    page: PageRequest,
) -> Result<Page<Contact>> {
    let pattern = filter.keyword.as_deref().map(like_contains);
    const WHERE: &str = "WHERE ($1::int IS NULL OR group_id = $1)
                           AND ($2::text IS NULL OR email LIKE $2 ESCAPE '\\')
                           AND ($3::int IS NULL OR active = $3)";
    let total = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(DISTINCT email) FROM bm_contacts {WHERE}"
    ))
    .bind(filter.group_id)
    .bind(&pattern)
    .bind(filter.active)
    .fetch_one(pg)
    .await?;
    if total == 0 {
        return Ok(Page {
            total,
            list: Vec::new(),
        });
    }

    let sql = format!(
        "WITH newest AS (
             SELECT DISTINCT ON (email) id FROM bm_contacts {WHERE}
              ORDER BY email, create_time DESC, id DESC
         )
         SELECT {CONTACT_COLUMNS}
           FROM bm_contacts c
           JOIN newest n ON n.id = c.id
           LEFT JOIN bm_contact_groups cg ON cg.id = c.group_id
          ORDER BY c.create_time DESC, c.id DESC
          LIMIT $4 OFFSET $5"
    );
    let mut list = sqlx::query_as::<_, Contact>(&sql)
        .bind(filter.group_id)
        .bind(&pattern)
        .bind(filter.active)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pg)
        .await?;

    let emails: Vec<&str> = list.iter().map(|c| c.email.as_str()).collect();
    let memberships = sqlx::query_as::<_, (String, i32, String)>(
        "SELECT DISTINCT c.email, g.id, g.name
           FROM bm_contacts c JOIN bm_contact_groups g ON g.id = c.group_id
          WHERE c.email = ANY($1) AND ($2::int IS NULL OR c.active = $2)
          ORDER BY g.id",
    )
    .bind(&emails)
    .bind(filter.active)
    .fetch_all(pg)
    .await?;
    for contact in &mut list {
        contact.groups = memberships
            .iter()
            .filter(|(email, _, _)| *email == contact.email)
            .map(|(_, id, name)| GroupRef {
                id: *id,
                name: name.clone(),
            })
            .collect();
    }
    Ok(Page { total, list })
}

#[derive(Debug, Clone, Default)]
pub struct ContactFilter {
    pub group_id: Option<i32>,
    pub keyword: Option<String>,
    pub active: Option<i32>,
    /// Contacts with any of these tags.
    pub tag_ids: Vec<i32>,
    /// `(since, true)`: active since; `(since, false)`: not active since.
    pub last_active: Option<(i64, bool)>,
    pub sort_by_last_active: bool,
    pub ascending: bool,
}

/// Every row (one per group membership) with its group name and tags, for
/// `/contact/list_ndp`.
pub async fn list_rows(
    pg: &PgPool,
    filter: &ContactFilter,
    page: PageRequest,
) -> Result<Page<Contact>> {
    let pattern = filter.keyword.as_deref().map(like_contains);
    let (since, active_since) = match filter.last_active {
        Some((since, active)) => (Some(since), Some(active)),
        None => (None, None),
    };
    const WHERE: &str = "WHERE ($1::int IS NULL OR c.group_id = $1)
        AND ($2::text IS NULL OR c.email LIKE $2 ESCAPE '\\')
        AND ($3::int IS NULL OR c.active = $3)
        AND (cardinality($4::int[]) = 0 OR EXISTS (
             SELECT 1 FROM bm_contact_tags ct WHERE ct.contact_id = c.id AND ct.tag_id = ANY($4)))
        AND ($5::bigint IS NULL
             OR ($6 AND c.last_active_at >= $5)
             OR (NOT $6 AND (c.last_active_at IS NULL OR c.last_active_at < $5)))";

    let total =
        sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM bm_contacts c {WHERE}"))
            .bind(filter.group_id)
            .bind(&pattern)
            .bind(filter.active)
            .bind(&filter.tag_ids)
            .bind(since)
            .bind(active_since)
            .fetch_one(pg)
            .await?;

    let column = if filter.sort_by_last_active {
        "c.last_active_at"
    } else {
        "c.create_time"
    };
    let direction = if filter.ascending { "ASC" } else { "DESC" };
    let sql = format!(
        "SELECT {CONTACT_COLUMNS}
           FROM bm_contacts c
           LEFT JOIN bm_contact_groups cg ON cg.id = c.group_id
         {WHERE}
          ORDER BY {column} {direction} NULLS LAST, c.id DESC
          LIMIT $7 OFFSET $8"
    );
    let mut list = sqlx::query_as::<_, Contact>(&sql)
        .bind(filter.group_id)
        .bind(&pattern)
        .bind(filter.active)
        .bind(&filter.tag_ids)
        .bind(since)
        .bind(active_since)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pg)
        .await?;

    let ids: Vec<i32> = list.iter().map(|c| c.id).collect();
    let tags = sqlx::query_as::<_, (i32, i32, String, i32)>(
        "SELECT ct.contact_id, t.id, t.name, ct.create_time
           FROM bm_contact_tags ct JOIN bm_tags t ON t.id = ct.tag_id
          WHERE ct.contact_id = ANY($1)
          ORDER BY ct.create_time DESC, t.id",
    )
    .bind(&ids)
    .fetch_all(pg)
    .await?;
    for contact in &mut list {
        contact.tags = tags
            .iter()
            .filter(|(contact_id, ..)| *contact_id == contact.id)
            .map(|(_, id, name, create_time)| ContactTag {
                id: *id,
                name: name.clone(),
                create_time: *create_time,
            })
            .collect();
    }
    Ok(Page { total, list })
}

/// Places one address in exactly `group_ids`, keeping the rows (and their
/// tags and history) of groups it stays in. Go deleted every row of the
/// address and recreated them. Attributes and status come from the
/// address's newest row unless `attribs` is given.
pub async fn set_groups(
    pg: &PgPool,
    email: &str,
    group_ids: &[i32],
    active: Option<i32>,
    attribs: Option<&str>,
    now: i32,
) -> Result<()> {
    let mut tx = pg.begin().await?;
    let newest = sqlx::query_as::<_, (String, i32)>(
        "SELECT COALESCE(attribs, '{}'::jsonb)::text, COALESCE(status, 0)
           FROM bm_contacts WHERE email = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?;
    let (old_attribs, status) = newest.unwrap_or_else(|| ("{}".to_owned(), 0));
    let attribs = attribs.unwrap_or(&old_attribs);

    sqlx::query(
        "DELETE FROM bm_contact_tags WHERE contact_id IN
            (SELECT id FROM bm_contacts WHERE email = $1 AND group_id <> ALL($2))",
    )
    .bind(email)
    .bind(group_ids)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM bm_contacts WHERE email = $1 AND (group_id IS NULL OR group_id <> ALL($2))",
    )
    .bind(email)
    .bind(group_ids)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO bm_contacts (email, group_id, active, task_id, status, attribs, create_time)
         SELECT $1, g, COALESCE($3, 1), 0, $4, $5::jsonb, $6 FROM unnest($2::int[]) AS g
         ON CONFLICT (group_id, email) DO UPDATE
            SET active = COALESCE($3, bm_contacts.active), attribs = $5::jsonb",
    )
    .bind(email)
    .bind(group_ids)
    .bind(active)
    .bind(status)
    .bind(attribs)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Updates subscription state and/or attributes on every row of an address.
pub async fn update_address(
    pg: &PgPool,
    email: &str,
    active: Option<i32>,
    attribs: Option<&str>,
) -> Result<u64> {
    Ok(sqlx::query(
        "UPDATE bm_contacts SET active = COALESCE($2, active), attribs = COALESCE($3::jsonb, attribs)
          WHERE email = $1",
    )
    .bind(email)
    .bind(active)
    .bind(attribs)
    .execute(pg)
    .await?
    .rows_affected())
}

/// Updates one contact row; returns its address, or `None` when missing.
pub async fn update_row(
    pg: &PgPool,
    id: i32,
    active: Option<i32>,
    status: Option<i32>,
    attribs: Option<&str>,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, String>(
        "UPDATE bm_contacts
            SET active = COALESCE($2, active), status = COALESCE($3, status),
                attribs = COALESCE($4::jsonb, attribs)
          WHERE id = $1
         RETURNING email",
    )
    .bind(id)
    .bind(active)
    .bind(status)
    .bind(attribs)
    .fetch_optional(pg)
    .await?)
}

/// Deletes the rows of these addresses in the given subscription state, in
/// every group, with their tag assignments (Go left those behind).
pub async fn delete_addresses(pg: &PgPool, emails: &[String], active: i32) -> Result<u64> {
    let mut tx = pg.begin().await?;
    sqlx::query(
        "DELETE FROM bm_contact_tags WHERE contact_id IN
            (SELECT id FROM bm_contacts WHERE email = ANY($1) AND active = $2)",
    )
    .bind(emails)
    .bind(active)
    .execute(&mut *tx)
    .await?;
    let deleted = sqlx::query("DELETE FROM bm_contacts WHERE email = ANY($1) AND active = $2")
        .bind(emails)
        .bind(active)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(deleted)
}

/// Deletes contact rows by ID with their tag assignments; returns the
/// deleted `(id, email, group_id)`.
pub async fn delete_rows(pg: &PgPool, ids: &[i32]) -> Result<Vec<(i32, String, i32)>> {
    let mut tx = pg.begin().await?;
    sqlx::query("DELETE FROM bm_contact_tags WHERE contact_id = ANY($1)")
        .bind(ids)
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query_as::<_, (i32, String, i32)>(
        "DELETE FROM bm_contacts WHERE id = ANY($1) RETURNING id, email, COALESCE(group_id, 0)",
    )
    .bind(ids)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(deleted)
}

/// Moves addresses (in one subscription state) into exactly `group_ids`:
/// rows in other groups are removed, missing memberships are added with the
/// address's newest attributes and status, and rows already in a target
/// group are kept with their tags. Go deleted and re-inserted everything,
/// and failed outright when an address was already in a target group with
/// another state. Returns the memberships now in place.
pub async fn move_addresses(
    pg: &PgPool,
    emails: &[String],
    active: i32,
    group_ids: &[i32],
    now: i32,
) -> Result<i64> {
    let mut tx = pg.begin().await?;
    for sql in [
        "DELETE FROM bm_contact_tags WHERE contact_id IN
            (SELECT id FROM bm_contacts
              WHERE email = ANY($1) AND active = $2 AND (group_id IS NULL OR group_id <> ALL($3)))",
        "DELETE FROM bm_contacts
          WHERE email = ANY($1) AND active = $2 AND (group_id IS NULL OR group_id <> ALL($3))",
    ] {
        sqlx::query(sql)
            .bind(emails)
            .bind(active)
            .bind(group_ids)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO bm_contacts (email, group_id, active, task_id, status, attribs, create_time)
         SELECT e.email, g.id, $2, 0, COALESCE(n.status, 0), COALESCE(n.attribs, '{}'::jsonb), $4
           FROM unnest($1::text[]) AS e(email)
          CROSS JOIN unnest($3::int[]) AS g(id)
           LEFT JOIN (SELECT DISTINCT ON (email) email, status, attribs FROM bm_contacts
                       WHERE email = ANY($1) ORDER BY email, id DESC) n ON n.email = e.email
         ON CONFLICT (group_id, email) DO NOTHING",
    )
    .bind(emails)
    .bind(active)
    .bind(group_ids)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let placed = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM bm_contacts WHERE email = ANY($1) AND group_id = ANY($3) AND active = $2",
    )
    .bind(emails)
    .bind(active)
    .bind(group_ids)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(placed)
}

/// Outcome of adding or removing tags on contact rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagChange {
    pub changed: u64,
    /// Requested pairs not changed (already in that state, tag from
    /// another group, or unknown contact/tag).
    pub skipped: u64,
}

/// Tags contact rows. A tag only applies to contacts of its own group.
pub async fn tag_rows(
    pg: &PgPool,
    contact_ids: &[i32],
    tag_ids: &[i32],
    now: i32,
) -> Result<TagChange> {
    let mut tx = pg.begin().await?;
    let (contacts, tags) = existing_counts(&mut tx, contact_ids, tag_ids).await?;
    if contacts == 0 || tags == 0 {
        return Ok(TagChange {
            changed: 0,
            skipped: contact_ids.len() as u64,
        });
    }
    let changed = sqlx::query(
        "INSERT INTO bm_contact_tags (contact_id, tag_id, create_time)
         SELECT c.id, t.id, $3
           FROM bm_contacts c JOIN bm_tags t ON t.group_id = c.group_id
          WHERE c.id = ANY($1) AND t.id = ANY($2)
         ON CONFLICT (contact_id, tag_id) DO NOTHING",
    )
    .bind(contact_ids)
    .bind(tag_ids)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(TagChange {
        changed,
        skipped: (contacts * tags).saturating_sub(changed),
    })
}

/// Removes tags from contact rows.
pub async fn untag_rows(pg: &PgPool, contact_ids: &[i32], tag_ids: &[i32]) -> Result<TagChange> {
    let mut tx = pg.begin().await?;
    let (contacts, tags) = existing_counts(&mut tx, contact_ids, tag_ids).await?;
    if contacts == 0 || tags == 0 {
        return Ok(TagChange {
            changed: 0,
            skipped: contact_ids.len() as u64,
        });
    }
    let changed =
        sqlx::query("DELETE FROM bm_contact_tags WHERE contact_id = ANY($1) AND tag_id = ANY($2)")
            .bind(contact_ids)
            .bind(tag_ids)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    tx.commit().await?;
    Ok(TagChange {
        changed,
        skipped: (contacts * tags).saturating_sub(changed),
    })
}

async fn existing_counts(
    conn: &mut PgConnection,
    contact_ids: &[i32],
    tag_ids: &[i32],
) -> Result<(u64, u64)> {
    let (contacts, tags) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT (SELECT COUNT(*) FROM bm_contacts WHERE id = ANY($1)),
                (SELECT COUNT(*) FROM bm_tags WHERE id = ANY($2))",
    )
    .bind(contact_ids)
    .bind(tag_ids)
    .fetch_one(conn)
    .await?;
    Ok((
        u64::try_from(contacts).unwrap_or(0),
        u64::try_from(tags).unwrap_or(0),
    ))
}

#[derive(Debug, Clone, Default)]
pub struct TrendFilter {
    pub group_id: Option<i32>,
    pub active: Option<i32>,
    pub tag_ids: Vec<i32>,
    /// Bucket by `last_active_at` and keep contacts active (`true`) or not
    /// (`false`) since the given time. Otherwise bucket by `create_time`
    /// inside the window.
    pub last_active: Option<(i64, bool)>,
}

/// Distinct contacts per bucket label (UTC).
pub async fn trend(
    pg: &PgPool,
    filter: &TrendFilter,
    window: &ferropost_domain::contacts::TrendWindow,
) -> Result<Vec<(String, i64)>> {
    let (since, active_since) = match filter.last_active {
        Some((since, active)) => (Some(since), Some(active)),
        None => (None, None),
    };
    let field = if filter.last_active.is_some() {
        "c.last_active_at"
    } else {
        "c.create_time"
    };
    let sql = format!(
        "SELECT to_char(to_timestamp({field}) AT TIME ZONE 'UTC', '{format}') AS label,
                COUNT(DISTINCT c.id)
           FROM bm_contacts c
          WHERE ($1::int IS NULL OR c.group_id = $1)
            AND ($2::int IS NULL OR c.active = $2)
            AND (cardinality($3::int[]) = 0 OR EXISTS (
                 SELECT 1 FROM bm_contact_tags ct WHERE ct.contact_id = c.id AND ct.tag_id = ANY($3)))
            AND ($4::bigint IS NULL
                 OR ($5 AND c.last_active_at >= $4)
                 OR (NOT $5 AND (c.last_active_at IS NULL OR c.last_active_at < $4)))
            AND ($4::bigint IS NOT NULL OR c.create_time BETWEEN $6 AND $7)
          GROUP BY label
          ORDER BY label",
        format = window.granularity.sql_format(),
    );
    Ok(sqlx::query_as::<_, (String, i64)>(&sql)
        .bind(filter.group_id)
        .bind(filter.active)
        .bind(&filter.tag_ids)
        .bind(since)
        .bind(active_since)
        .bind(window.start)
        .bind(window.end)
        .fetch_all(pg)
        .await?)
}

/// A contact as exported.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ExportRow {
    pub email: String,
    pub attribs: String,
    pub active: i32,
    pub create_time: i32,
}

/// One row per address across the groups. Subscription state is kept when
/// every group agrees, otherwise unsubscribed (Go's rule); attributes and
/// creation time come from the oldest row. Sorted by address (Go's order
/// was random).
pub async fn export_merged(
    pg: &PgPool,
    group_ids: &[i32],
    include_inactive: bool,
) -> Result<Vec<ExportRow>> {
    Ok(sqlx::query_as::<_, ExportRow>(
        "SELECT email, attribs, active, create_time FROM (
             SELECT email,
                    (ARRAY_AGG(COALESCE(attribs, '{}'::jsonb)::text ORDER BY id))[1] AS attribs,
                    CASE WHEN MIN(active) = MAX(active) THEN MIN(active) ELSE 0 END AS active,
                    (ARRAY_AGG(create_time ORDER BY id))[1] AS create_time
               FROM bm_contacts WHERE group_id = ANY($1) GROUP BY email
         ) merged
          WHERE $2 OR active = 1
          ORDER BY email",
    )
    .bind(group_ids)
    .bind(include_inactive)
    .fetch_all(pg)
    .await?)
}

pub async fn export_group(
    pg: &PgPool,
    group_id: i32,
    include_inactive: bool,
) -> Result<Vec<ExportRow>> {
    Ok(sqlx::query_as::<_, ExportRow>(
        "SELECT email, COALESCE(attribs, '{}'::jsonb)::text AS attribs, COALESCE(active, 0) AS active, create_time
           FROM bm_contacts
          WHERE group_id = $1 AND ($2 OR active = 1)
          ORDER BY id",
    )
    .bind(group_id)
    .bind(include_inactive)
    .fetch_all(pg)
    .await?)
}
