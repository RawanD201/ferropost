//! Contacts (`bm_contacts`).

use anyhow::Result;
use ferropost_domain::contacts::ImportedContact;
use sqlx::{PgConnection, Postgres};

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
