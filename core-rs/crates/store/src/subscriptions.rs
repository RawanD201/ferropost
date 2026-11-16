//! Subscribe and unsubscribe flows (`bm_contacts`, `unsubscribe_records`).

use anyhow::Result;
use ferropost_domain::groups::ContactGroup;
use sqlx::PgPool;

/// A group by its public subscribe token. An empty token matches nothing
/// (Go matched groups created before tokens existed).
pub async fn group_by_token(pg: &PgPool, token: &str) -> Result<Option<ContactGroup>> {
    if token.trim().is_empty() {
        return Ok(None);
    }
    let id =
        sqlx::query_scalar::<_, i32>("SELECT id FROM bm_contact_groups WHERE token = $1 LIMIT 1")
            .bind(token)
            .fetch_optional(pg)
            .await?;
    match id {
        Some(id) => crate::groups::get(pg, id).await,
        None => Ok(None),
    }
}

/// `(active, status)` of an address in a group.
pub async fn membership(pg: &PgPool, email: &str, group_id: i32) -> Result<Option<(i32, i32)>> {
    Ok(sqlx::query_as::<_, (i32, i32)>(
        "SELECT COALESCE(active, 0), COALESCE(status, 0) FROM bm_contacts WHERE email = $1 AND group_id = $2",
    )
    .bind(email)
    .bind(group_id)
    .fetch_optional(pg)
    .await?)
}

/// Adds the address (or updates it) with `status` 0 pending / 1 confirmed,
/// merging submitted attributes into existing ones (Go replaced them).
pub async fn upsert_subscriber(
    pg: &PgPool,
    email: &str,
    group_id: i32,
    attribs: &serde_json::Value,
    status: i32,
    now: i32,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO bm_contacts (email, group_id, active, status, attribs, create_time, last_active_at)
         VALUES ($1, $2, 1, $3, $4, $5, $5)
         ON CONFLICT (group_id, email) DO UPDATE
            SET status = EXCLUDED.status,
                attribs = COALESCE(bm_contacts.attribs, '{}'::jsonb) || EXCLUDED.attribs,
                last_active_at = EXCLUDED.last_active_at",
    )
    .bind(email)
    .bind(group_id)
    .bind(status)
    .bind(attribs)
    .bind(now)
    .execute(pg)
    .await?;
    Ok(())
}

/// Marks the address subscribed and confirmed.
pub async fn confirm(pg: &PgPool, email: &str, group_id: i32, now: i32) -> Result<()> {
    sqlx::query(
        "UPDATE bm_contacts SET status = 1, active = 1, last_active_at = $3 WHERE email = $1 AND group_id = $2",
    )
    .bind(email)
    .bind(group_id)
    .bind(now)
    .execute(pg)
    .await?;
    Ok(())
}

/// Unsubscribes an address from groups and records it, atomically.
pub async fn unsubscribe(
    pg: &PgPool,
    email: &str,
    group_ids: &[i32],
    template_id: i64,
    task_id: i64,
    now: i32,
) -> Result<()> {
    let mut tx = pg.begin().await?;
    sqlx::query(
        "UPDATE bm_contacts SET active = 0, last_active_at = $3 WHERE email = $1 AND group_id = ANY($2)",
    )
    .bind(email)
    .bind(group_ids)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO unsubscribe_records (email, group_id, template_id, task_id, unsubscribe_time)
         SELECT $1, g, $3, $4, $5 FROM unnest($2::int[]) AS g",
    )
    .bind(email)
    .bind(group_ids)
    .bind(i32::try_from(template_id).unwrap_or(0))
    .bind(i32::try_from(task_id).unwrap_or(0))
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Groups an address is subscribed to, for the unsubscribe page.
pub async fn subscribed_groups(pg: &PgPool, email: &str) -> Result<Vec<(i32, String)>> {
    Ok(sqlx::query_as::<_, (i32, String)>(
        "SELECT g.id, g.name FROM bm_contacts c JOIN bm_contact_groups g ON g.id = c.group_id
          WHERE c.email = $1 AND c.active = 1 ORDER BY g.id",
    )
    .bind(email)
    .fetch_all(pg)
    .await?)
}

/// Extra evidence for a legacy (forgeable) unsubscribe token: the campaign
/// it names was sent to this address (Go's send-API mail put the API's ID
/// there, so a delivery through that API counts too), or, without a
/// campaign, the address is in the group.
pub async fn legacy_token_plausible(
    pg: &PgPool,
    email: &str,
    task_id: i64,
    group_id: i64,
) -> Result<bool> {
    let sql = if task_id > 0 {
        "SELECT EXISTS (SELECT 1 FROM recipient_info WHERE task_id = $2 AND recipient = $1)
             OR EXISTS (SELECT 1 FROM api_mail_logs WHERE api_id = $2 AND recipient = $1)"
    } else {
        "SELECT EXISTS (SELECT 1 FROM bm_contacts WHERE email = $1 AND group_id = $3)"
    };
    Ok(sqlx::query_scalar::<_, bool>(sql)
        .bind(email)
        .bind(i32::try_from(task_id).unwrap_or(0))
        .bind(i32::try_from(group_id).unwrap_or(0))
        .fetch_one(pg)
        .await?)
}

/// Attributes and state of the address's first contact row (Go's lookup
/// for personalising system mail).
pub async fn first_contact(
    pg: &PgPool,
    email: &str,
) -> Result<Option<(serde_json::Value, i32, i32)>> {
    Ok(sqlx::query_as::<_, (serde_json::Value, i32, i32)>(
        "SELECT COALESCE(attribs, '{}'::jsonb), COALESCE(active, 0), COALESCE(status, 0)
           FROM bm_contacts WHERE email = $1 ORDER BY id LIMIT 1",
    )
    .bind(email)
    .fetch_optional(pg)
    .await?)
}

/// The domain system mail is sent from: the configured one, else the
/// oldest active domain (saved, as Go did).
pub async fn default_sender_domain(pg: &PgPool) -> Result<Option<String>> {
    if let Some(domain) = crate::options::get(pg, "default_sender_domain").await? {
        return Ok(Some(domain));
    }
    let oldest = sqlx::query_scalar::<_, String>(
        "SELECT domain FROM domain WHERE active = 1 ORDER BY create_time, domain LIMIT 1",
    )
    .fetch_optional(pg)
    .await?;
    if let Some(domain) = &oldest {
        crate::options::set(pg, "default_sender_domain", domain).await?;
    }
    Ok(oldest)
}

/// Sender address of a campaign.
pub async fn task_sender(pg: &PgPool, task_id: i64) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT addresser FROM email_tasks WHERE id = $1")
            .bind(i32::try_from(task_id).unwrap_or(0))
            .fetch_optional(pg)
            .await?,
    )
}
