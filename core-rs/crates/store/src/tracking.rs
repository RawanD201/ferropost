//! Open and click events from tracking links.

use anyhow::Result;
use ferropost_domain::tracking::{API_CAMPAIGN_FLOOR, EventKind, TrackingEvent};
use sqlx::PgPool;

/// Records an open or click and marks the contact active.
///
/// Tracking tokens can be forged (see `ferropost_domain::tracking`), so an
/// event is only accepted when its message ID belongs to mail this server
/// sent (Postfix logged it). Returns `false` when it does not; the caller
/// then neither counts it nor redirects.
pub async fn record(pg: &PgPool, event: &TrackingEvent, now_millis: i64) -> Result<bool> {
    let Some(postfix_id) = sqlx::query_scalar::<_, String>(
        "SELECT postfix_message_id FROM mailstat_message_ids WHERE message_id = $1 LIMIT 1",
    )
    .bind(&event.message_id)
    .fetch_optional(pg)
    .await?
    else {
        return Ok(false);
    };

    let mut tx = pg.begin().await?;
    let sql = match event.kind {
        EventKind::Open => {
            "INSERT INTO mailstat_opened (campaign_id, log_time_millis, recipient, message_id, postfix_message_id)
             VALUES ($1, $2, $3, $4, $5)"
        }
        // Go left `url` empty although the column exists.
        EventKind::Click => {
            "INSERT INTO mailstat_clicked (campaign_id, log_time_millis, recipient, message_id, postfix_message_id, url)
             VALUES ($1, $2, $3, $4, $5, $6)"
        }
    };
    sqlx::query(sql)
        .bind(i32::try_from(event.campaign_id).unwrap_or(i32::MAX))
        .bind(now_millis)
        .bind(&event.recipient)
        .bind(&event.message_id)
        .bind(&postfix_id)
        .bind(&event.url)
        .execute(&mut *tx)
        .await?;

    // Campaign sends update the campaign's group; API sends every group.
    // Go buffered these in memory for up to 30 s and dropped them when busy.
    sqlx::query(
        "UPDATE bm_contacts SET last_active_at = $2
          WHERE email = $1
            AND ($3 OR group_id = (SELECT group_id FROM email_tasks WHERE id = $4))",
    )
    .bind(&event.recipient)
    .bind(i32::try_from(now_millis / 1000).unwrap_or(i32::MAX))
    .bind(event.campaign_id > API_CAMPAIGN_FLOOR)
    .bind(i32::try_from(event.campaign_id).unwrap_or(0))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}
