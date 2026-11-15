//! `mailstat_*` tables fed from Postfix's `mail.log`.

use std::collections::HashMap;

use anyhow::Result;
use ferropost_domain::maillog::{Delivery, Event};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};

/// Where the next unread line of `mail.log` starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub inode: u64,
    pub offset: u64,
    /// Lines at or before this time (Unix ms) are skipped. Set to Go's
    /// watermark on the first pass so history Go already stored is not
    /// stored again; reset when the log rotates.
    #[serde(default)]
    pub skip_until: i64,
}

const CURSOR_OPTION: &str = "ferropost_maillog_cursor";
/// Go's watermark, still maintained so Go can resume if switched back.
const GO_WATERMARK: &str = "last_maillog_time_millis";
const AGGREGATE_WATERMARK: &str = "last_maillog_aggregate_time_millis";

pub async fn cursor(pg: &PgPool) -> Result<Option<Cursor>> {
    Ok(crate::options::get(pg, CURSOR_OPTION)
        .await?
        .and_then(|raw| serde_json::from_str(&raw).ok()))
}

/// Go's last processed log time, used once to start where Go stopped.
pub async fn go_watermark(pg: &PgPool) -> Result<i64> {
    Ok(crate::options::get(pg, GO_WATERMARK)
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0))
}

/// Writes one batch of events and the cursor after it atomically, so every
/// line is stored exactly once even if the process stops mid-way. Go's
/// timestamp watermark re-read the last second each round, duplicating
/// deferred entries.
///
/// Returns `false` without writing when another instance holds the lock.
pub async fn store_batch(pg: &PgPool, events: &[(i64, Event)], cursor: Cursor) -> Result<bool> {
    let mut tx = pg.begin().await?;
    let locked: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext('ferropost:maillog'))")
            .fetch_one(&mut *tx)
            .await?;
    if !locked {
        return Ok(false);
    }

    let mut sent: HashMap<&str, (i64, &Delivery)> = HashMap::new();
    let mut received: HashMap<&str, (i64, &Delivery)> = HashMap::new();
    let mut deferred = Vec::new();
    let mut message_ids = Vec::new();
    let mut senders = Vec::new();
    let mut removed = Vec::new();
    let mut newest = 0;

    for (time, event) in events {
        newest = newest.max(*time);
        match event {
            Event::Sent(d) => {
                if d.status == "deferred" {
                    deferred.push((*time, d));
                }
                keep_newest(&mut sent, *time, d);
            }
            Event::Received(d) => keep_newest(&mut received, *time, d),
            Event::MessageId {
                queue_id,
                message_id,
            } => message_ids.push((*time, queue_id, message_id)),
            Event::Sender {
                queue_id,
                sender,
                size,
            } => senders.push((*time, queue_id, sender, *size)),
            Event::Removed { queue_id } => removed.push((*time, queue_id)),
        }
    }

    upsert_deliveries(&mut tx, "mailstat_send_mails", &sent, true).await?;
    upsert_deliveries(&mut tx, "mailstat_receive_mails", &received, false).await?;
    if !deferred.is_empty() {
        sqlx::query(
            "INSERT INTO mailstat_deferred_mails
                    (postfix_message_id, log_time_millis, delay, delays, dsn, relay, description)
             SELECT * FROM unnest($1::text[], $2::bigint[], $3::real[], $4::text[], $5::text[], $6::text[], $7::text[])",
        )
        .bind(deferred.iter().map(|(_, d)| d.queue_id.as_str()).collect::<Vec<_>>())
        .bind(deferred.iter().map(|(t, _)| *t).collect::<Vec<_>>())
        .bind(deferred.iter().map(|(_, d)| d.delay as f32).collect::<Vec<_>>())
        .bind(deferred.iter().map(|(_, d)| d.delays.as_str()).collect::<Vec<_>>())
        .bind(deferred.iter().map(|(_, d)| d.dsn.as_str()).collect::<Vec<_>>())
        .bind(deferred.iter().map(|(_, d)| d.relay.as_str()).collect::<Vec<_>>())
        .bind(deferred.iter().map(|(_, d)| d.description.as_str()).collect::<Vec<_>>())
        .execute(&mut *tx)
        .await?;
    }
    if !message_ids.is_empty() {
        sqlx::query(
            "INSERT INTO mailstat_message_ids (postfix_message_id, log_time_millis, message_id)
             SELECT * FROM unnest($1::text[], $2::bigint[], $3::text[])
             ON CONFLICT (postfix_message_id) DO NOTHING",
        )
        .bind(
            message_ids
                .iter()
                .map(|(_, q, _)| q.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(message_ids.iter().map(|(t, _, _)| *t).collect::<Vec<_>>())
        .bind(
            message_ids
                .iter()
                .map(|(_, _, m)| m.as_str())
                .collect::<Vec<_>>(),
        )
        .execute(&mut *tx)
        .await?;
    }
    if !senders.is_empty() {
        sqlx::query(
            "INSERT INTO mailstat_senders (postfix_message_id, log_time_millis, sender, size)
             SELECT * FROM unnest($1::text[], $2::bigint[], $3::text[], $4::int[])
             ON CONFLICT (postfix_message_id) DO NOTHING",
        )
        .bind(
            senders
                .iter()
                .map(|(_, q, _, _)| q.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(senders.iter().map(|(t, _, _, _)| *t).collect::<Vec<_>>())
        .bind(
            senders
                .iter()
                .map(|(_, _, s, _)| s.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(
            senders
                .iter()
                .map(|(_, _, _, size)| i32::try_from(*size).unwrap_or(i32::MAX))
                .collect::<Vec<_>>(),
        )
        .execute(&mut *tx)
        .await?;
    }
    if !removed.is_empty() {
        sqlx::query(
            "INSERT INTO mailstat_removed (postfix_message_id, log_time_millis)
             SELECT * FROM unnest($1::text[], $2::bigint[])
             ON CONFLICT (postfix_message_id) DO NOTHING",
        )
        .bind(removed.iter().map(|(_, q)| q.as_str()).collect::<Vec<_>>())
        .bind(removed.iter().map(|(t, _)| *t).collect::<Vec<_>>())
        .execute(&mut *tx)
        .await?;
    }

    set_option(&mut tx, CURSOR_OPTION, &serde_json::to_string(&cursor)?).await?;
    if newest > 0 {
        sqlx::query(
            "INSERT INTO bm_options (name, value) VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE SET value = CASE
                 WHEN bm_options.value ~ '^[0-9]+$'
                 THEN GREATEST(bm_options.value::bigint, EXCLUDED.value::bigint)::text
                 ELSE EXCLUDED.value END",
        )
        .bind(GO_WATERMARK)
        .bind(newest.to_string())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// One row per queue ID (the tables are keyed by it): the newest line wins.
fn keep_newest<'a>(map: &mut HashMap<&'a str, (i64, &'a Delivery)>, time: i64, d: &'a Delivery) {
    match map.get(d.queue_id.as_str()) {
        Some((existing, _)) if *existing > time => {}
        _ => {
            map.insert(d.queue_id.as_str(), (time, d));
        }
    }
}

async fn upsert_deliveries(
    conn: &mut PgConnection,
    table: &'static str,
    rows: &HashMap<&str, (i64, &Delivery)>,
    with_provider: bool,
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let rows: Vec<&(i64, &Delivery)> = rows.values().collect();
    let newer = |column: &str| {
        format!(
            "{column} = CASE WHEN EXCLUDED.log_time_millis > {table}.log_time_millis
                             THEN EXCLUDED.{column} ELSE {table}.{column} END"
        )
    };
    let updates = [
        "status",
        "delay",
        "delays",
        "dsn",
        "relay",
        "description",
        "log_time_millis",
    ]
    .map(newer)
    .join(", ");
    let (provider_col, provider_val) = if with_provider {
        (", mail_provider", ", unnest($10::text[])")
    } else {
        ("", "")
    };
    let sql = format!(
        "INSERT INTO {table} (postfix_message_id, log_time_millis, status, recipient, delay, delays, dsn, relay, description{provider_col})
         SELECT unnest($1::text[]), unnest($2::bigint[]), unnest($3::text[]), unnest($4::text[]),
                unnest($5::real[]), unnest($6::text[]), unnest($7::text[]), unnest($8::text[]), unnest($9::text[]){provider_val}
         ON CONFLICT (postfix_message_id) DO UPDATE SET {updates}"
    );
    let mut query = sqlx::query(&sql)
        .bind(
            rows.iter()
                .map(|(_, d)| d.queue_id.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(rows.iter().map(|(t, _)| *t).collect::<Vec<_>>())
        .bind(
            rows.iter()
                .map(|(_, d)| d.status.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(
            rows.iter()
                .map(|(_, d)| d.recipient.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(rows.iter().map(|(_, d)| d.delay as f32).collect::<Vec<_>>())
        .bind(
            rows.iter()
                .map(|(_, d)| d.delays.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(rows.iter().map(|(_, d)| d.dsn.as_str()).collect::<Vec<_>>())
        .bind(
            rows.iter()
                .map(|(_, d)| d.relay.as_str())
                .collect::<Vec<_>>(),
        )
        .bind(
            rows.iter()
                .map(|(_, d)| d.description.as_str())
                .collect::<Vec<_>>(),
        );
    if with_provider {
        query = query.bind(rows.iter().map(|(_, d)| d.provider).collect::<Vec<_>>());
    }
    query.execute(conn).await?;
    Ok(())
}

async fn set_option(conn: &mut PgConnection, name: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO bm_options (name, value) VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(name)
    .bind(value)
    .execute(conn)
    .await?;
    Ok(())
}

/// Copies deliveries between your own domains (sender and recipient both
/// on an active domain) from `mailstat_receive_mails` into
/// `mailstat_send_mails` as provider `local` (Go's `AggregateMaillogs`).
/// Idempotent, and each run re-scans the last hour so senders whose
/// delivery line arrived later are not skipped. Returns rows added.
pub async fn aggregate_local(pg: &PgPool, now_millis: i64) -> Result<u64> {
    const OVERLAP_MILLIS: i64 = 3_600_000;
    const FIRST_RUN_MILLIS: i64 = 90 * 86_400_000;
    let watermark: Option<i64> = crate::options::get(pg, AGGREGATE_WATERMARK)
        .await?
        .and_then(|v| v.parse().ok());
    let start = watermark.map_or(now_millis - FIRST_RUN_MILLIS, |w| w - OVERLAP_MILLIS);

    let mut tx = pg.begin().await?;
    let added = sqlx::query(
        "INSERT INTO mailstat_send_mails
                (postfix_message_id, log_time_millis, status, recipient, mail_provider,
                 delay, delays, dsn, relay, description)
         SELECT rm.postfix_message_id, rm.log_time_millis, rm.status, rm.recipient, 'local',
                rm.delay, rm.delays, rm.dsn, rm.relay, rm.description
           FROM mailstat_senders s
           JOIN mailstat_receive_mails rm ON rm.postfix_message_id = s.postfix_message_id
          WHERE s.log_time_millis > $1 AND s.log_time_millis < $2
            AND lower(split_part(s.sender, '@', 2)) IN (SELECT lower(domain) FROM domain WHERE active = 1)
            AND lower(split_part(rm.recipient, '@', 2)) IN (SELECT lower(domain) FROM domain WHERE active = 1)
         ON CONFLICT (postfix_message_id) DO NOTHING",
    )
    .bind(start)
    .bind(now_millis)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    set_option(&mut tx, AGGREGATE_WATERMARK, &now_millis.to_string()).await?;
    tx.commit().await?;
    Ok(added)
}
