//! Campaigns (`email_tasks`) and their recipients (`recipient_info`).
//!
//! `recipient_info` is the send queue. The sender claims rows (`is_sent =
//! 2`) with `FOR UPDATE SKIP LOCKED` and settles each one right after its
//! submission, so a restart loses nothing: claims left behind are released
//! when the sender starts. Go kept claims only in memory and lost them on
//! a restart, and the rows a warmup limit skipped stayed claimed forever,
//! so such campaigns never finished.

use std::collections::HashMap;

use anyhow::Result;
use ferropost_domain::campaigns::{Task, format_tag_ids, recipient, status};
use ferropost_domain::groups::TagLogic;
use sqlx::{PgPool, Postgres, Transaction};

const COLUMNS: &str = "id, task_name, addresser, COALESCE(subject, '') AS subject,
    COALESCE(full_name, '') AS full_name, recipient_count, task_process::int AS task_process,
    pause::int AS pause, template_id, is_record::int AS is_record,
    unsubscribe::int AS unsubscribe, threads, track_open::int AS track_open,
    track_click::int AS track_click, start_time, create_time, update_time,
    COALESCE(remark, '') AS remark, active::int AS active, add_type::int AS add_type,
    sends_count, delivered_count, bounced_count, deferred_count, stats_update_time, group_id,
    COALESCE(tag_ids, '') AS tag_ids, COALESCE(tag_logic, '') AS tag_logic";

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub async fn get(pg: &PgPool, id: i32) -> Result<Option<Task>> {
    Ok(
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM email_tasks WHERE id = $1"))
            .bind(id)
            .fetch_optional(pg)
            .await?,
    )
}

/// A page of campaigns, newest first. The keyword matches the name or the
/// subject; Go's `OR` also escaped the status filter.
pub async fn list(
    pg: &PgPool,
    keyword: Option<&str>,
    status: Option<i32>,
    page: i64,
    page_size: i64,
) -> Result<(i64, Vec<Task>)> {
    let pattern = keyword.map(|k| format!("%{}%", like_escape(k)));
    let filter = "($1::text IS NULL OR task_name LIKE $1 OR subject LIKE $1)
        AND ($2::int IS NULL OR task_process = $2)";
    let total: i64 =
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM email_tasks WHERE {filter}"))
            .bind(&pattern)
            .bind(status)
            .fetch_one(pg)
            .await?;
    let tasks = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM email_tasks WHERE {filter}
          ORDER BY create_time DESC, id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(&pattern)
    .bind(status)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pg)
    .await?;
    Ok((total, tasks))
}

/// Recipient rows per campaign, for those whose stored count is unset (Go
/// repaired the count while listing).
pub async fn repair_recipient_counts(pg: &PgPool, ids: &[i32]) -> Result<HashMap<i32, i32>> {
    let rows: Vec<(i32, i32)> = sqlx::query_as(
        "WITH c AS (SELECT task_id, COUNT(*)::int AS n FROM recipient_info
                     WHERE task_id = ANY($1) GROUP BY task_id)
         UPDATE email_tasks t SET recipient_count = c.n FROM c
          WHERE t.id = c.task_id RETURNING t.id, c.n",
    )
    .bind(ids)
    .fetch_all(pg)
    .await?;
    Ok(rows.into_iter().collect())
}

pub async fn group_names(pg: &PgPool, ids: &[i32]) -> Result<HashMap<i32, String>> {
    let rows: Vec<(i32, String)> =
        sqlx::query_as("SELECT id, name FROM bm_contact_groups WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(pg)
            .await?;
    Ok(rows.into_iter().collect())
}

pub async fn template_names(pg: &PgPool, ids: &[i32]) -> Result<HashMap<i32, String>> {
    let rows: Vec<(i32, String)> = sqlx::query_as(
        "SELECT id, COALESCE(temp_name, '') FROM email_templates WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(pg)
    .await?;
    Ok(rows.into_iter().collect())
}

/// `(id, name, create_time)` of tags.
pub async fn tags(pg: &PgPool, ids: &[i32]) -> Result<Vec<(i32, String, i32)>> {
    Ok(
        sqlx::query_as("SELECT id, name, create_time FROM bm_tags WHERE id = ANY($1) ORDER BY id")
            .bind(ids)
            .fetch_all(pg)
            .await?,
    )
}

/// Campaigns among `ids` tied to the sender IP warmup.
pub async fn warmup_campaigns(pg: &PgPool, ids: &[i32]) -> Result<Vec<i32>> {
    let ids: Vec<i64> = ids.iter().map(|&i| i64::from(i)).collect();
    let rows: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT task_id FROM bm_campaign_warmup WHERE task_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(pg)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|i| i32::try_from(i).ok())
        .collect())
}

pub async fn uses_warmup(pg: &PgPool, task_id: i32) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM bm_campaign_warmup WHERE task_id = $1)")
            .bind(i64::from(task_id))
            .fetch_one(pg)
            .await?,
    )
}

/// Ties a campaign to an IP's warmup (Go: `AssociateCampaignWithWarmup`).
pub async fn associate_warmup(pg: &PgPool, task_id: i32, warmup_id: i32) -> Result<()> {
    sqlx::query(
        "WITH upd AS (UPDATE bm_campaign_warmup SET warmup_id = $2 WHERE task_id = $1 RETURNING id)
         INSERT INTO bm_campaign_warmup (task_id, warmup_id)
         SELECT $1, $2 WHERE NOT EXISTS (SELECT 1 FROM upd)",
    )
    .bind(i64::from(task_id))
    .bind(i64::from(warmup_id))
    .execute(pg)
    .await?;
    Ok(())
}

pub async fn dissociate_warmup(pg: &PgPool, task_id: i32) -> Result<()> {
    sqlx::query("DELETE FROM bm_campaign_warmup WHERE task_id = $1")
        .bind(i64::from(task_id))
        .execute(pg)
        .await?;
    Ok(())
}

/// Recipients still waiting, per campaign.
pub async fn unsent_counts(pg: &PgPool, ids: &[i32]) -> Result<HashMap<i32, i64>> {
    let rows: Vec<(i32, i64)> = sqlx::query_as(
        "SELECT task_id, COUNT(*) FROM recipient_info
          WHERE task_id = ANY($1) AND is_sent = 0 GROUP BY task_id",
    )
    .bind(ids)
    .fetch_all(pg)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Who a campaign for `group_id` (optionally narrowed by tags) goes to.
#[derive(Debug, Clone)]
pub struct Audience<'a> {
    pub group_id: i32,
    pub tag_ids: &'a [i32],
    pub tag_logic: TagLogic,
}

/// Confirmed, subscribed contacts of the audience, oldest first, with
/// whether the address bounced repeatedly (`abnormal_recipient`).
async fn audience(
    tx: &mut Transaction<'_, Postgres>,
    a: &Audience<'_>,
) -> Result<Vec<(String, bool)>> {
    let mut tags: Vec<i32> = a.tag_ids.to_vec();
    tags.sort_unstable();
    tags.dedup();
    let tag_filter = if tags.is_empty() {
        "TRUE"
    } else {
        crate::groups::tag_filter_sql(a.tag_logic)
    };
    Ok(sqlx::query_as(&format!(
        "SELECT c.email, EXISTS (SELECT 1 FROM abnormal_recipient ar
                                  WHERE ar.recipient = c.email AND ar.count >= 3)
           FROM bm_contacts c
          WHERE c.group_id = $1 AND c.active = 1 AND c.status = 1 AND {tag_filter}
          ORDER BY c.id"
    ))
    .bind(a.group_id)
    .bind(&tags)
    .fetch_all(&mut **tx)
    .await?)
}

/// Why a campaign got no recipients (Go's messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRecipients {
    EmptyGroup,
    NoTagMatch,
    NoneValid,
}

/// Puts the audience into the campaign's queue, skipping repeatedly
/// bouncing and invalid addresses, and stores the count.
async fn fill_queue(
    tx: &mut Transaction<'_, Postgres>,
    task_id: i32,
    a: &Audience<'_>,
    is_valid: impl Fn(&str) -> bool,
    now: i32,
) -> Result<Result<i32, NoRecipients>> {
    let candidates = audience(tx, a).await?;
    if candidates.is_empty() {
        return Ok(Err(if a.tag_ids.is_empty() {
            NoRecipients::EmptyGroup
        } else {
            NoRecipients::NoTagMatch
        }));
    }
    let emails: Vec<String> = candidates
        .into_iter()
        .filter(|(email, abnormal)| !abnormal && is_valid(email))
        .map(|(email, _)| email)
        .collect();
    if emails.is_empty() {
        return Ok(Err(NoRecipients::NoneValid));
    }
    for chunk in emails.chunks(10_000) {
        sqlx::query(
            "INSERT INTO recipient_info (task_id, recipient, is_sent, sent_time, message_id, create_time)
             SELECT $1, r, 0, 0, '', $2 FROM unnest($3::text[]) AS r
             ON CONFLICT (task_id, recipient) DO NOTHING",
        )
        .bind(task_id)
        .bind(now)
        .bind(chunk)
        .execute(&mut **tx)
        .await?;
    }
    let count: i32 = sqlx::query_scalar(
        "UPDATE email_tasks SET recipient_count = (SELECT COUNT(*) FROM recipient_info WHERE task_id = $1)
          WHERE id = $1 RETURNING recipient_count",
    )
    .bind(task_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(Ok(count))
}

/// A campaign to create.
#[derive(Debug, Clone)]
pub struct NewTask<'a> {
    pub addresser: &'a str,
    pub subject: &'a str,
    pub full_name: &'a str,
    pub template_id: i32,
    pub is_record: i32,
    pub unsubscribe: i32,
    pub threads: i32,
    pub track_open: i32,
    pub track_click: i32,
    pub start_time: i32,
    pub remark: &'a str,
    pub tag_logic: &'a str,
    pub audience: Audience<'a>,
    pub now: i32,
}

/// Creates the campaign and its queue in one transaction.
pub async fn create(
    pg: &PgPool,
    t: &NewTask<'_>,
    is_valid: impl Fn(&str) -> bool,
) -> Result<Result<i32, NoRecipients>> {
    let mut tx = pg.begin().await?;
    let id: i32 = sqlx::query_scalar(
        "INSERT INTO email_tasks (task_name, addresser, subject, full_name, recipient_count,
             task_process, pause, template_id, is_record, unsubscribe, threads, track_open,
             track_click, start_time, create_time, update_time, active, remark, add_type,
             group_id, tag_ids, tag_logic)
         VALUES ($1, $2, $3, $4, 0, 0, 0, $5, $6, $7, $8, $9, $10, $11, $12, $12, 1, $13, 0,
                 $14, $15, $16)
         RETURNING id",
    )
    .bind(format!("task_{}", t.now))
    .bind(t.addresser)
    .bind(t.subject)
    .bind(t.full_name)
    .bind(t.template_id)
    .bind(t.is_record as i16)
    .bind(t.unsubscribe as i16)
    .bind(t.threads)
    .bind(t.track_open as i16)
    .bind(t.track_click as i16)
    .bind(t.start_time)
    .bind(t.now)
    .bind(t.remark)
    .bind(t.audience.group_id)
    .bind(format_tag_ids(t.audience.tag_ids))
    .bind(t.tag_logic)
    .fetch_one(&mut *tx)
    .await?;
    match fill_queue(&mut tx, id, &t.audience, is_valid, t.now).await? {
        Ok(_) => {
            tx.commit().await?;
            Ok(Ok(id))
        }
        Err(why) => Ok(Err(why)),
    }
}

/// Fields of `task/update`; `None` keeps the stored value.
#[derive(Debug, Clone, Default)]
pub struct TaskChanges {
    pub addresser: Option<String>,
    pub subject: Option<String>,
    pub full_name: Option<String>,
    pub remark: Option<String>,
    pub template_id: Option<i32>,
    pub unsubscribe: Option<i32>,
    pub threads: Option<i32>,
    pub start_time: Option<i32>,
    pub tag_ids: Option<Vec<i32>>,
    pub tag_logic: Option<String>,
}

/// Applies the changes. A campaign that has not started gets its queue
/// rebuilt when its tag filter changed (Go kept the old recipients, so the
/// change had no effect).
pub async fn update(
    pg: &PgPool,
    task: &Task,
    c: &TaskChanges,
    is_valid: impl Fn(&str) -> bool,
    now: i32,
) -> Result<Result<(), NoRecipients>> {
    let mut tx = pg.begin().await?;
    let tag_ids = c.tag_ids.as_deref().map(format_tag_ids);
    sqlx::query(
        "UPDATE email_tasks SET
            addresser = COALESCE($2, addresser), subject = COALESCE($3, subject),
            full_name = COALESCE($4, full_name), remark = COALESCE($5, remark),
            template_id = COALESCE($6, template_id), unsubscribe = COALESCE($7, unsubscribe),
            threads = COALESCE($8, threads), start_time = COALESCE($9, start_time),
            tag_ids = COALESCE($10, tag_ids), tag_logic = COALESCE($11, tag_logic),
            update_time = $12
          WHERE id = $1",
    )
    .bind(task.id)
    .bind(&c.addresser)
    .bind(&c.subject)
    .bind(&c.full_name)
    .bind(&c.remark)
    .bind(c.template_id)
    .bind(c.unsubscribe.map(|v| v as i16))
    .bind(c.threads)
    .bind(c.start_time)
    .bind(&tag_ids)
    .bind(&c.tag_logic)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    let new_tags = c.tag_ids.clone().unwrap_or_else(|| task.tag_ids());
    let new_logic = c
        .tag_logic
        .clone()
        .unwrap_or_else(|| task.tag_logic.clone());
    let filter_changed = new_tags != task.tag_ids() || new_logic != task.tag_logic;
    if task.task_process == status::NOT_STARTED && filter_changed {
        sqlx::query("DELETE FROM recipient_info WHERE task_id = $1")
            .bind(task.id)
            .execute(&mut *tx)
            .await?;
        let audience = Audience {
            group_id: task.group_id,
            tag_ids: &new_tags,
            tag_logic: TagLogic::parse(&new_logic).unwrap_or(TagLogic::All),
        };
        if let Err(why) = fill_queue(&mut tx, task.id, &audience, is_valid, now).await? {
            return Ok(Err(why));
        }
    }
    tx.commit().await?;
    Ok(Ok(()))
}

/// Deletes a campaign (its queue goes with it) and returns its subject.
pub async fn delete(pg: &PgPool, id: i32) -> Result<Option<String>> {
    let mut tx = pg.begin().await?;
    let subject: Option<Option<String>> =
        sqlx::query_scalar("DELETE FROM email_tasks WHERE id = $1 RETURNING subject")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    sqlx::query("DELETE FROM bm_campaign_warmup WHERE task_id = $1")
        .bind(i64::from(id))
        .execute(&mut *tx)
        .await?;
    // The foreign key cascades too; this keeps the queue clean without it.
    sqlx::query("DELETE FROM recipient_info WHERE task_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(subject.map(Option::unwrap_or_default))
}

/// Pauses (`task_process` 3) or resumes (1) a campaign. The sender checks
/// the flag before every batch it claims.
pub async fn set_paused(pg: &PgPool, id: i32, paused: bool) -> Result<()> {
    sqlx::query("UPDATE email_tasks SET pause = $2, task_process = $3 WHERE id = $1")
        .bind(id)
        .bind(i16::from(paused))
        .bind(
            (if paused {
                status::PAUSED
            } else {
                status::RUNNING
            }) as i16,
        )
        .execute(pg)
        .await?;
    Ok(())
}

pub async fn set_threads(pg: &PgPool, id: i32, threads: i32) -> Result<()> {
    sqlx::query("UPDATE email_tasks SET threads = $2 WHERE id = $1")
        .bind(id)
        .bind(threads)
        .execute(pg)
        .await?;
    Ok(())
}

/// Messages sent per minute between two Unix times.
pub async fn sends_per_minute(
    pg: &PgPool,
    task_id: i32,
    start: i64,
    end: i64,
) -> Result<Vec<(i64, i64)>> {
    Ok(sqlx::query_as(
        "SELECT (sent_time - sent_time % 60)::bigint AS minute, COUNT(*) FROM recipient_info
          WHERE task_id = $1 AND is_sent = 1 AND sent_time BETWEEN $2 AND $3
          GROUP BY 1 ORDER BY 1",
    )
    .bind(task_id)
    .bind(start)
    .bind(end)
    .fetch_all(pg)
    .await?)
}

/// A delivery attempt of a campaign message.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct DeliveryLog {
    pub postfix_message_id: String,
    pub status: String,
    pub recipient: String,
    pub mail_provider: String,
    pub delay: f64,
    pub delays: String,
    pub dsn: String,
    pub relay: String,
    pub description: String,
    pub log_time: i64,
}

/// `1` delivered, `0` bounced, anything else both.
fn outcome_filter(outcome: i64) -> &'static str {
    match outcome {
        1 => "sm.status = 'sent' AND sm.dsn LIKE '2.%'",
        0 => "sm.status = 'bounced'",
        _ => "TRUE",
    }
}

const CAMPAIGN_DELIVERIES: &str = "mailstat_send_mails sm
    JOIN mailstat_message_ids mi ON mi.postfix_message_id = sm.postfix_message_id
    JOIN recipient_info ri ON ri.message_id = mi.message_id";

/// Filters for the delivery log.
#[derive(Debug, Clone)]
pub struct LogFilter<'a> {
    pub task_id: i32,
    pub outcome: i64,
    /// Recipient domain.
    pub domain: Option<&'a str>,
    pub start: i64,
    pub end: i64,
}

pub async fn delivery_log(
    pg: &PgPool,
    f: &LogFilter<'_>,
    page: i64,
    page_size: i64,
) -> Result<(i64, Vec<DeliveryLog>)> {
    let filter = format!(
        "ri.task_id = $1 AND sm.log_time_millis > $2 * 1000 - 1 AND sm.log_time_millis < $3 * 1000 + 1
         AND ($4::text IS NULL OR sm.recipient LIKE $4) AND {}",
        outcome_filter(f.outcome)
    );
    let domain = f.domain.map(|d| format!("%@{}", like_escape(d)));
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {CAMPAIGN_DELIVERIES} WHERE {filter}"
    ))
    .bind(f.task_id)
    .bind(f.start)
    .bind(f.end)
    .bind(&domain)
    .fetch_one(pg)
    .await?;
    let list = sqlx::query_as(&format!(
        "SELECT sm.postfix_message_id, sm.status, sm.recipient, sm.mail_provider,
                sm.delay::float8 AS delay, sm.delays, sm.dsn, sm.relay, sm.description,
                (sm.log_time_millis / 1000)::bigint AS log_time
           FROM {CAMPAIGN_DELIVERIES} WHERE {filter}
          ORDER BY sm.log_time_millis DESC LIMIT $5 OFFSET $6"
    ))
    .bind(f.task_id)
    .bind(f.start)
    .bind(f.end)
    .bind(&domain)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pg)
    .await?;
    Ok((total, list))
}

/// Deliveries per recipient domain, most first.
pub async fn deliveries_by_domain(
    pg: &PgPool,
    task_id: i32,
    outcome: i64,
) -> Result<Vec<(String, i64)>> {
    Ok(sqlx::query_as(&format!(
        "SELECT split_part(ri.recipient, '@', 2) AS domain, COUNT(*) AS count
           FROM {CAMPAIGN_DELIVERIES}
          WHERE ri.task_id = $1 AND {} AND split_part(ri.recipient, '@', 2) <> ''
          GROUP BY 1 ORDER BY count DESC, domain",
        outcome_filter(outcome)
    ))
    .bind(task_id)
    .fetch_all(pg)
    .await?)
}

/// `(sends, delivered, bounced, opened, clicked)` of all sent mail in a
/// window (0 means unbounded); `task/overview`.
pub async fn sending_summary(
    pg: &PgPool,
    start: i64,
    end: i64,
) -> Result<(i64, i64, i64, i64, i64)> {
    Ok(sqlx::query_as(
        "WITH w AS (SELECT $1::bigint AS s, $2::bigint AS e)
         SELECT COUNT(*),
                COUNT(*) FILTER (WHERE status = 'sent' AND dsn LIKE '2.%'),
                COUNT(*) FILTER (WHERE status = 'bounced'),
                (SELECT COUNT(DISTINCT postfix_message_id) FROM mailstat_opened, w
                  WHERE (w.s <= 0 OR log_time_millis > w.s * 1000 - 1)
                    AND (w.e <= 0 OR log_time_millis < w.e * 1000 + 1)),
                (SELECT COUNT(DISTINCT postfix_message_id) FROM mailstat_clicked, w
                  WHERE (w.s <= 0 OR log_time_millis > w.s * 1000 - 1)
                    AND (w.e <= 0 OR log_time_millis < w.e * 1000 + 1))
           FROM mailstat_send_mails, w
          WHERE (w.s <= 0 OR log_time_millis > w.s * 1000 - 1)
            AND (w.e <= 0 OR log_time_millis < w.e * 1000 + 1)",
    )
    .bind(start)
    .bind(end)
    .fetch_one(pg)
    .await?)
}

// ---- The send queue -------------------------------------------------------

/// The exclusive right to work a send queue, held while this value (and
/// its connection) lives, so two processes never send the same mail.
pub struct SenderLock(sqlx::pool::PoolConnection<Postgres>, &'static str);

impl SenderLock {
    /// `name` identifies the queue (`ferropost:campaigns`, ...).
    pub async fn try_take(pg: &PgPool, name: &'static str) -> Result<Option<Self>> {
        let mut conn = pg.acquire().await?;
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
            .bind(name)
            .fetch_one(&mut *conn)
            .await?;
        Ok(locked.then_some(Self(conn, name)))
    }

    pub async fn release(mut self) -> Result<()> {
        sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
            .bind(self.1)
            .execute(&mut *self.0)
            .await?;
        Ok(())
    }
}

/// Campaigns that should be sending now.
pub async fn due(pg: &PgPool, now: i64) -> Result<Vec<i32>> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM email_tasks
          WHERE task_process IN (0, 1) AND pause = 0 AND start_time <= $1 ORDER BY id",
    )
    .bind(now)
    .fetch_all(pg)
    .await?)
}

/// Marks a campaign as sending.
pub async fn start(pg: &PgPool, id: i32) -> Result<()> {
    sqlx::query("UPDATE email_tasks SET task_process = 1 WHERE id = $1 AND task_process = 0")
        .bind(id)
        .execute(pg)
        .await?;
    Ok(())
}

/// Releases claims a stopped sender left behind; returns how many.
pub async fn release_all_claims(pg: &PgPool) -> Result<u64> {
    Ok(
        sqlx::query("UPDATE recipient_info SET is_sent = 0 WHERE is_sent = 2")
            .execute(pg)
            .await?
            .rows_affected(),
    )
}

pub async fn release(pg: &PgPool, ids: &[i32]) -> Result<()> {
    sqlx::query("UPDATE recipient_info SET is_sent = 0 WHERE id = ANY($1) AND is_sent = 2")
        .bind(ids)
        .execute(pg)
        .await?;
    Ok(())
}

/// Releases a campaign's claims once its sender has stopped.
pub async fn release_task(pg: &PgPool, task_id: i32) -> Result<u64> {
    Ok(
        sqlx::query("UPDATE recipient_info SET is_sent = 0 WHERE task_id = $1 AND is_sent = 2")
            .bind(task_id)
            .execute(pg)
            .await?
            .rows_affected(),
    )
}

/// Claims up to `limit` recipients that may be sent now, in queue order.
pub async fn claim(pg: &PgPool, task_id: i32, limit: i64, now: i64) -> Result<Vec<(i32, String)>> {
    let mut rows: Vec<(i32, String)> = sqlx::query_as(
        "UPDATE recipient_info r SET is_sent = 2
           FROM (SELECT id FROM recipient_info
                  WHERE task_id = $1 AND is_sent = 0 AND sent_time <= $3
                  ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED) c
          WHERE r.id = c.id
         RETURNING r.id, r.recipient",
    )
    .bind(task_id)
    .bind(limit)
    .bind(now)
    .fetch_all(pg)
    .await?;
    rows.sort_unstable();
    Ok(rows)
}

pub async fn mark_sent(pg: &PgPool, id: i32, message_id: &str, now: i64) -> Result<()> {
    sqlx::query(
        "UPDATE recipient_info SET is_sent = $2, sent_time = $3, message_id = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(recipient::SENT as i16)
    .bind(now as i32)
    .bind(message_id)
    .execute(pg)
    .await?;
    Ok(())
}

pub async fn mark_failed(pg: &PgPool, id: i32, now: i64) -> Result<()> {
    sqlx::query("UPDATE recipient_info SET is_sent = $2, sent_time = $3 WHERE id = $1")
        .bind(id)
        .bind(recipient::FAILED as i16)
        .bind(now as i32)
        .execute(pg)
        .await?;
    Ok(())
}

/// Puts a recipient back in the queue, not before `not_before`.
pub async fn postpone(pg: &PgPool, id: i32, not_before: i64) -> Result<()> {
    sqlx::query("UPDATE recipient_info SET is_sent = 0, sent_time = $2 WHERE id = $1")
        .bind(id)
        .bind(not_before as i32)
        .execute(pg)
        .await?;
    Ok(())
}

/// What is left of a campaign's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct Remaining {
    /// Waiting and sendable now.
    pub due: i64,
    /// Earliest time a postponed recipient may be sent.
    pub next_at: Option<i32>,
    pub claimed: i64,
}

impl Remaining {
    pub fn finished(&self) -> bool {
        self.due == 0 && self.next_at.is_none() && self.claimed == 0
    }
}

pub async fn remaining(pg: &PgPool, task_id: i32, now: i64) -> Result<Remaining> {
    Ok(sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE is_sent = 0 AND sent_time <= $2) AS due,
                MIN(sent_time) FILTER (WHERE is_sent = 0 AND sent_time > $2) AS next_at,
                COUNT(*) FILTER (WHERE is_sent = 2) AS claimed
           FROM recipient_info WHERE task_id = $1",
    )
    .bind(task_id)
    .bind(now)
    .fetch_one(pg)
    .await?)
}

/// Marks a campaign completed unless it was paused meanwhile.
pub async fn complete(pg: &PgPool, id: i32, now: i64) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE email_tasks SET task_process = 2, update_time = $2
          WHERE id = $1 AND task_process = 1 AND pause = 0",
    )
    .bind(id)
    .bind(now as i32)
    .execute(pg)
    .await?
    .rows_affected()
        == 1)
}

/// Contact data for personalising: per address, its row in the campaign's
/// group, else its newest row (Go's two lookups per recipient).
pub async fn contacts_for(
    pg: &PgPool,
    emails: &[String],
    group_id: i32,
) -> Result<HashMap<String, (serde_json::Value, i32, i32)>> {
    let rows: Vec<(String, serde_json::Value, i32, i32)> = sqlx::query_as(
        "SELECT DISTINCT ON (email) email, COALESCE(attribs, '{}'::jsonb),
                COALESCE(active, 0), COALESCE(status, 0)
           FROM bm_contacts WHERE email = ANY($1)
          ORDER BY email, (group_id = $2) DESC, create_time DESC, id DESC",
    )
    .bind(emails)
    .bind(group_id)
    .fetch_all(pg)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(email, attribs, active, status)| (email, (attribs, active, status)))
        .collect())
}

/// Refreshes the delivery counts shown in the campaign list from the
/// mail log (Go: `UpdateTaskJoinMailstat`): campaigns sending or paused,
/// never counted, or completed within 36 hours (and up to a week while
/// deliveries are still being logged). Go refreshed completed campaigns
/// forever and stored a deferred count of 0; this counts messages still
/// deferred. Returns how many campaigns were updated.
pub async fn refresh_stats(pg: &PgPool, now: i64) -> Result<u64> {
    Ok(sqlx::query(
        "WITH due AS (
             SELECT id FROM email_tasks
              WHERE task_process IN (1, 3) OR stats_update_time = 0
                 OR (task_process = 2 AND update_time > $1 - 36 * 3600)
                 OR (task_process = 2 AND sends_count < recipient_count * 0.99
                     AND update_time > $1 - 7 * 86400)
         ), counts AS (
             SELECT ri.task_id, COUNT(*) AS sends,
                    COUNT(*) FILTER (WHERE sm.status = 'sent' AND sm.dsn LIKE '2.%') AS delivered,
                    COUNT(*) FILTER (WHERE sm.status = 'bounced') AS bounced,
                    COUNT(*) FILTER (WHERE sm.status = 'deferred') AS deferred
               FROM recipient_info ri
               JOIN mailstat_message_ids mi ON mi.message_id = ri.message_id
               JOIN mailstat_send_mails sm ON sm.postfix_message_id = mi.postfix_message_id
              WHERE ri.task_id IN (SELECT id FROM due) AND ri.message_id <> ''
              GROUP BY ri.task_id
         )
         UPDATE email_tasks t
            SET sends_count = COALESCE(c.sends, 0), delivered_count = COALESCE(c.delivered, 0),
                bounced_count = COALESCE(c.bounced, 0), deferred_count = COALESCE(c.deferred, 0),
                stats_update_time = $1
           FROM due LEFT JOIN counts c ON c.task_id = due.id
          WHERE t.id = due.id",
    )
    .bind(now as i32)
    .execute(pg)
    .await?
    .rows_affected())
}

/// Takes a campaign out of sending (missing template or sender mailbox,
/// repeated failures): the console shows it paused.
pub async fn halt(pg: &PgPool, id: i32) -> Result<()> {
    set_paused(pg, id, true).await
}
