//! Sender IP warmup state (`bm_sender_ip_warmup`,
//! `bm_sender_ip_mail_provider`, `bm_campaign_warmup`) and the delivery
//! data it is scored on.
//!
//! The tables have no unique constraint on the IP (and provider), so rows
//! are created under an advisory lock and read oldest first; the schema
//! gains the constraint once it moves to migrations.

use anyhow::Result;
use ferropost_domain::warmup::{
    self, DAY, DEFAULT_PERIOD_DAYS, INITIAL_IP_SCORE, INITIAL_PROVIDER_SCORE, IpWarmup,
    ProviderWarmup, SendStats,
};
use sqlx::PgPool;

const IP_COLUMNS: &str = "id, sender_ip, period, score, last_evaluate_time, progress, re_warmups,
    begin_time, end_time, COALESCE(create_time, 0) AS create_time,
    COALESCE(update_time, 0) AS update_time";
const PROVIDER_COLUMNS: &str =
    "id, sender_ip, mail_provider, score, last_evaluate_time, create_time, update_time";

/// Every IP in warmup, oldest first.
pub async fn ips(pg: &PgPool) -> Result<Vec<IpWarmup>> {
    Ok(sqlx::query_as(&format!(
        "SELECT DISTINCT ON (sender_ip) {IP_COLUMNS} FROM bm_sender_ip_warmup
          ORDER BY sender_ip, id"
    ))
    .fetch_all(pg)
    .await?)
}

pub async fn ip_by_id(pg: &PgPool, id: i32) -> Result<Option<IpWarmup>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {IP_COLUMNS} FROM bm_sender_ip_warmup WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pg)
    .await?)
}

/// The IP's warmup, started now if it has none (Go:
/// `InitializeOrGetWarmupStatus`).
pub async fn ip_or_start(pg: &PgPool, ip: &str, now: i64) -> Result<IpWarmup> {
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('ferropost:warmup:' || $1))")
        .bind(ip)
        .execute(&mut *tx)
        .await?;
    let select = format!(
        "SELECT {IP_COLUMNS} FROM bm_sender_ip_warmup WHERE sender_ip = $1 ORDER BY id LIMIT 1"
    );
    if let Some(rec) = sqlx::query_as(&select)
        .bind(ip)
        .fetch_optional(&mut *tx)
        .await?
    {
        return Ok(rec);
    }
    let rec = sqlx::query_as(&format!(
        "INSERT INTO bm_sender_ip_warmup (sender_ip, period, score, last_evaluate_time, progress,
             re_warmups, begin_time, end_time, create_time, update_time)
         VALUES ($1, $2, $3, $4, 0, 0, $4, $5, $4, $4) RETURNING {IP_COLUMNS}"
    ))
    .bind(ip)
    .bind(DEFAULT_PERIOD_DAYS)
    .bind(INITIAL_IP_SCORE)
    .bind(now as i32)
    .bind((now + i64::from(DEFAULT_PERIOD_DAYS) * DAY) as i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(%ip, "warmup started for sender IP");
    Ok(rec)
}

/// The provider group's score row, created at the initial score if missing
/// (Go: `InitializeOrGetProviderStatus`).
pub async fn provider_or_init(
    pg: &PgPool,
    ip: &str,
    provider: &str,
    now: i64,
) -> Result<ProviderWarmup> {
    let mut tx = pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('ferropost:warmup:' || $1 || ':' || $2))")
        .bind(ip)
        .bind(provider)
        .execute(&mut *tx)
        .await?;
    let select = format!(
        "SELECT {PROVIDER_COLUMNS} FROM bm_sender_ip_mail_provider
          WHERE sender_ip = $1 AND mail_provider = $2 ORDER BY id LIMIT 1"
    );
    if let Some(rec) = sqlx::query_as(&select)
        .bind(ip)
        .bind(provider)
        .fetch_optional(&mut *tx)
        .await?
    {
        return Ok(rec);
    }
    let rec = sqlx::query_as(&format!(
        "INSERT INTO bm_sender_ip_mail_provider
             (sender_ip, mail_provider, score, last_evaluate_time, create_time, update_time)
         VALUES ($1, $2, $3, $4, $4, $4) RETURNING {PROVIDER_COLUMNS}"
    ))
    .bind(ip)
    .bind(provider)
    .bind(INITIAL_PROVIDER_SCORE)
    .bind(now as i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rec)
}

/// Active sending domains, whose mail the scores are based on (Go scores
/// every active domain's mail against each IP).
pub async fn active_domains(pg: &PgPool) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT domain FROM domain WHERE active = 1 ORDER BY domain")
            .fetch_all(pg)
            .await?,
    )
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Results of mail sent from `domains` since `since_ms`, optionally only to
/// one provider group, in one query (Go loaded every message ID and sent
/// them back as an `IN` list, up to 70,000 of them).
pub async fn send_stats(
    pg: &PgPool,
    domains: &[String],
    since_ms: i64,
    provider: Option<&str>,
) -> Result<SendStats> {
    let patterns: Vec<String> = domains
        .iter()
        .map(|d| format!("%@{}", like_escape(d)))
        .collect();
    Ok(sqlx::query_as(
        "WITH pm AS (
             SELECT DISTINCT s.postfix_message_id FROM mailstat_senders s
              WHERE s.log_time_millis >= $2 AND s.sender LIKE ANY($1)
                AND ($3::text IS NULL OR EXISTS (
                    SELECT 1 FROM mailstat_send_mails p
                     WHERE p.postfix_message_id = s.postfix_message_id AND p.mail_provider = $3))
         ), sm AS (
             SELECT lower(status) AS status, left(dsn, 1) AS class FROM mailstat_send_mails
              WHERE postfix_message_id IN (SELECT postfix_message_id FROM pm)
                AND log_time_millis >= $2 AND ($3::text IS NULL OR mail_provider = $3)
         )
         SELECT (SELECT COUNT(*) FROM pm) AS messages,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'sent') AS sent,
                COUNT(*) FILTER (WHERE status = 'bounced' AND class = '5') AS hard_bounces,
                COUNT(*) FILTER (WHERE status = 'bounced' AND class IS DISTINCT FROM '5')
                    AS soft_bounces,
                COUNT(*) FILTER (WHERE status = 'deferred') AS deferred,
                (SELECT COUNT(DISTINCT postfix_message_id) FROM mailstat_opened
                  WHERE postfix_message_id IN (SELECT postfix_message_id FROM pm)
                    AND log_time_millis >= $2) AS opened,
                (SELECT COUNT(DISTINCT postfix_message_id) FROM mailstat_clicked
                  WHERE postfix_message_id IN (SELECT postfix_message_id FROM pm)
                    AND log_time_millis >= $2) AS clicked,
                (SELECT COUNT(DISTINCT postfix_message_id) FROM mailstat_complaints
                  WHERE postfix_message_id IN (SELECT postfix_message_id FROM pm)
                    AND log_time_millis >= $2) AS complaints
           FROM sm",
    )
    .bind(&patterns)
    .bind(since_ms)
    .bind(provider)
    .fetch_one(pg)
    .await?)
}

/// Stores an IP evaluation; a finished warmup gets period 0 and 100%.
pub async fn save_ip_score(
    pg: &PgPool,
    id: i32,
    score: i32,
    finished: bool,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE bm_sender_ip_warmup
            SET score = $2, last_evaluate_time = $3, update_time = $3,
                period = CASE WHEN $4 THEN 0 ELSE period END,
                end_time = CASE WHEN $4 THEN $3 ELSE end_time END,
                progress = CASE WHEN $4 THEN 100 ELSE progress END
          WHERE id = $1",
    )
    .bind(id)
    .bind(score)
    .bind(now as i32)
    .bind(finished)
    .execute(pg)
    .await?;
    Ok(())
}

pub async fn set_period(pg: &PgPool, rec: &IpWarmup, period: i32, now: i64) -> Result<()> {
    sqlx::query(
        "UPDATE bm_sender_ip_warmup SET period = $2, end_time = $3, update_time = $4 WHERE id = $1",
    )
    .bind(rec.id)
    .bind(period)
    .bind((i64::from(rec.begin_time) + i64::from(period) * DAY) as i32)
    .bind(now as i32)
    .execute(pg)
    .await?;
    Ok(())
}

pub async fn set_progress(pg: &PgPool, id: i32, progress: i32, now: i64) -> Result<()> {
    sqlx::query("UPDATE bm_sender_ip_warmup SET progress = $2, update_time = $3 WHERE id = $1")
        .bind(id)
        .bind(progress)
        .bind(now as i32)
        .execute(pg)
        .await?;
    Ok(())
}

/// Starts the warmup over (Go: `CheckAndTriggerReWarmup`).
pub async fn restart(pg: &PgPool, rec: &IpWarmup, now: i64) -> Result<()> {
    let period = warmup::REWARMUP_PERIOD_DAYS;
    sqlx::query(
        "UPDATE bm_sender_ip_warmup
            SET progress = 0, re_warmups = re_warmups + 1, period = $2, begin_time = $3,
                end_time = $4, last_evaluate_time = $3, update_time = $3
          WHERE id = $1",
    )
    .bind(rec.id)
    .bind(period)
    .bind(now as i32)
    .bind((now + i64::from(period) * DAY) as i32)
    .execute(pg)
    .await?;
    Ok(())
}

pub async fn save_provider_score(pg: &PgPool, id: i32, score: i32, now: i64) -> Result<()> {
    sqlx::query(
        "UPDATE bm_sender_ip_mail_provider
            SET score = $2, last_evaluate_time = $3, update_time = $3
          WHERE id = $1",
    )
    .bind(id)
    .bind(score)
    .bind(now as i32)
    .execute(pg)
    .await?;
    Ok(())
}

/// `(daily, hourly)` sending limits for one IP and provider group (Go:
/// `GetAdjustedSendingLimitsForProvider`). Starts the IP's warmup and the
/// group's score if they do not exist yet, as Go did.
pub async fn limits(pg: &PgPool, ip: &str, provider: &str, now: i64) -> Result<(i64, i64)> {
    let rec = ip_or_start(pg, ip, now).await?;
    let base = warmup::base_limits(i64::from(rec.begin_time), now);
    let group = provider_or_init(pg, ip, provider, now).await?;
    Ok(warmup::adjusted_limits(base, group.score))
}
