//! Hourly sender IP warmup pass (Go: `SenderIpWarmup().PeriodicTask` and
//! `SenderIpMailProvider().PeriodicTaskForProviders`): re-scores each IP in
//! warmup and each of its provider groups, then moves the warmup period
//! and progress along.

use std::time::Duration;

use anyhow::Result;
use ferropost_domain::warmup::{
    self, IP_EVALUATION_INTERVAL, IpWarmup, PROVIDER_EVALUATION_INTERVAL, PROVIDER_GROUPS,
};
use ferropost_store::warmup as store;
use sqlx::PgPool;
use tokio::sync::watch;

const EVERY: Duration = Duration::from_secs(3600);

/// Runs a pass now and then every hour (Go waited an hour for the first).
/// The scores only change once their evaluation interval has passed, so an
/// extra pass at start-up is harmless.
pub async fn run(pg: PgPool, mut shutdown: watch::Receiver<bool>) {
    loop {
        if let Err(err) = pass(&pg, chrono::Utc::now().timestamp()).await {
            tracing::warn!(error = %format!("{err:#}"), "warmup pass failed");
        }
        tokio::select! {
            () = tokio::time::sleep(EVERY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// One pass over every IP in warmup. Skipped while another process holds
/// the lock.
pub async fn pass(pg: &PgPool, now: i64) -> Result<()> {
    let mut lock = pg.acquire().await?;
    let locked: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext('ferropost:warmup-pass'))")
            .fetch_one(&mut *lock)
            .await?;
    if !locked {
        tracing::debug!("warmup pass already running elsewhere");
        return Ok(());
    }
    let result = run_pass(pg, now).await;
    sqlx::query("SELECT pg_advisory_unlock(hashtext('ferropost:warmup-pass'))")
        .execute(&mut *lock)
        .await?;
    result
}

async fn run_pass(pg: &PgPool, now: i64) -> Result<()> {
    let ips = store::ips(pg).await?;
    if ips.is_empty() {
        return Ok(());
    }
    let domains = store::active_domains(pg).await?;
    for rec in &ips {
        if let Err(err) = advance_ip(pg, rec, &domains, now).await {
            tracing::warn!(ip = %rec.sender_ip, error = %format!("{err:#}"), "warmup update failed");
        }
    }
    for rec in store::ips(pg).await? {
        for group in PROVIDER_GROUPS {
            if let Err(err) = score_provider(pg, &rec, group, &domains, now).await {
                tracing::warn!(ip = %rec.sender_ip, group, error = %format!("{err:#}"),
                    "provider score update failed");
            }
        }
    }
    Ok(())
}

async fn reload(pg: &PgPool, id: i32) -> Result<IpWarmup> {
    store::ip_by_id(pg, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("warmup row {id} disappeared"))
}

async fn advance_ip(pg: &PgPool, rec: &IpWarmup, domains: &[String], now: i64) -> Result<()> {
    if now > i64::from(rec.last_evaluate_time) + IP_EVALUATION_INTERVAL {
        let since = warmup::ip_window_start(rec, now * 1000);
        let stats = store::send_stats(pg, domains, since, None).await?;
        let eval = warmup::evaluate_ip(rec, &stats, !domains.is_empty());
        store::save_ip_score(pg, rec.id, eval.score, eval.finished, now).await?;
        tracing::debug!(ip = %rec.sender_ip, score = eval.score, total = stats.total,
            finished = eval.finished, "sender IP scored");
    }
    // Each step sees the previous one's result, as in Go.
    let current = reload(pg, rec.id).await?;
    if let Some(period) = warmup::next_period(&current) {
        store::set_period(pg, &current, period, now).await?;
    }
    let after_period = reload(pg, rec.id).await?;
    if let Some(progress) = warmup::next_progress(&after_period, now) {
        store::set_progress(pg, rec.id, progress, now).await?;
    }
    if warmup::rewarmup_check_due(&current, now) {
        let latest = reload(pg, rec.id).await?;
        if warmup::needs_rewarmup(&latest) {
            store::restart(pg, &latest, now).await?;
            tracing::info!(ip = %rec.sender_ip, score = latest.score, "sender IP warmup restarted");
        }
    }
    Ok(())
}

async fn score_provider(
    pg: &PgPool,
    ip: &IpWarmup,
    group: &str,
    domains: &[String],
    now: i64,
) -> Result<()> {
    let rec = store::provider_or_init(pg, &ip.sender_ip, group, now).await?;
    if now <= i64::from(rec.last_evaluate_time) + PROVIDER_EVALUATION_INTERVAL {
        return Ok(());
    }
    let since = warmup::provider_window_start(&rec, now * 1000);
    let stats = store::send_stats(pg, domains, since, Some(group)).await?;
    let score = warmup::evaluate_provider(&rec, &stats, !domains.is_empty(), ip.progress);
    store::save_provider_score(pg, rec.id, score, now).await?;
    tracing::debug!(ip = %ip.sender_ip, group, score, total = stats.total, "provider scored");
    Ok(())
}
