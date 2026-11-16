//! Recording recipients that bounce (Go: `AbnormalRecipientAutoStat`,
//! every 30 minutes): each address that bounced since the last pass counts
//! one more failure, so campaigns stop mailing it after three.

use std::time::Duration;

use anyhow::Result;
use ferropost_store::abnormal::{self, source};
use sqlx::PgPool;
use tokio::sync::watch;

const EVERY: Duration = Duration::from_secs(30 * 60);
/// Console switch; on unless set to something else than `1`.
pub const SWITCH: &str = "abnormal_mail_check_switch";
const LAST_RUN: &str = "abnormal_recipient_last_time";

pub async fn run(pg: PgPool, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(EVERY) => {}
            _ = shutdown.changed() => return,
        }
        if let Err(err) = pass(&pg, chrono::Utc::now().timestamp()).await {
            tracing::warn!(error = %format!("{err:#}"), "bounce statistics pass failed");
        }
    }
}

/// Whether automatic recording is on.
pub async fn enabled(pg: &PgPool) -> Result<bool> {
    Ok(ferropost_store::options::get(pg, SWITCH)
        .await?
        .is_none_or(|v| v.trim().is_empty() || v.trim() == "1"))
}

/// One pass up to `now`; returns how many addresses were counted.
pub async fn pass(pg: &PgPool, now: i64) -> Result<u64> {
    if !enabled(pg).await? {
        return Ok(0);
    }
    let since = ferropost_store::options::get(pg, LAST_RUN)
        .await?
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(now - 30 * 60);
    let bounced = abnormal::bounced_between(pg, since, now).await?;
    let counted = abnormal::record_failures(
        pg,
        &bounced,
        source::BOUNCES,
        "Automatic statistics",
        now as i32,
    )
    .await?;
    ferropost_store::options::set(pg, LAST_RUN, &now.to_string()).await?;
    Ok(counted)
}
