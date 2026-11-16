//! Background jobs moved out of the Go core.
//!
//! A job runs only when listed in `FERROPOST_RUST_JOBS`; Go reads the same
//! variable and skips it, so each job has exactly one owner.

pub mod maillog;
pub mod warmup;

use std::time::Duration;

use ferropost_common::Config;
use ferropost_store::Store;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Job names shared with Go's `timers.OwnedByRust`.
pub const MAILLOG: &str = "maillog";
pub const WARMUP: &str = "warmup";

const AGGREGATE_EVERY: Duration = Duration::from_secs(60);

/// Starts the jobs this process owns. They stop when `shutdown` flips.
pub fn spawn(
    config: &Config,
    store: &Store,
    shutdown: watch::Receiver<bool>,
) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::new();
    if config.runs_job(MAILLOG) {
        let tailer = maillog::Tailer::new(
            config.maillog_path.clone(),
            config.postfix_main_cf.clone(),
            store.pg.clone(),
        );
        tasks.push(tokio::spawn(tailer.run(shutdown.clone())));
        tasks.push(tokio::spawn(aggregate(store.pg.clone(), shutdown.clone())));
        tracing::info!(path = %config.maillog_path.display(), "maillog jobs started");
    }
    if config.runs_job(WARMUP) {
        tasks.push(tokio::spawn(warmup::run(store.pg.clone(), shutdown)));
        tracing::info!("warmup job started");
    }
    tasks
}

/// Copies deliveries between your own domains into the sending stats every
/// minute (Go's `AggregateMaillogsTask`).
async fn aggregate(pg: sqlx::PgPool, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(AGGREGATE_EVERY) => {}
            _ = shutdown.changed() => return,
        }
        match ferropost_store::maillog::aggregate_local(&pg, chrono::Utc::now().timestamp_millis())
            .await
        {
            Ok(0) => {}
            Ok(added) => tracing::debug!(added, "local deliveries aggregated"),
            Err(err) => tracing::warn!(error = %format!("{err:#}"), "maillog aggregation failed"),
        }
    }
}
