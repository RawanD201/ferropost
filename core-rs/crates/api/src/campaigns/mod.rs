//! Campaign sending, owned by the `campaigns` job (Go:
//! `ProcessEmailTasks`, the task executor and `UpdateTaskJoinMailstat`).
//!
//! The queue is `recipient_info` (see `ferropost_store::campaigns`). A
//! supervisor starts one worker per due campaign; a worker claims small
//! batches, re-reading the campaign before each, so pausing, deleting or
//! changing the speed in the console takes effect within a batch, from any
//! process. Every submission records its outcome itself, and a worker that
//! stops waits for those before handing unsent claims back.
//!
//! Differences from Go: a restart resumes exactly where sending stopped;
//! recipients held back by warmup limits are retried when allowed (Go left
//! them claimed for good); the circuit breaker pauses the campaign in the
//! database, so the console shows it; a missing template or sender mailbox
//! pauses the campaign instead of failing every message; warmup limits use
//! the recipient's provider group (Go passed the group name where an
//! address was expected, so every recipient counted as "other"); and one
//! connection pool per campaign replaces a new SMTP session per message.

pub mod compose;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use ferropost_domain::campaigns::{CIRCUIT_BREAKER, Task, prepare_content, status};
use ferropost_domain::maillog::provider_group;
use ferropost_sender::smtp::{Mailer, SmtpConfig, decode_mailbox_password};
use ferropost_store::PgPool;
use ferropost_store::campaigns as store;
use ferropost_store::warmup::Admission;
use rand::SeedableRng;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::state::AppState;
use compose::Composer;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "campaigns";

const POLL: Duration = Duration::from_secs(5);
const STATS_EVERY: Duration = Duration::from_secs(60);

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Starts the sender and the stats refresh when this process owns
/// campaigns.
pub fn spawn(state: &AppState, shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("campaign sender started");
    vec![
        tokio::spawn(supervise(state.clone(), shutdown.clone())),
        tokio::spawn(refresh_stats(state.store.pg.clone(), shutdown)),
    ]
}

async fn supervise(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let pg = state.store.pg.clone();
    // A single sender across processes; the lock lives with the connection.
    let lock = loop {
        match store::SenderLock::try_take(&pg, "ferropost:campaigns").await {
            Ok(Some(lock)) => break lock,
            Ok(None) => tracing::info!("another process is sending campaigns; waiting"),
            Err(err) => tracing::warn!(error = %format!("{err:#}"), "campaign sender lock failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = shutdown.changed() => return,
        }
    };
    match store::release_all_claims(&pg).await {
        Ok(0) => {}
        Ok(released) => tracing::info!(
            released,
            "recipients claimed before the restart are queued again"
        ),
        Err(err) => tracing::warn!(error = %format!("{err:#}"), "releasing old claims failed"),
    }

    let running = Arc::new(Mutex::new(HashSet::new()));
    let mut workers = JoinSet::new();
    loop {
        while workers.try_join_next().is_some() {}
        match store::due(&pg, now()).await {
            Ok(ids) => {
                for id in ids {
                    if running.lock().expect("running set").insert(id) {
                        workers.spawn(worker(state.clone(), id, shutdown.clone(), running.clone()));
                    }
                }
            }
            Err(err) => tracing::warn!(error = %format!("{err:#}"), "listing due campaigns failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(POLL) => {}
            _ = shutdown.changed() => break,
        }
    }
    while workers.join_next().await.is_some() {}
    if let Err(err) = lock.release().await {
        tracing::debug!(error = %format!("{err:#}"), "campaign sender unlock failed");
    }
}

async fn worker(
    state: AppState,
    task_id: i32,
    shutdown: watch::Receiver<bool>,
    running: Arc<Mutex<HashSet<i32>>>,
) {
    let mut in_flight = JoinSet::new();
    let result = run(&state, task_id, &mut in_flight, &shutdown).await;
    // Submissions record their own outcome; wait for them before handing
    // unsent claims back, so nothing is sent twice.
    while in_flight.join_next().await.is_some() {}
    if let Err(err) = &result {
        tracing::warn!(task_id, error = %format!("{err:#}"), "campaign sending stopped");
    }
    if let Err(err) = store::release_task(&state.store.pg, task_id).await {
        tracing::warn!(task_id, error = %format!("{err:#}"), "releasing claims failed");
    }
    running.lock().expect("running set").remove(&task_id);
}

/// Spaces submissions to Go's rate of 20 per second per thread.
#[derive(Default)]
struct Pace {
    interval: Duration,
    next: Option<Instant>,
}

impl Pace {
    fn set_rate(&mut self, per_second: u32) {
        self.interval = Duration::from_secs(1) / per_second.max(1);
    }

    async fn wait(&mut self) {
        let now = Instant::now();
        let at = self.next.unwrap_or(now).max(now);
        if at > now {
            tokio::time::sleep_until(at).await;
        }
        self.next = Some(at + self.interval);
    }
}

/// Consecutive failures after a submission finished.
fn tally(failures: u32, joined: Result<bool, JoinError>) -> u32 {
    match joined {
        Ok(true) => 0,
        _ => failures + 1,
    }
}

/// A pooled connection for the campaign's sender, logging in as its
/// mailbox; `None` when the mailbox does not exist.
async fn mailer_for(state: &AppState, task: &Task) -> Result<Option<Mailer>> {
    let pg = &state.store.pg;
    let Some(encoded) = ferropost_store::mailboxes::encoded_password(pg, &task.addresser).await?
    else {
        return Ok(None);
    };
    let config = SmtpConfig {
        host: state.config.smtp_host.clone(),
        port: state.config.smtp_port,
        username: task.addresser.clone(),
        password: decode_mailbox_password(&encoded)?,
    };
    Ok(Some(Mailer::with_connections(
        &config,
        task.concurrency() as u32,
    )?))
}

async fn halt(pg: &PgPool, task_id: i32, why: &str) -> Result<()> {
    tracing::warn!(task_id, "campaign paused: {why}");
    store::halt(pg, task_id).await
}

async fn run(
    state: &AppState,
    task_id: i32,
    in_flight: &mut JoinSet<bool>,
    shutdown: &watch::Receiver<bool>,
) -> Result<()> {
    let pg = &state.store.pg;
    let mut mailer: Option<(String, usize, Mailer)> = None;
    let mut pace = Pace::default();
    let mut failures = 0u32;
    let mut rng = rand::rngs::StdRng::from_entropy();
    // Go read the IP once per executor as well.
    let warmup_ip = if store::uses_warmup(pg, task_id).await? {
        Some(
            crate::edge::server_public_ip(state)
                .await
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
        )
    } else {
        None
    };

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let now = now();
        let Some(task) = store::get(pg, task_id).await? else {
            return Ok(()); // deleted
        };
        let sendable =
            task.task_process == status::NOT_STARTED || task.task_process == status::RUNNING;
        if task.pause == 1 || !sendable || i64::from(task.start_time) > now {
            return Ok(());
        }
        if task.task_process == status::NOT_STARTED {
            store::start(pg, task_id).await?;
        }
        let Some(template) = ferropost_store::templates::get(pg, task.template_id).await? else {
            return halt(pg, task_id, "its template no longer exists").await;
        };
        let concurrency = task.concurrency();
        let current = match mailer.take() {
            Some((sender, size, m)) if sender == task.addresser && size == concurrency => m,
            _ => match mailer_for(state, &task).await? {
                Some(m) => m,
                None => return halt(pg, task_id, "the sender has no mailbox").await,
            },
        };
        mailer = Some((task.addresser.clone(), concurrency, current.clone()));
        pace.set_rate(concurrency as u32 * 20);

        let limit = (concurrency * 4).clamp(10, 200) as i64;
        let batch = store::claim(pg, task_id, limit, now).await?;
        if batch.is_empty() {
            while let Some(joined) = in_flight.join_next().await {
                failures = tally(failures, joined);
            }
            if failures >= CIRCUIT_BREAKER {
                return halt(pg, task_id, "too many submissions failed in a row").await;
            }
            let left = store::remaining(pg, task_id, now).await?;
            if left.finished() {
                if store::complete(pg, task_id, now).await? {
                    tracing::info!(task_id, "campaign completed");
                }
                return Ok(());
            }
            // Only recipients postponed by warmup limits are left.
            let wait = left
                .next_at
                .map_or(1, |at| (i64::from(at) - now).clamp(1, 30));
            let mut stop = shutdown.clone();
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(wait as u64)) => {}
                _ = stop.changed() => return Ok(()),
            }
            continue;
        }

        let content = prepare_content(&template.content, task.unsubscribe == 1);
        let base_url = crate::base_url::for_sender(state, &task.addresser).await;
        let keys = state.token_keys().await?;
        let composer = Composer {
            task: &task,
            content: &content,
            base_url: &base_url,
            keys: &keys,
            tracking_key: &state.tracking_key,
            now,
        };
        let emails: Vec<String> = batch.iter().map(|(_, email)| email.clone()).collect();
        let contacts = store::contacts_for(pg, &emails, task.group_id).await?;

        for (n, (id, email)) in batch.into_iter().enumerate() {
            if *shutdown.borrow() {
                return Ok(());
            }
            if let Some(ip) = &warmup_ip {
                let admitted = ferropost_store::warmup::admit(
                    pg,
                    &state.store.redis,
                    ip,
                    provider_group(&email),
                    now,
                )
                .await;
                let retry_in = match admitted {
                    Ok(Admission::Allow) => None,
                    // Spread the retries like Go did.
                    Ok(Admission::Wait(secs)) => Some(secs * 2 * (1 + n as i64 % 10)),
                    Err(err) => {
                        tracing::warn!(task_id, error = %format!("{err:#}"), "warmup check failed");
                        Some(300)
                    }
                };
                if let Some(secs) = retry_in {
                    store::postpone(pg, id, now + secs).await?;
                    continue;
                }
            }
            while in_flight.len() >= concurrency {
                if let Some(joined) = in_flight.join_next().await {
                    failures = tally(failures, joined);
                }
            }
            if failures >= CIRCUIT_BREAKER {
                return halt(pg, task_id, "too many submissions failed in a row").await;
            }
            pace.wait().await;

            let message = composer.compose(&email, contacts.get(&email), &mut rng);
            let (mailer, pg) = (current.clone(), pg.clone());
            in_flight.spawn(async move {
                let sent = mailer.send(&message).await;
                let at = chrono::Utc::now().timestamp();
                let recorded = match &sent {
                    Ok(()) => {
                        let message_id = message.message_id.trim_matches(['<', '>']);
                        store::mark_sent(&pg, id, message_id, at).await
                    }
                    Err(_) => store::mark_failed(&pg, id, at).await,
                };
                if let Err(err) = recorded {
                    tracing::warn!(id, error = %format!("{err:#}"), "recording a send failed");
                }
                if let Err(err) = &sent {
                    tracing::debug!(recipient = %email, error = %format!("{err:#}"), "submission failed");
                }
                sent.is_ok()
            });
            while let Some(joined) = in_flight.try_join_next() {
                failures = tally(failures, joined);
            }
        }
    }
}

async fn refresh_stats(pg: PgPool, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(STATS_EVERY) => {}
            _ = shutdown.changed() => return,
        }
        match store::refresh_stats(&pg, now()).await {
            Ok(updated) => tracing::debug!(updated, "campaign stats refreshed"),
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "campaign stats refresh failed")
            }
        }
    }
}
