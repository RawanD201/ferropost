//! Sending mail queued through the send API, owned by the `api_mail` job
//! (Go: `ProcessApiMailQueueWithLock`).
//!
//! Go polled once a minute under a lock that did not exclude anyone, with
//! a 15-second deadline that could stop a run after sending but before
//! recording, so mail went out twice; its caches were shared maps written
//! from several goroutines. Here a single sender (advisory lock) works the
//! queue continuously, woken as soon as the API queues mail, and every
//! message is recorded as it is submitted.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use ferropost_domain::campaigns::{prepare_content, unsubscribe_page_url};
use ferropost_domain::send_api::campaign_id;
use ferropost_domain::templates::EmailTemplate;
use ferropost_sender::smtp::{Mailer, Outgoing, SmtpConfig, decode_mailbox_password};
use ferropost_sender::template::{RenderData, Subscriber};
use ferropost_sender::tokens::{TokenKeys, UnsubscribeClaims, issue_unsubscribe};
use ferropost_sender::tracking::Tracker;
use ferropost_store::campaigns::SenderLock;
use ferropost_store::send_api::{self as store, ApiKey, Queued};
use rand::SeedableRng;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::campaigns::compose::{ContactData, apply_tracking, list_unsubscribe, personalise};
use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "api_mail";

const BATCH: i64 = 200;
/// Concurrent submissions (Go ran 20 workers).
const CONCURRENCY: usize = 20;
/// Connections per sender mailbox (Go opened 5).
const CONNECTIONS: u32 = 5;
const IDLE: Duration = Duration::from_secs(2);

pub fn spawn(state: &AppState, shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("API mail sender started");
    vec![tokio::spawn(run(state.clone(), shutdown))]
}

async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let pg = state.store.pg.clone();
    let lock = loop {
        match SenderLock::try_take(&pg, "ferropost:api_mail").await {
            Ok(Some(lock)) => break lock,
            Ok(None) => tracing::info!("another process is sending API mail; waiting"),
            Err(err) => tracing::warn!(error = %format!("{err:#}"), "API mail sender lock failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            _ = shutdown.changed() => return,
        }
    };
    match store::release_claims(&pg).await {
        Ok(0) => {}
        Ok(released) => tracing::info!(
            released,
            "API mail claimed before the restart is queued again"
        ),
        Err(err) => tracing::warn!(error = %format!("{err:#}"), "releasing API mail claims failed"),
    }
    loop {
        if *shutdown.borrow() {
            break;
        }
        match store::claim(&pg, BATCH).await {
            Ok(batch) if !batch.is_empty() => {
                if let Err(err) = send_batch(&state, batch).await {
                    tracing::warn!(error = %format!("{err:#}"), "API mail batch failed");
                    let _ = store::release_claims(&pg).await;
                    tokio::time::sleep(IDLE).await;
                }
                continue;
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %format!("{err:#}"), "claiming API mail failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(IDLE) => {}
            () = state.api_mail_queued.notified() => {}
            _ = shutdown.changed() => break,
        }
    }
    if let Err(err) = lock.release().await {
        tracing::debug!(error = %format!("{err:#}"), "API mail sender unlock failed");
    }
}

/// What a batch needs per API.
struct ApiContext {
    api: ApiKey,
    template: Option<EmailTemplate>,
    group: Option<i32>,
    contacts: HashMap<String, ContactData>,
}

async fn send_batch(state: &AppState, batch: Vec<Queued>) -> Result<()> {
    let pg = &state.store.pg;
    let mut apis: HashMap<i32, Option<ApiContext>> = HashMap::new();
    for row in &batch {
        if apis.contains_key(&row.api_id) {
            continue;
        }
        let ctx = match store::get(pg, row.api_id).await? {
            Some(api) => {
                let template = ferropost_store::templates::get(pg, api.template_id).await?;
                let group = store::existing_recipient_group(pg, &api).await?;
                let emails: Vec<String> = batch
                    .iter()
                    .filter(|r| r.api_id == api.id)
                    .map(|r| r.recipient.clone())
                    .collect();
                let contacts =
                    ferropost_store::campaigns::contacts_for(pg, &emails, group.unwrap_or(0))
                        .await?;
                Some(ApiContext {
                    api,
                    template,
                    group,
                    contacts,
                })
            }
            None => None,
        };
        apis.insert(row.api_id, ctx);
    }

    let mut mailers: HashMap<String, Option<Mailer>> = HashMap::new();
    for row in &batch {
        if mailers.contains_key(&row.addresser) {
            continue;
        }
        let mailer = match ferropost_store::mailboxes::encoded_password(pg, &row.addresser).await? {
            Some(encoded) => Some(Mailer::with_connections(
                &SmtpConfig {
                    host: state.config.smtp_host.clone(),
                    port: state.config.smtp_port,
                    username: row.addresser.clone(),
                    password: decode_mailbox_password(&encoded)?,
                },
                CONNECTIONS,
            )?),
            None => None,
        };
        mailers.insert(row.addresser.clone(), mailer);
    }

    let keys = state.token_keys().await?;
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut in_flight = JoinSet::new();
    for row in batch {
        let now = chrono::Utc::now().timestamp();
        let failure = match (apis.get(&row.api_id), mailers.get(&row.addresser)) {
            (None | Some(None), _) => Some("Failed to get API template".to_owned()),
            (Some(Some(ApiContext { template: None, .. })), _) => {
                Some("Failed to get email template".to_owned())
            }
            (_, None | Some(None)) => Some(format!(
                "Failed to create sender: password not found for {}",
                row.addresser
            )),
            _ => None,
        };
        if let Some(error) = failure {
            store::settle(pg, row.id, Some(&error), now).await?;
            continue;
        }
        let (Some(Some(ctx)), Some(Some(mailer))) =
            (apis.get(&row.api_id), mailers.get(&row.addresser))
        else {
            continue;
        };
        let base_url = crate::base_url::for_sender(state, &row.addresser).await;
        let message = compose(
            ctx,
            &row,
            &base_url,
            &keys,
            &state.tracking_key,
            now,
            &mut rng,
        );
        while in_flight.len() >= CONCURRENCY {
            in_flight.join_next().await;
        }
        let (mailer, pg) = (mailer.clone(), pg.clone());
        in_flight.spawn(async move {
            let sent = mailer.send(&message).await;
            let error = sent
                .as_ref()
                .err()
                .map(|e| format!("Failed to send email: {e:#}"));
            let at = chrono::Utc::now().timestamp();
            if let Err(err) = store::settle(&pg, row.id, error.as_deref(), at).await {
                tracing::warn!(id = row.id, error = %format!("{err:#}"), "recording API mail failed");
            }
        });
    }
    while in_flight.join_next().await.is_some() {}
    Ok(())
}

/// One API message (Go: `processMailContentAndSubject`, `sendApiMail`).
/// Unlike Go it renders for recipients who are not contacts too (Go sent
/// the raw template), takes the unsubscribe group from the API's own group
/// rather than any group the address is in, and adds RFC 8058 headers.
fn compose(
    ctx: &ApiContext,
    row: &Queued,
    base_url: &str,
    keys: &TokenKeys,
    tracking_key: &[u8; 32],
    now: i64,
    rng: &mut impl rand::Rng,
) -> Outgoing {
    let api = &ctx.api;
    let template = ctx.template.as_ref().map_or("", |t| t.content.as_str());
    let content = prepare_content(template, api.unsubscribe == 1);
    let group = ctx.group.unwrap_or(0);
    let jwt = (api.unsubscribe == 1).then(|| {
        issue_unsubscribe(
            keys,
            UnsubscribeClaims {
                email: row.recipient.clone(),
                template_id: api.template_id.into(),
                // Go put the API's ID here; unsubscribe records keep it.
                task_id: api.id.into(),
                group_id: group.into(),
            },
            now,
        )
    });
    let subscriber = match ctx.contacts.get(&row.recipient) {
        Some((attribs, active, status)) => {
            Subscriber::from_contact(&row.recipient, attribs, *active, *status)
        }
        None => Subscriber {
            email: row.recipient.clone(),
            ..Subscriber::default()
        },
    };
    let data = RenderData {
        subscriber: Some(subscriber),
        unsubscribe_url: jwt
            .as_deref()
            .map(|jwt| unsubscribe_page_url(base_url, jwt, &row.recipient, group))
            .unwrap_or_default(),
        api: row
            .attribs
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default(),
        ..RenderData::default()
    };
    let html = personalise(&content, &data, rng);
    let subject = personalise(&api.subject, &data, rng);
    let message_id = format!("<{}>", row.message_id);
    let tracker = Tracker::new(
        base_url,
        campaign_id(api.id),
        &row.recipient,
        &message_id,
        tracking_key,
    );
    let html = apply_tracking(
        &tracker,
        html,
        base_url,
        api.track_click == 1,
        api.track_open == 1,
    );
    Outgoing {
        from_email: row.addresser.clone(),
        from_name: Some(api.full_name.clone()),
        to: vec![row.recipient.clone()],
        subject,
        html,
        headers: match &jwt {
            Some(jwt) if group > 0 => list_unsubscribe(base_url, jwt),
            _ => Vec::new(),
        },
        message_id,
    }
}
