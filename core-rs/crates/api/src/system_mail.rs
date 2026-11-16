//! Mail the platform sends itself: subscription confirmations, welcome and
//! unsubscribe notices (Go: `subscribe_list.SendMail`). Sent from
//! `noreply@<default sender domain>`, whose mailbox is created on first use
//! like Go did.

use std::path::Path;

use anyhow::{Context, Result, bail};
use ferropost_sender::smtp::{Mailer, Outgoing, SmtpConfig};
use ferropost_sender::template::{RenderData, Subscriber, render};

use crate::state::AppState;

pub struct SystemMail {
    pub to: String,
    pub subject: String,
    pub html: String,
    /// Replaces `{{ ConfirmURL . }}`; required when the HTML contains it.
    pub confirm_url: Option<String>,
}

/// Sends in the background, logging failures (as Go did after 500 ms).
pub fn spawn(state: &AppState, mail: SystemMail) {
    let state = state.clone();
    tokio::spawn(async move {
        let to = mail.to.clone();
        if let Err(err) = send(&state, mail).await {
            tracing::warn!(%to, error = %format!("{err:#}"), "system mail not sent");
        }
    });
}

pub async fn send(state: &AppState, mail: SystemMail) -> Result<()> {
    if mail.html.trim().is_empty() {
        bail!("the email template is empty");
    }
    let mut html = mail.html;
    if html.contains("{{ ConfirmURL . }}") {
        let url = mail
            .confirm_url
            .context("the confirmation email needs a confirmation link")?;
        html = html.replace("{{ ConfirmURL . }}", &url);
    }

    let pg = &state.store.pg;
    let (attribs, active, status) = ferropost_store::subscriptions::first_contact(pg, &mail.to)
        .await?
        .unwrap_or((serde_json::json!({}), 0, 0));
    let data = RenderData {
        subscriber: Some(Subscriber::from_contact(&mail.to, &attribs, active, status)),
        ..RenderData::default()
    };

    let domain = ferropost_store::subscriptions::default_sender_domain(pg)
        .await?
        .context("no active sending domain; add one first")?;
    let address = format!("noreply@{domain}");
    let password = noreply_password(state, &address, &domain).await?;
    let mailer = Mailer::new(&SmtpConfig {
        host: state.config.smtp_host.clone(),
        port: state.config.smtp_port,
        username: address.clone(),
        password,
    })?;
    mailer
        .send(&Outgoing {
            message_id: ferropost_sender::smtp::message_id(&address),
            from_email: address,
            from_name: Some("noreply".to_owned()),
            to: vec![mail.to],
            subject: render(&mail.subject, &data),
            html: render(&html, &data),
            headers: Vec::new(),
        })
        .await
}

/// Password of the noreply mailbox, creating the mailbox when missing.
async fn noreply_password(state: &AppState, address: &str, domain: &str) -> Result<String> {
    let pg = &state.store.pg;
    if let Some(encoded) = ferropost_store::mailboxes::encoded_password(pg, address).await? {
        return ferropost_sender::smtp::decode_mailbox_password(&encoded);
    }
    let password = ferropost_sender::smtp::random_password();
    let (hash, encoded) = ferropost_sender::smtp::mailbox_credentials(&password)?;
    let created = ferropost_store::mailboxes::insert(
        pg,
        &ferropost_store::mailboxes::NewMailbox {
            username: address,
            local_part: "noreply",
            domain,
            full_name: "noreply",
            password_hash: &hash,
            password_encoded: &encoded,
            quota: 5_242_880,
            now: crate::routes::now(),
        },
    )
    .await?;
    if !created {
        // Created concurrently: use the stored password.
        let encoded = ferropost_store::mailboxes::encoded_password(pg, address)
            .await?
            .context("noreply mailbox has no password")?;
        return ferropost_sender::smtp::decode_mailbox_password(&encoded);
    }
    let maildir = state
        .config
        .root
        .join("../vmail-data")
        .join(domain)
        .join("noreply");
    if let Err(err) = prepare_maildir(&maildir) {
        tracing::warn!(path = %maildir.display(), %err, "noreply maildir not prepared");
    }
    tracing::info!(%address, "noreply mailbox created");
    Ok(password)
}

/// Maildir and `maildirsize` owned by Dovecot (uid 150, gid 8), as Go set up.
fn prepare_maildir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let size = dir.join("maildirsize");
    if !size.exists() {
        std::fs::write(&size, "0S\n0 0\n")?;
    }
    for path in [dir, size.as_path()] {
        // Only possible as root (the container); ignored in development.
        let _ = std::os::unix::fs::chown(path, Some(150), Some(8));
    }
    Ok(())
}
