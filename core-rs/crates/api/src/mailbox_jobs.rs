//! Mailbox upkeep, owned by the `mailboxes` job (Go's timers:
//! `NormalizeMailboxes`, `InitQuotaPluginAndUpdateUsedSpace`,
//! `UpdateMailboxesUsedSpace`, `CheckMailboxesQuotaAlerts`).
//!
//! Differences from Go: an alert is sent once per 24 hours across
//! restarts (Go kept that in memory, so every restart re-sent them), domain
//! alerts go to the domain's administrator mailboxes (Go mailed
//! `noreply@<domain>` from itself, where nobody reads them), and a missing
//! `maildirsize` triggers a Dovecot recount (Go's check compared against an
//! error text it never produced, so it never did).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use ferropost_domain::mailboxes::{new_maildirsize, quota_alert, quota_alert_mail};
use ferropost_store::mailboxes as store;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::state::AppState;
use crate::system_mail::{self, SystemMail};

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "mailboxes";

const HOURLY: Duration = Duration::from_secs(3600);
const ALERT_HOLD_SECS: i64 = 24 * 3600;

pub fn spawn(state: &AppState, shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("mailbox jobs started");
    vec![
        tokio::spawn(start_up(state.clone())),
        tokio::spawn(every(
            state.clone(),
            shutdown.clone(),
            Duration::from_secs(20),
            "used space",
            |s| Box::pin(async move { refresh_usage(&s).await }),
        )),
        tokio::spawn(every(
            state.clone(),
            shutdown,
            Duration::from_secs(60),
            "quota alerts",
            |s| Box::pin(async move { send_quota_alerts(&s).await }),
        )),
    ]
}

type Pass = std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Runs `pass` after `first`, then hourly, until shutdown.
async fn every(
    state: AppState,
    mut shutdown: watch::Receiver<bool>,
    first: Duration,
    what: &'static str,
    pass: impl Fn(AppState) -> Pass,
) {
    let mut wait = first;
    loop {
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
        if let Err(err) = pass(state.clone()).await {
            tracing::warn!(error = %format!("{err:#}"), "mailbox {what} pass failed");
        }
        wait = HOURLY;
    }
}

async fn start_up(state: AppState) {
    match store::normalise_case(&state.store.pg).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(changed = n, "mailbox addresses lower-cased"),
        Err(err) => tracing::warn!(error = %format!("{err:#}"), "normalising mailboxes failed"),
    }
    if let Err(err) = init_quota_plugin(&state).await {
        tracing::warn!(error = %format!("{err:#}"), "quota plugin initialisation failed");
    }
}

// ---- used space ------------------------------------------------------------

/// Reads each mailbox's `maildirsize`, stores changed usage and the
/// domains' totals.
pub async fn refresh_usage(state: &AppState) -> Result<()> {
    let rows = store::quota_rows(&state.store.pg, true).await?;
    let mut changed = Vec::new();
    for (username, local, domain, old_used, _, _) in rows {
        let dir = crate::maildir::dir(state, &domain, &local);
        let mut used = read_used(dir.clone()).await;
        if used.is_none() {
            // Have Dovecot write the file, then read it again.
            if crate::maildir::recalc_now(&state.config.dovecot_container, &username)
                .await
                .is_ok()
            {
                used = read_used(dir).await;
            }
        }
        if let Some(used) = used
            && used != old_used
        {
            changed.push((username, used));
        }
    }
    if !changed.is_empty() {
        store::store_usage(&state.store.pg, &changed).await?;
        tracing::debug!(changed = changed.len(), "mailbox usage refreshed");
    }
    Ok(())
}

async fn read_used(dir: std::path::PathBuf) -> Option<i64> {
    tokio::task::spawn_blocking(move || crate::maildir::used(&dir))
        .await
        .ok()
        .flatten()
}

// ---- quota alerts ------------------------------------------------------------

/// Mails a warning at 90% and 95% of a quota, once per day per level.
pub async fn send_quota_alerts(state: &AppState) -> Result<()> {
    let pg = &state.store.pg;
    let mut alerts = Vec::new();
    for (domain, quota, used) in store::domain_quotas(pg).await? {
        if let Some((level, pct)) = quota_alert(used, quota) {
            alerts.push(("domain", domain, used, quota, level, pct));
        }
    }
    for (username, _, _, used, quota, _) in store::quota_rows(pg, true).await? {
        if let Some((level, pct)) = quota_alert(used, quota) {
            alerts.push(("mailbox", username, used, quota, level, pct));
        }
    }
    for (kind, target, used, quota, level, pct) in alerts {
        let recipients = if kind == "mailbox" {
            vec![target.clone()]
        } else {
            store::domain_admins(pg, &target).await?
        };
        if recipients.is_empty() {
            tracing::debug!(domain = %target, "quota alert skipped: the domain has no administrator mailbox");
            continue;
        }
        let key = format!("quota-alert:{kind}:{target}:{level}");
        if !ferropost_store::ratelimit::first_in_window(&state.store.redis, &key, ALERT_HOLD_SECS)
            .await?
        {
            continue;
        }
        let (subject, text) = quota_alert_mail(kind, &target, used, quota, level, pct);
        let html = format!(
            "<pre style=\"font-family: sans-serif\">{}</pre>",
            escape(&text)
        );
        for to in recipients {
            system_mail::spawn(
                state,
                SystemMail {
                    to,
                    subject: subject.clone(),
                    html: html.clone(),
                    confirm_url: None,
                },
            );
        }
    }
    Ok(())
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---- quota plugin (one-time) ---------------------------------------------------

/// Enables Dovecot's maildir quota once per installation (Go:
/// `InitQuotaPluginAndUpdateUsedSpace`, guarded by the same marker file):
/// loads the plugin, writes `maildirsize` for every mailbox and recounts.
pub async fn init_quota_plugin(state: &AppState) -> Result<()> {
    let marker = state.config.root.join("data/quota_init_done.mark");
    if marker.exists() {
        return Ok(());
    }
    let conf = state.config.dovecot_conf_dir.clone();
    if !conf.is_dir() {
        anyhow::bail!("dovecot conf dir not found: {}", conf.display());
    }
    let db = &state.config.database;
    let sql = sql_conf(&db.name, &db.user, &db.password);
    tokio::task::spawn_blocking(move || configure_dovecot(&conf, &sql))
        .await
        .context("configure dovecot")??;

    let pg = &state.store.pg;
    let rows = store::quota_rows(pg, false).await?;
    for (username, local, domain, _, quota, quota_active) in &rows {
        let dir = crate::maildir::dir(state, domain, local);
        let created = tokio::task::spawn_blocking({
            let dir = dir.clone();
            let content = new_maildirsize(*quota, *quota_active == 1);
            move || write_if_missing(&dir, &content)
        })
        .await?;
        if let Err(err) = created {
            tracing::warn!(%username, path = %dir.display(), %err, "maildirsize not written");
        }
    }
    for (username, _, _, _, quota, quota_active) in &rows {
        if *quota_active != 1 || *quota <= 0 {
            continue;
        }
        if let Err(err) =
            crate::maildir::recalc_now(&state.config.dovecot_container, username).await
        {
            tracing::warn!(%username, error = %format!("{err:#}"), "doveadm quota recalc failed");
        }
    }
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &marker,
        format!(
            "First sync completed at {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
        ),
    )?;
    if let Err(err) =
        crate::docker::exec(&state.config.dovecot_container, &["dovecot", "reload"]).await
    {
        tracing::warn!(error = %format!("{err:#}"), "dovecot reload failed");
    }
    tracing::info!("quota plugin initialised");
    Ok(())
}

fn write_if_missing(dir: &Path, content: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let file = dir.join("maildirsize");
    if !file.exists() {
        std::fs::write(&file, content)?;
    }
    for path in [dir, file.as_path()] {
        let _ = std::os::unix::fs::chown(path, Some(150), Some(8));
    }
    Ok(())
}

fn configure_dovecot(conf: &Path, sql: &str) -> Result<()> {
    let main = conf.join("dovecot.conf");
    let content = std::fs::read_to_string(&main).context("read dovecot.conf")?;
    std::fs::write(&main, with_quota_plugin(&content))?;
    let pop3 = conf.join("conf.d/20-pop3.conf");
    std::fs::write(
        &pop3,
        pop3_with_plugins(std::fs::read_to_string(&pop3).ok().as_deref()),
    )?;
    let quota = conf.join("conf.d/90-quota.conf");
    if let Some(updated) = quota_conf(std::fs::read_to_string(&quota).ok().as_deref()) {
        std::fs::write(&quota, updated)?;
    }
    std::fs::write(conf.join("conf.d/dovecot-sql.conf.ext"), sql)?;
    Ok(())
}

/// Adds `quota` to `mail_plugins` (Go: `ensureDovecotConf`).
pub fn with_quota_plugin(content: &str) -> String {
    let mut found = false;
    let lines: Vec<String> = content
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("mail_plugins")
                && trimmed["mail_plugins".len()..]
                    .trim_start()
                    .starts_with('=')
            {
                found = true;
                if line.contains("quota") {
                    return line.to_owned();
                }
                return format!("{line} quota");
            }
            line.to_owned()
        })
        .collect();
    let mut out = lines.join("\n");
    if content.ends_with('\n') {
        out.push('\n');
    }
    if found {
        return out;
    }
    match content.find("!include") {
        Some(at) => format!("{}mail_plugins = quota\n{}", &content[..at], &content[at..]),
        None => format!("mail_plugins = quota\n{content}"),
    }
}

/// POP3 loads the global plugins too (Go: `ensurePop3Conf`).
pub fn pop3_with_plugins(content: Option<&str>) -> String {
    let Some(content) = content else {
        return "protocol pop3 {\n  mail_plugins = $mail_plugins\n}\n".to_owned();
    };
    if content.contains("\n  mail_plugins = $mail_plugins")
        || content.contains("\n\tmail_plugins = $mail_plugins")
    {
        return content.to_owned();
    }
    let content = content.replace(
        "#mail_plugins = $mail_plugins",
        "  mail_plugins = $mail_plugins",
    );
    if content.contains("mail_plugins = $mail_plugins") {
        return content;
    }
    content.replacen(
        "protocol pop3 {",
        "protocol pop3 {\n  mail_plugins = $mail_plugins",
        1,
    )
}

/// Turns on the maildir quota backend, or `None` when it already is (Go:
/// `ensureQuotaConf`, branch for branch).
pub fn quota_conf(content: Option<&str>) -> Option<String> {
    let Some(content) = content else {
        return Some("plugin {\n  quota = maildir\n}\n".to_owned());
    };
    let mentioned = content.contains("quota = maildir");
    if mentioned && !content.contains("#quota = maildir") && !content.contains("/*quota = maildir")
    {
        return None;
    }
    if content.contains("plugin {") && !mentioned {
        Some(content.replacen("plugin {", "plugin {\n  quota = maildir", 1))
    } else {
        Some(format!("{content}\nplugin {{\n  quota = maildir\n}}\n"))
    }
}

/// Dovecot's SQL settings (Go: `recreateSqlConf`).
pub fn sql_conf(db_name: &str, db_user: &str, db_password: &str) -> String {
    format!(
        "driver = pgsql\n\
         connect = host=pgsql dbname={db_name} user={db_user} password={db_password}\n\
         default_pass_scheme = MD5-CRYPT\n\
         user_query = SELECT '/var/vmail/%d/%n' as home, 'maildir:/var/vmail/%d/%n' as mail, 150 AS uid, 8 AS gid, 'maildir:storage=' || quota AS quota FROM mailbox WHERE username = '%u' AND active = 1\n\
         password_query = SELECT username as user, password, '/var/vmail/%d/%n' as userdb_home, 'maildir:/var/vmail/%d/%n' as userdb_mail, 150 as userdb_uid, 8 as userdb_gid FROM mailbox WHERE username = '%u' AND active = 1\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dovecot_conf_edits() {
        assert_eq!(
            with_quota_plugin("protocols = imap\n!include conf.d/*.conf\n"),
            "protocols = imap\nmail_plugins = quota\n!include conf.d/*.conf\n"
        );
        assert_eq!(
            with_quota_plugin("mail_plugins = acl\n"),
            "mail_plugins = acl quota\n"
        );
        assert_eq!(
            with_quota_plugin("mail_plugins = quota acl\n"),
            "mail_plugins = quota acl\n"
        );
        assert_eq!(with_quota_plugin("x = 1"), "mail_plugins = quota\nx = 1");

        let shipped = "protocol pop3 {\n  # comment\n  #mail_plugins = $mail_plugins\n}\n";
        assert_eq!(
            pop3_with_plugins(Some(shipped)),
            "protocol pop3 {\n  # comment\n    mail_plugins = $mail_plugins\n}\n"
        );
        assert_eq!(
            pop3_with_plugins(Some("protocol pop3 {\n}\n")),
            "protocol pop3 {\n  mail_plugins = $mail_plugins\n}\n"
        );
        assert_eq!(
            pop3_with_plugins(None),
            "protocol pop3 {\n  mail_plugins = $mail_plugins\n}\n"
        );

        assert_eq!(quota_conf(Some("plugin {\n  quota = maildir\n}\n")), None);
        // The shipped file only has it commented out: a block is appended.
        assert_eq!(
            quota_conf(Some("plugin {\n  #quota = maildir:User quota\n}\n")),
            Some(
                "plugin {\n  #quota = maildir:User quota\n}\n\nplugin {\n  quota = maildir\n}\n"
                    .to_owned()
            )
        );
        assert_eq!(
            quota_conf(Some("plugin {\n}\n")),
            Some("plugin {\n  quota = maildir\n}\n".to_owned())
        );
        assert_eq!(
            quota_conf(Some("# nothing\n")),
            Some("# nothing\n\nplugin {\n  quota = maildir\n}\n".to_owned())
        );
        assert!(
            sql_conf("db", "u", "p").contains("connect = host=pgsql dbname=db user=u password=p\n")
        );
        assert!(sql_conf("db", "u", "p").contains("WHERE username = '%u' AND active = 1\n"));
    }
}
