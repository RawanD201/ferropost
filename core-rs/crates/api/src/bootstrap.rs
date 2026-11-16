//! Start-up work Go did in `cmd.go` before serving: the administrator
//! account from `.env` (which `bm.sh change-password` edits before
//! restarting the core), the first API token, rspamd's controller password
//! and the console's self-signed certificate.
//!
//! Differences from Go: the administrator's password is hashed again only
//! when `.env` changed it (Go re-hashed and rewrote it at every start);
//! `worker-controller.inc` is written as an argument list's output, never
//! through a shell; the self-signed key is owner-only (Go: 0777).

use anyhow::{Context, Result, bail};
use ferropost_store::{options, rbac};

use crate::state::AppState;

const CONTROLLER_PASSWORD: &str = "rspamd_worker_controller_password";

/// Runs what must be done before the console is served; failures are
/// logged, never fatal (as in Go).
pub async fn before_serving(state: &AppState) {
    if let Err(err) = admin_account(state).await {
        tracing::warn!(error = %format!("{err:#}"), "administrator account not synced from .env");
    }
    if let Err(err) = api_token(state).await {
        tracing::warn!(error = %format!("{err:#}"), "API token not issued");
    }
}

/// What may take a while (container commands, restarts), in the
/// background.
pub fn soon(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = console_certificate(&state).await {
            tracing::warn!(error = %format!("{err:#}"), "self-signed certificate not made");
        }
        if let Err(err) = rspamd_controller(&state).await {
            tracing::warn!(error = %format!("{err:#}"), "rspamd controller password not set");
        }
    });
}

fn now() -> i32 {
    crate::routes::now()
}

/// The administrator account, its login taken from `ADMIN_USERNAME` and
/// `ADMIN_PASSWORD` (Go's RBAC initialisation).
pub async fn admin_account(state: &AppState) -> Result<()> {
    let env = &state.config.env;
    let (Some(username), Some(password)) = (env.get("ADMIN_USERNAME"), env.get("ADMIN_PASSWORD"))
    else {
        return Ok(());
    };
    let pg = &state.store.pg;
    let role = rbac::ensure_role(pg, "admin", "System administrator with full access").await?;
    let hash = |password: String| async move {
        tokio::task::spawn_blocking(move || pwhash::bcrypt::hash(password))
            .await
            .context("hash password")?
            .context("hash password")
    };
    let id = match rbac::admin_account_id(pg, &username).await? {
        None => {
            let id = rbac::create_account(pg, &username, &hash(password).await?, now()).await?;
            tracing::info!(%username, "administrator account created");
            id
        }
        Some(id) => {
            let account = rbac::account_by_id(pg, id)
                .await?
                .context("administrator account vanished")?;
            let stored = account.password.clone();
            let given = password.clone();
            let same_password =
                tokio::task::spawn_blocking(move || pwhash::bcrypt::verify(given, &stored))
                    .await
                    .unwrap_or(false);
            if account.username != username || !same_password {
                if account.username != username && rbac::username_taken(pg, &username, id).await? {
                    bail!("ADMIN_USERNAME {username:?} is taken by another account");
                }
                let new_hash = if same_password {
                    None
                } else {
                    Some(hash(password).await?)
                };
                rbac::set_login(pg, id, Some(&username), new_hash.as_deref(), now()).await?;
                tracing::info!(%username, "administrator login updated from .env");
            }
            id
        }
    };
    rbac::grant_role(pg, id, role).await
}

/// The API token, issued once (Go issued it at first start).
pub async fn api_token(state: &AppState) -> Result<()> {
    let pg = &state.store.pg;
    if options::get_string(pg, crate::auth::API_TOKEN_OPTION)
        .await?
        .is_some_and(|t| !t.is_empty())
    {
        return Ok(());
    }
    let username = state.config.env.get("ADMIN_USERNAME").unwrap_or_default();
    let Some(id) = rbac::admin_account_id(pg, &username).await? else {
        return Ok(());
    };
    let account = rbac::account_by_id(pg, id)
        .await?
        .context("administrator account vanished")?;
    let token = state.jwt.issue_api_token(id, &account.username);
    options::set_string(pg, crate::auth::API_TOKEN_OPTION, &token).await?;
    state.caches.api_token.invalidate_all();
    Ok(())
}

/// A self-signed console certificate when there is none (Go's
/// `SelfSignedCert().Generate()`); Postfix and Dovecot use it too.
pub async fn console_certificate(state: &AppState) -> Result<()> {
    let dir = &state.config.ssl_dir;
    if dir.join("cert.pem").exists() && dir.join("key.pem").exists() {
        return Ok(());
    }
    crate::mail_tls::reset_console(state).await?;
    tracing::info!("self-signed console certificate made");
    Ok(())
}

/// `worker-controller.inc`: rspamd's web interface password, hashed by
/// `rspamadm`, kept in the options so the proxy can log in (Go's
/// `InitWorkerController`).
pub async fn rspamd_controller(state: &AppState) -> Result<()> {
    let config = &state.config;
    let path = config.rspamd_local_d.join("worker-controller.inc");
    let pg = &state.store.pg;
    let known = options::get_string(pg, CONTROLLER_PASSWORD)
        .await?
        .is_some_and(|p| !p.is_empty());
    if (path.exists() && known)
        || config.rspamd_container == "none"
        || !config.rspamd_local_d.is_dir()
    {
        return Ok(());
    }
    let password = ferropost_sender::smtp::random_password();
    let output = crate::docker::exec_ok(
        &config.rspamd_container,
        &["rspamadm", "pw", "-p", &password],
    )
    .await?;
    let hash = output.lines().next().unwrap_or_default().trim().to_owned();
    if hash.is_empty() || hash.contains(['"', '\\']) {
        bail!("rspamadm pw gave no usable hash");
    }
    let content = format!(
        "count = 1;\npassword = \"{hash}\";\nsecure_ip = \"127.0.0.1\";\nsecure_ip = \"::1\";\nstatic_dir = \"${{WWWDIR}}\";\n"
    );
    tokio::task::spawn_blocking(move || {
        crate::fsio::write_atomic(&path, content.as_bytes(), 0o644)
    })
    .await
    .context("write worker-controller.inc")??;
    options::set_string(pg, CONTROLLER_PASSWORD, &password).await?;
    crate::docker::restart_named(config, &config.rspamd_container).await?;
    tracing::info!("rspamd controller password set");
    Ok(())
}
