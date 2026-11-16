//! Dedicated sending IPs (Go: `service/multi_ip_domain`), and the
//! `multi_ip` job: the host's SNAT rules at start-up (Go's
//! `ReapplyAllIptablesRules`).
//!
//! Differences from Go:
//! - Host commands run as argument lists in one helper container started
//!   from the core's own image (Go pulled `alpine:latest` and pasted values
//!   into a `sh -c` string for every rule).
//! - Old SNAT rules are removed by specification, not line number, and are
//!   removed even once no dedicated IP is left (Go left them in place).
//! - Postfix joins the main network at `<IPV4_NETWORK>.100` (Go:
//!   `172.66.1.100` whatever the network), and the rewritten compose file
//!   keeps the blank lines between services.
//! - Applying with no dedicated IP left removes the earlier transports from
//!   `master.cf` (Go did nothing).

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ferropost_domain::multi_ip::{self as rules, DedicatedIp};
use ferropost_store::multi_ip::{self as store, DedicatedIpRow};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::postfix::{conf, edit_main_cf_at, write_if_changed};
use crate::state::AppState;

/// Job name shared with Go's `timers.OwnedByRust`.
pub const JOB: &str = "multi_ip";
/// Option counting the SNAT rules last installed, so a start-up with none
/// to keep does not start a privileged helper for nothing.
const RULES_OPTION: &str = "ferropost_snat_rules";

static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn as_config(row: &DedicatedIpRow) -> DedicatedIp {
    DedicatedIp {
        domain: row.domain.clone(),
        outbound_ip: row.outbound_ip.clone(),
        network_name: row.network_name.clone(),
        subnet: row.subnet.clone(),
        postfix_ip: row.postfix_ip.clone(),
        aliases: row.aliases.clone(),
        smtp_server_name: row.smtp_server_name.clone(),
    }
}

/// The host directory holding `docker-compose.yml`.
pub async fn host_dir(state: &AppState) -> String {
    let config = state.config.clone();
    state
        .caches
        .compose_dir
        .get_with((), async move { crate::docker::compose_dir(&config).await })
        .await
        .unwrap_or_else(|| {
            state
                .config
                .root
                .parent()
                .unwrap_or(&state.config.root)
                .display()
                .to_string()
        })
}

fn main_ip(state: &AppState) -> String {
    rules::main_postfix_ip(state.config.env.get("IPV4_NETWORK").as_deref())
}

/// Copies a file on the host.
async fn host_copy(state: &AppState, from: &str, to: &str) -> Result<()> {
    for path in [from, to] {
        if !path.starts_with('/') || path.contains(['\n', '\0']) {
            bail!("unexpected host path {path:?}");
        }
    }
    let (code, output) =
        crate::docker::run_on_host(&state.config, &["chroot", "/host_root", "cp", from, to])
            .await?;
    if code != 0 {
        bail!("copying {from} failed (exit {code}): {output}");
    }
    Ok(())
}

/// Writes `docker-compose_addnetwork.yml` next to the host's compose file.
async fn write_compose(state: &AppState, configs: &[DedicatedIp]) -> Result<()> {
    let host = host_dir(state).await;
    let local: PathBuf = state.config.root.join("data");
    let host_data = format!("{host}/core-data");
    tokio::fs::create_dir_all(&local).await?;
    let original = local.join("temp_docker-compose.yml");
    let modified = local.join("temp_docker-compose_addnetwork.yml");
    let outcome = async {
        host_copy(
            state,
            &format!("{host}/docker-compose.yml"),
            &format!("{host_data}/temp_docker-compose.yml"),
        )
        .await?;
        let content = tokio::fs::read_to_string(&original)
            .await
            .context("read the copied docker-compose.yml")?;
        let next = rules::compose_with_networks(&content, configs, &main_ip(state))
            .map_err(|e| anyhow!("{e}"))?;
        tokio::fs::write(&modified, next).await?;
        host_copy(
            state,
            &format!("{host_data}/temp_docker-compose_addnetwork.yml"),
            &format!("{host}/docker-compose_addnetwork.yml"),
        )
        .await
    }
    .await;
    let _ = tokio::fs::remove_file(&original).await;
    let _ = tokio::fs::remove_file(&modified).await;
    outcome
}

/// What `apply` did, and what to run on the host.
pub struct Applied {
    pub domains: Vec<String>,
    pub command: String,
    pub fix_command: String,
}

/// Writes the compose file and Postfix's files for every active dedicated
/// IP; on failure the Postfix files are put back (Go's
/// `ApplyConfigsWithRollback`).
pub async fn apply(state: &AppState) -> Result<Applied> {
    let _one = ONE.lock().await;
    let pg = &state.store.pg;
    let rows = store::active(pg).await?;
    let host = host_dir(state).await;
    let applied = Applied {
        domains: rows.iter().map(|r| r.domain.clone()).collect(),
        command: format!("cd {host} && bash bm.sh multi_ip"),
        fix_command: format!("cd {host} && bash bm.sh fix_multi_ip "),
    };
    let master_path = conf(state, "master.cf");
    let main_path = conf(state, "main.cf");
    let master = tokio::fs::read_to_string(&master_path)
        .await
        .unwrap_or_default();
    if rows.is_empty() && !master.contains(rules::MASTER_BEGIN) {
        return Ok(applied);
    }
    let pending: Vec<i32> = rows
        .iter()
        .filter(|r| r.status != "applied")
        .map(|r| r.id)
        .collect();
    store::set_status(pg, &pending, "applying").await?;
    let all: Vec<i32> = rows.iter().map(|r| r.id).collect();
    let configs: Vec<DedicatedIp> = rows.iter().map(as_config).collect();
    let main = tokio::fs::read_to_string(&main_path)
        .await
        .unwrap_or_default();

    let outcome = async {
        write_compose(state, &configs).await?;
        let (master_path, main_path, configs, ip) = (
            master_path.clone(),
            main_path.clone(),
            configs.clone(),
            main_ip(state),
        );
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut changed = edit_main_cf_at(&main_path, |c| rules::apply_main(c, &ip))?;
            let current = std::fs::read_to_string(&master_path).context("read master.cf")?;
            changed |=
                write_if_changed(&master_path, &rules::apply_master(&current, &configs), None)?;
            Ok(changed)
        })
        .await
        .map_err(|e| anyhow!("write Postfix files: {e}"))?
    }
    .await;
    match outcome {
        Ok(_) => Ok(applied),
        Err(err) => {
            let (main_path, master_path) = (main_path.clone(), master_path.clone());
            let restored = tokio::task::spawn_blocking(move || -> Result<()> {
                if !main.is_empty() {
                    edit_main_cf_at(&main_path, |_| main.clone())?;
                }
                if !master.is_empty() {
                    write_if_changed(&master_path, &master, None)?;
                }
                Ok(())
            })
            .await;
            if !matches!(restored, Ok(Ok(()))) {
                tracing::error!(
                    "restoring main.cf and master.cf after a failed multi-IP apply failed"
                );
            }
            store::set_status(pg, &all, "failed").await?;
            Err(err)
        }
    }
}

/// Go's `ValidateDNSRecords`: the domain's mail host must resolve to the
/// IP; the SPF record is advice only (`Ok(Some(advice))`).
pub async fn test(state: &AppState, domain: &str, outbound_ip: Ipv4Addr) -> Result<Option<String>> {
    let host = ferropost_store::domains::format_mx(&state.store.pg, domain).await?;
    let addresses: Vec<std::net::IpAddr> = match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), 25)),
    )
    .await
    {
        Ok(Ok(found)) => found.map(|a| a.ip()).collect(),
        Ok(Err(e)) => bail!(
            "failed to query A record for domain '{domain}': {e}. Please ensure the domain is correctly resolved."
        ),
        Err(_) => bail!("failed to query A record for domain '{domain}': timed out"),
    };
    if !addresses.contains(&std::net::IpAddr::V4(outbound_ip)) {
        bail!(
            "A record validation failed: The resolution result of domain '{domain}' does not contain the specified outbound IP '{outbound_ip}'"
        );
    }
    let spf = crate::dns::spf_record(domain).await;
    Ok(rules::spf_advice(
        spf.as_deref(),
        &outbound_ip.to_string(),
        domain,
        &host,
    ))
}

/// Replaces the host's SNAT rules with the active configurations' (Go's
/// `ReapplyAllIptablesRules`).
pub async fn reapply_rules(state: &AppState) -> Result<usize> {
    let pg = &state.store.pg;
    let pairs: Vec<(String, String)> = store::active(pg)
        .await?
        .into_iter()
        .map(|r| (r.subnet, r.outbound_ip))
        .collect();
    let args = rules::snat_args(&pairs);
    let installed = ferropost_store::options::get(pg, RULES_OPTION)
        .await?
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    if args.is_empty() && installed == 0 {
        return Ok(0);
    }
    let mut cmd: Vec<&str> = vec![
        "chroot",
        "/host_root",
        "/bin/sh",
        "-c",
        rules::IPTABLES_SCRIPT,
        "sh",
    ];
    cmd.extend(args.iter().map(String::as_str));
    let (code, output) = crate::docker::run_on_host(&state.config, &cmd).await?;
    if code != 0 {
        bail!("iptables failed (exit {code}): {output}");
    }
    let count = args.len() / 2;
    ferropost_store::options::set(pg, RULES_OPTION, &count.to_string()).await?;
    Ok(count)
}

pub fn spawn(state: &AppState, mut shutdown: watch::Receiver<bool>) -> Vec<JoinHandle<()>> {
    if !state.config.runs_job(JOB) {
        return Vec::new();
    }
    tracing::info!("multi_ip job started");
    let state = state.clone();
    vec![tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(3)) => {}
            _ = shutdown.changed() => return,
        }
        match reapply_rules(&state).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(rules = n, "SNAT rules installed"),
            Err(err) => tracing::warn!(error = %format!("{err:#}"), "SNAT rules not installed"),
        }
    })]
}
