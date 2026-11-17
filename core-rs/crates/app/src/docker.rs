//! The other containers, through the Docker socket (Go: `dockerapi`).
//!
//! Unlike Go, only the platform's own containers can be inspected or
//! restarted: Go restarted or read the stats of any container ID it was
//! given, on a host where the socket reaches every container.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use bollard::Docker;
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::models::ContainerStatsResponse;
use bollard::query_parameters::{ListContainersOptions, RestartContainerOptions, StatsOptions};
use ferropost_common::Config;
use futures_util::StreamExt;
use serde::Serialize;

const TIMEOUT: Duration = Duration::from_secs(30);

/// Go's `consts.SERVICES`; Compose names the containers
/// `<project>-<service>-<n>`.
pub const PLATFORM: [&str; 7] = [
    "pgsql-billionmail",
    "redis-billionmail",
    "rspamd-billionmail",
    "dovecot-billionmail",
    "postfix-billionmail",
    "webmail-billionmail",
    "core-billionmail",
];

/// Runs `cmd` as root in `container` and returns its standard output.
/// `none` as the container name (development, tests) does nothing.
pub async fn exec(container: &str, cmd: &[&str]) -> Result<String> {
    if container == "none" {
        return Ok(String::new());
    }
    tokio::time::timeout(TIMEOUT, run(container, cmd))
        .await
        .with_context(|| format!("{} in {container} timed out", cmd.join(" ")))?
}

async fn run(container: &str, cmd: &[&str]) -> Result<String> {
    Ok(run_full(container, cmd).await?.0)
}

/// Runs `cmd` and fails unless it exits with 0, with its error output in
/// the message (Go's `ExecCommandByName` result check). `none` does nothing.
pub async fn exec_ok(container: &str, cmd: &[&str]) -> Result<String> {
    if container == "none" {
        return Ok(String::new());
    }
    let (stdout, stderr, code) = tokio::time::timeout(TIMEOUT, run_full(container, cmd))
        .await
        .with_context(|| format!("{} in {container} timed out", cmd.join(" ")))??;
    if code != Some(0) {
        bail!(
            "{} in {container} failed (exit {}): {}",
            cmd.join(" "),
            code.map_or_else(|| "unknown".to_owned(), |c| c.to_string()),
            stderr.trim()
        );
    }
    Ok(stdout)
}

/// Standard output, standard error and exit code of `cmd`, for callers
/// that read a failure themselves. `none` succeeds with no output.
pub async fn exec_status(container: &str, cmd: &[&str]) -> Result<(String, String, Option<i64>)> {
    if container == "none" {
        return Ok((String::new(), String::new(), Some(0)));
    }
    tokio::time::timeout(TIMEOUT, run_full(container, cmd))
        .await
        .with_context(|| format!("{} in {container} timed out", cmd.join(" ")))?
}

/// Standard output, standard error and exit code of `cmd`.
async fn run_full(container: &str, cmd: &[&str]) -> Result<(String, String, Option<i64>)> {
    use bollard::container::LogOutput;
    let docker = Docker::connect_with_unix_defaults().context("connect to docker")?;
    let exec = docker
        .create_exec(
            container,
            CreateExecOptions {
                cmd: Some(cmd.to_vec()),
                user: Some("root"),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        )
        .await
        .context("create exec")?;
    let StartExecResults::Attached { mut output, .. } = docker.start_exec(&exec.id, None).await?
    else {
        return Ok((String::new(), String::new(), None));
    };
    let (mut stdout, mut stderr) = (String::new(), String::new());
    while let Some(chunk) = output.next().await {
        match chunk? {
            LogOutput::StdErr { message } => stderr.push_str(&String::from_utf8_lossy(&message)),
            other => stdout.push_str(&other.to_string()),
        }
    }
    let code = docker.inspect_exec(&exec.id).await?.exit_code;
    Ok((stdout, stderr, code))
}

fn connect(config: &Config) -> Result<Docker> {
    if !config.docker_enabled {
        bail!("Docker is disabled (FERROPOST_DOCKER=none)");
    }
    Docker::connect_with_unix_defaults().context("connect to docker")
}

/// A container as the console's service list reads it (Docker's own field
/// names, as Go passed Docker's summary through).
#[derive(Debug, Clone, Serialize)]
pub struct Container {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: Vec<String>,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Created")]
    pub created: i64,
}

impl Container {
    /// The platform service this container runs, if it is one of ours.
    pub fn service(&self) -> Option<&'static str> {
        PLATFORM.into_iter().find(|service| {
            self.names
                .iter()
                .any(|n| n.trim_start_matches('/').contains(service))
        })
    }
}

/// The platform's containers, running or not.
pub async fn platform_containers(config: &Config) -> Result<Vec<Container>> {
    let docker = connect(config)?;
    let filters = std::collections::HashMap::from([(
        "name".to_owned(),
        PLATFORM.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
    )]);
    let list = tokio::time::timeout(
        TIMEOUT,
        docker.list_containers(Some(ListContainersOptions {
            all: true,
            filters: Some(filters),
            ..Default::default()
        })),
    )
    .await
    .context("listing containers timed out")??;
    Ok(list
        .into_iter()
        .map(|c| Container {
            id: c.id.unwrap_or_default(),
            names: c.names.unwrap_or_default(),
            image: c.image.unwrap_or_default(),
            state: c.state.map(|s| s.to_string()).unwrap_or_default(),
            status: c.status.unwrap_or_default(),
            created: c.created.unwrap_or_default(),
        })
        .filter(|c| c.service().is_some())
        .collect())
}

/// A platform container by its ID (or an unambiguous ID prefix).
pub async fn platform_container(config: &Config, id: &str) -> Result<Option<Container>> {
    let id = id.trim();
    if id.len() < 4 {
        return Ok(None);
    }
    Ok(platform_containers(config)
        .await?
        .into_iter()
        .find(|c| c.id.starts_with(id)))
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Io {
    #[serde(rename = "in")]
    pub read: f64,
    #[serde(rename = "out")]
    pub written: f64,
}

/// Go's `ContainerStats`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Stats {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub memory_mb: f64,
    pub net_io: Io,
    pub block_io: Io,
}

/// One sample of a container's usage.
pub async fn stats(config: &Config, id: &str) -> Result<Stats> {
    let docker = connect(config)?;
    let mut stream = docker.stats(
        id,
        Some(StatsOptions {
            stream: false,
            one_shot: false,
        }),
    );
    let sample = tokio::time::timeout(TIMEOUT, stream.next())
        .await
        .context("reading container stats timed out")?
        .context("no stats")??;
    Ok(summarize(&sample))
}

/// Usage figures as `docker stats` computes them. Go multiplied by the
/// length of `percpu_usage`, which cgroup v2 hosts leave empty, so it showed
/// 0% CPU there; it also counted the page cache as used memory.
pub fn summarize(s: &ContainerStatsResponse) -> Stats {
    let cpu = s.cpu_stats.as_ref();
    let pre = s.precpu_stats.as_ref();
    let total = |c: Option<&bollard::models::ContainerCpuStats>| {
        c.and_then(|c| c.cpu_usage.as_ref())
            .and_then(|u| u.total_usage)
            .unwrap_or(0) as f64
    };
    let system = |c: Option<&bollard::models::ContainerCpuStats>| {
        c.and_then(|c| c.system_cpu_usage).unwrap_or(0) as f64
    };
    let cpus = cpu
        .and_then(|c| c.online_cpus)
        .filter(|n| *n > 0)
        .map(f64::from)
        .or_else(|| {
            cpu.and_then(|c| c.cpu_usage.as_ref())
                .and_then(|u| u.percpu_usage.as_ref())
                .map(|p| p.len() as f64)
        })
        .unwrap_or(1.0);
    let (cpu_delta, system_delta) = (total(cpu) - total(pre), system(cpu) - system(pre));
    let cpu_percent = if cpu_delta > 0.0 && system_delta > 0.0 {
        cpu_delta / system_delta * cpus * 100.0
    } else {
        0.0
    };

    let memory = s.memory_stats.as_ref();
    let cache = memory
        .and_then(|m| m.stats.as_ref())
        .and_then(|st| {
            st.get("inactive_file")
                .or_else(|| st.get("total_inactive_file"))
        })
        .copied()
        .unwrap_or(0);
    let used = memory
        .and_then(|m| m.usage)
        .unwrap_or(0)
        .saturating_sub(cache) as f64;
    let limit = memory.and_then(|m| m.limit).unwrap_or(0) as f64;

    let mut net_io = Io::default();
    for n in s.networks.iter().flat_map(|n| n.values()) {
        net_io.read += n.rx_bytes.unwrap_or(0) as f64;
        net_io.written += n.tx_bytes.unwrap_or(0) as f64;
    }
    let mut block_io = Io::default();
    for e in s
        .blkio_stats
        .iter()
        .flat_map(|b| b.io_service_bytes_recursive.iter().flatten())
    {
        match e.op.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("read") => block_io.read += e.value.unwrap_or(0) as f64,
            Some("write") => block_io.written += e.value.unwrap_or(0) as f64,
            _ => {}
        }
    }
    Stats {
        cpu_percent,
        memory_percent: if limit > 0.0 {
            used / limit * 100.0
        } else {
            0.0
        },
        memory_mb: used / 1024.0 / 1024.0,
        net_io,
        block_io,
    }
}

pub async fn restart(config: &Config, id: &str) -> Result<()> {
    let docker = connect(config)?;
    tokio::time::timeout(
        Duration::from_secs(60),
        docker.restart_container(
            id,
            Some(RestartContainerOptions {
                t: Some(10),
                ..Default::default()
            }),
        ),
    )
    .await
    .context("restart timed out")??;
    Ok(())
}

/// Restarts the container after a moment, so the reply that asked for it
/// still goes out (the container may be this one).
pub fn restart_soon(config: &Config, id: String) {
    let config = config.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Err(err) = restart(&config, &id).await {
            tracing::error!(container = %id, error = %format!("{err:#}"), "restart failed");
        }
    });
}

/// Restarts the platform container named `name` now (`none` does nothing).
pub async fn restart_named(config: &Config, name: &str) -> Result<()> {
    if name == "none" || !config.docker_enabled {
        return Ok(());
    }
    let container = platform_containers(config)
        .await?
        .into_iter()
        .find(|c| {
            c.names
                .iter()
                .any(|n| n.trim_start_matches('/').contains(name))
        })
        .with_context(|| format!("container {name} not found"))?;
    restart(config, &container.id).await
}

/// Restarts the core container (this service and Go) for settings only
/// read at start-up.
pub async fn restart_core_soon(config: &Config) {
    if config.core_container == "none" || !config.docker_enabled {
        return;
    }
    match platform_containers(config).await {
        Ok(list) => {
            let core = list.into_iter().find(|c| {
                c.names
                    .iter()
                    .any(|n| n.trim_start_matches('/').contains(&config.core_container))
            });
            match core {
                Some(core) => restart_soon(config, core.id),
                None => {
                    tracing::error!(container = %config.core_container, "core container not found")
                }
            }
        }
        Err(err) => tracing::error!(error = %format!("{err:#}"), "list containers"),
    }
}

/// The image for a one-off helper on the host: the core container's own
/// (already present; Go pulled whatever `alpine:latest` was), else the
/// Alpine release the core image is built on.
async fn helper_image(config: &Config, docker: &Docker) -> Result<String> {
    if config.core_container != "none"
        && let Ok(list) = platform_containers(config).await
        && let Some(core) = list.into_iter().find(|c| {
            c.names
                .iter()
                .any(|n| n.trim_start_matches('/').contains(&config.core_container))
        })
        && let Ok(inspected) = docker
            .inspect_container(
                &core.id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
        && let Some(image) = inspected.image
    {
        return Ok(image);
    }
    // The core image's base (Dockerfiles/core); only `chroot` and `sh` are used.
    const ALPINE_TAG: &str = "3.24";
    let fallback = format!("alpine:{ALPINE_TAG}");
    if docker.inspect_image(&fallback).await.is_err() {
        let mut pull = docker.create_image(
            Some(bollard::query_parameters::CreateImageOptions {
                from_image: Some("alpine".to_owned()),
                tag: Some(ALPINE_TAG.to_owned()),
                ..Default::default()
            }),
            None,
            None,
        );
        while let Some(step) = pull.next().await {
            step.with_context(|| format!("pull {fallback}"))?;
        }
    }
    Ok(fallback)
}

/// Runs `cmd` on the host: in a throw-away privileged container that
/// mounts the host's root at `/host_root` (as Go's `ExecHostCommand`), so
/// `chroot /host_root <program>` runs the host's own program. The command
/// is an argument list, never a shell string. Returns the exit code and
/// the combined output.
pub async fn run_on_host(config: &Config, cmd: &[&str]) -> Result<(i64, String)> {
    use bollard::models::{ContainerCreateBody, HostConfig};
    let docker = connect(config)?;
    let image = helper_image(config, &docker).await?;
    let created = docker
        .create_container(
            None::<bollard::query_parameters::CreateContainerOptions>,
            ContainerCreateBody {
                image: Some(image),
                cmd: Some(cmd.iter().map(|c| (*c).to_owned()).collect()),
                entrypoint: Some(Vec::new()),
                working_dir: Some("/host_root".to_owned()),
                labels: Some(std::collections::HashMap::from([(
                    "ferropost.helper".to_owned(),
                    "host".to_owned(),
                )])),
                host_config: Some(HostConfig {
                    privileged: Some(true),
                    binds: Some(vec!["/:/host_root".to_owned()]),
                    network_mode: Some("host".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .context("create host helper")?;
    let id = created.id;
    let outcome = async {
        docker
            .start_container(
                &id,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await
            .context("start host helper")?;
        let mut wait =
            docker.wait_container(&id, None::<bollard::query_parameters::WaitContainerOptions>);
        let mut code = -1;
        while let Some(status) = wait.next().await {
            match status {
                Ok(s) => code = s.status_code,
                // A non-zero exit arrives as an error carrying the code.
                Err(bollard::errors::Error::DockerContainerWaitError { code: c, .. }) => code = c,
                Err(e) => return Err(anyhow::Error::from(e).context("wait for host helper")),
            }
        }
        let mut logs = docker.logs(
            &id,
            Some(bollard::query_parameters::LogsOptions {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );
        let mut output = String::new();
        while let Some(chunk) = logs.next().await {
            output.push_str(&chunk?.to_string());
        }
        Ok::<_, anyhow::Error>((code, output.trim().to_owned()))
    };
    let result = tokio::time::timeout(Duration::from_secs(120), outcome)
        .await
        .context("host helper timed out");
    let _ = docker
        .remove_container(
            &id,
            Some(bollard::query_parameters::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    result?
}

/// The directory on the host that holds `docker-compose.yml` (Go: the
/// core container's Compose label), for the `bm.sh` commands the console
/// shows.
pub async fn compose_dir(config: &Config) -> Option<String> {
    if config.core_container == "none" {
        return None;
    }
    let docker = connect(config).ok()?;
    let filters =
        std::collections::HashMap::from([("name".to_owned(), vec![config.core_container.clone()])]);
    let list = tokio::time::timeout(
        Duration::from_secs(5),
        docker.list_containers(Some(ListContainersOptions {
            all: true,
            filters: Some(filters),
            ..Default::default()
        })),
    )
    .await
    .ok()?
    .ok()?;
    list.into_iter()
        .filter_map(|c| c.labels)
        .find_map(|labels| {
            labels
                .get("com.docker.compose.project.working_dir")
                .cloned()
        })
        .filter(|dir| !dir.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ContainerCpuStats, ContainerCpuUsage, ContainerMemoryStats};

    #[test]
    fn usage_like_docker_stats() {
        let cpu = |total, system| ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(total),
                ..Default::default()
            }),
            system_cpu_usage: Some(system),
            online_cpus: Some(4),
            ..Default::default()
        };
        let sample = ContainerStatsResponse {
            cpu_stats: Some(cpu(2_000, 20_000)),
            precpu_stats: Some(cpu(1_000, 10_000)),
            memory_stats: Some(ContainerMemoryStats {
                usage: Some(300 * 1024 * 1024),
                limit: Some(1000 * 1024 * 1024),
                stats: Some(std::collections::HashMap::from([(
                    "inactive_file".to_owned(),
                    100 * 1024 * 1024,
                )])),
                ..Default::default()
            }),
            ..Default::default()
        };
        let stats = summarize(&sample);
        assert!(
            (stats.cpu_percent - 40.0).abs() < 1e-9,
            "{}",
            stats.cpu_percent
        );
        assert!((stats.memory_mb - 200.0).abs() < 1e-9);
        assert!((stats.memory_percent - 20.0).abs() < 1e-9);
        assert_eq!(
            summarize(&ContainerStatsResponse::default()),
            Stats::default()
        );
    }

    #[test]
    fn platform_names() {
        let c = |name: &str| Container {
            id: "abc".into(),
            names: vec![format!("/{name}")],
            image: String::new(),
            state: "running".into(),
            status: String::new(),
            created: 0,
        };
        assert_eq!(
            c("billionmail-core-billionmail-1").service(),
            Some("core-billionmail")
        );
        assert_eq!(c("someone-elses-db").service(), None);
    }
}
