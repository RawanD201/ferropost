//! Commands in the other containers through the Docker socket (Go:
//! `dockerapi.ExecCommandByName`).

use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures_util::StreamExt;

const TIMEOUT: Duration = Duration::from_secs(30);

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
    let docker = Docker::connect_with_unix_defaults().context("connect to docker")?;
    let exec = docker
        .create_exec(
            container,
            CreateExecOptions {
                cmd: Some(cmd.to_vec()),
                user: Some("root"),
                attach_stdout: Some(true),
                attach_stderr: Some(false),
                ..Default::default()
            },
        )
        .await
        .context("create exec")?;
    let StartExecResults::Attached { mut output, .. } = docker.start_exec(&exec.id, None).await?
    else {
        return Ok(String::new());
    };
    let mut text = String::new();
    while let Some(chunk) = output.next().await {
        text.push_str(&chunk?.to_string());
    }
    Ok(text)
}
