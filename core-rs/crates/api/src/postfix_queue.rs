//! Size of Postfix's deferred queue, read with `postqueue -j` inside the
//! Postfix container through the Docker socket (as Go did).

use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::exec::{CreateExecOptions, StartExecResults};
use futures_util::StreamExt;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Number of messages in the deferred queue.
pub async fn deferred_count(container: &str) -> Result<i64> {
    tokio::time::timeout(TIMEOUT, query(container))
        .await
        .context("postqueue timed out")?
}

async fn query(container: &str) -> Result<i64> {
    let docker = Docker::connect_with_unix_defaults().context("connect to docker")?;
    let exec = docker
        .create_exec(
            container,
            CreateExecOptions {
                cmd: Some(vec!["postqueue", "-j"]),
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
        return Ok(0);
    };
    let mut text = String::new();
    while let Some(chunk) = output.next().await {
        text.push_str(&chunk?.to_string());
    }
    Ok(count_deferred(&text))
}

/// `postqueue -j` prints one JSON object per queued message.
pub fn count_deferred(output: &str) -> i64 {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
        .filter(|item| item["queue_name"] == "deferred")
        .count() as i64
}

#[cfg(test)]
mod tests {
    use super::count_deferred;

    #[test]
    fn counts_deferred_entries() {
        let out = "{\"queue_name\":\"deferred\",\"queue_id\":\"A\"}\n\
                   {\"queue_name\":\"active\",\"queue_id\":\"B\"}\n\
                   \n not json\n\
                   {\"queue_name\":\"deferred\",\"queue_id\":\"C\"}\n";
        assert_eq!(count_deferred(out), 2);
        assert_eq!(count_deferred(""), 0);
    }
}
