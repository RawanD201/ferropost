//! Size of Postfix's deferred queue, read with `postqueue -j` inside the
//! Postfix container through the Docker socket (as Go did).

use anyhow::Result;

/// Number of messages in the deferred queue.
pub async fn deferred_count(container: &str) -> Result<i64> {
    let text = crate::docker::exec(container, &["postqueue", "-j"]).await?;
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
