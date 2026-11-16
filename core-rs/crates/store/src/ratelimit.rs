//! Simple Redis-backed limits.

use anyhow::Result;
use fred::prelude::KeysInterface;
use fred::types::{Expiration, SetOptions};

use crate::RedisClient;

/// True the first time `key` is seen within `window_secs`, false after.
pub async fn first_in_window(redis: &RedisClient, key: &str, window_secs: i64) -> Result<bool> {
    let set: Option<String> = redis
        .set(
            format!("ferropost:limit:{key}"),
            "1",
            Some(Expiration::EX(window_secs)),
            Some(SetOptions::NX),
            false,
        )
        .await?;
    Ok(set.is_some())
}
