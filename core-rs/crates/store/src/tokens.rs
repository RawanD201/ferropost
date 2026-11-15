//! Revoked JWTs, stored in Redis by the Go core on logout.

use anyhow::Result;
use fred::prelude::KeysInterface;

use crate::RedisClient;

/// Key prefix shared with Go (`consts.JWT_BLACK_LIST_KEY_PREFIX`).
pub const REVOKED_PREFIX: &str = "JWT_BLACK_LIST:";

pub async fn is_revoked(redis: &RedisClient, jti: &str) -> Result<bool> {
    let count: i64 = redis.exists(format!("{REVOKED_PREFIX}{jti}")).await?;
    Ok(count > 0)
}
