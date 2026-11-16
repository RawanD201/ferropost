//! Revoked JWTs and other short-lived login state, in Redis.

use anyhow::Result;
use fred::prelude::KeysInterface;
use fred::types::Expiration;

use crate::RedisClient;

/// Key prefix shared with Go (`consts.JWT_BLACK_LIST_KEY_PREFIX`), so a
/// token revoked here is refused by Go too.
pub const REVOKED_PREFIX: &str = "JWT_BLACK_LIST:";
const SESSION_PREFIX: &str = "ferropost:session-revoked:";
const LOGIN_FAILURES_PREFIX: &str = "ferropost:login-failures:";
const CAPTCHA_PREFIX: &str = "ferropost:captcha:";

pub async fn is_revoked(redis: &RedisClient, jti: &str) -> Result<bool> {
    let count: i64 = redis.exists(format!("{REVOKED_PREFIX}{jti}")).await?;
    Ok(count > 0)
}

/// Revokes a token until it would have expired anyway.
pub async fn revoke(redis: &RedisClient, jti: &str, ttl_secs: i64) -> Result<()> {
    if ttl_secs > 0 && !jti.is_empty() {
        let _: () = redis
            .set(
                format!("{REVOKED_PREFIX}{jti}"),
                "0",
                Some(Expiration::EX(ttl_secs)),
                None,
                false,
            )
            .await?;
    }
    Ok(())
}

/// Ends a login session: every token issued with this session ID.
pub async fn revoke_session(redis: &RedisClient, sid: &str, ttl_secs: i64) -> Result<()> {
    if ttl_secs > 0 && !sid.is_empty() {
        let _: () = redis
            .set(
                format!("{SESSION_PREFIX}{sid}"),
                "1",
                Some(Expiration::EX(ttl_secs)),
                None,
                false,
            )
            .await?;
    }
    Ok(())
}

pub async fn session_revoked(redis: &RedisClient, sid: &str) -> Result<bool> {
    let count: i64 = redis.exists(format!("{SESSION_PREFIX}{sid}")).await?;
    Ok(count > 0)
}

/// Failed logins from `client` in the current window, and seconds left.
pub async fn login_failures(redis: &RedisClient, client: &str) -> Result<(i64, i64)> {
    let key = format!("{LOGIN_FAILURES_PREFIX}{client}");
    let count: Option<i64> = redis.get(&key).await?;
    let ttl: i64 = redis.ttl(&key).await?;
    Ok((count.unwrap_or(0), ttl.max(0)))
}

/// Counts a failed login; the window restarts with each failure.
pub async fn record_login_failure(
    redis: &RedisClient,
    client: &str,
    window_secs: i64,
) -> Result<i64> {
    let key = format!("{LOGIN_FAILURES_PREFIX}{client}");
    let count: i64 = redis.incr(&key).await?;
    let _: () = redis.expire(&key, window_secs, None).await?;
    Ok(count)
}

pub async fn clear_login_failures(redis: &RedisClient, client: &str) -> Result<()> {
    let _: i64 = redis
        .del(format!("{LOGIN_FAILURES_PREFIX}{client}"))
        .await?;
    Ok(())
}

pub async fn store_captcha(
    redis: &RedisClient,
    id: &str,
    answer: &str,
    ttl_secs: i64,
) -> Result<()> {
    let _: () = redis
        .set(
            format!("{CAPTCHA_PREFIX}{id}"),
            answer,
            Some(Expiration::EX(ttl_secs)),
            None,
            false,
        )
        .await?;
    Ok(())
}

/// The captcha's answer, which can be used once.
pub async fn take_captcha(redis: &RedisClient, id: &str) -> Result<Option<String>> {
    Ok(redis.getdel(format!("{CAPTCHA_PREFIX}{id}")).await?)
}
