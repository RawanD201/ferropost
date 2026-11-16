//! Key/value settings in `bm_options`.

use anyhow::Result;
use sqlx::PgPool;

pub const CURRENT_LANGUAGE: &str = "CurrentLanguage";

pub async fn get(pg: &PgPool, name: &str) -> Result<Option<String>> {
    let value = sqlx::query_scalar::<_, String>("SELECT value FROM bm_options WHERE name = $1")
        .bind(name)
        .fetch_optional(pg)
        .await?;
    Ok(value.filter(|v| !v.is_empty()))
}

pub async fn set(pg: &PgPool, name: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO bm_options (name, value) VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(name)
    .bind(value)
    .execute(pg)
    .await?;
    Ok(())
}

/// Sets `name` only if absent, then returns the stored value (so concurrent
/// callers agree on one value).
pub async fn get_or_init(pg: &PgPool, name: &str, value: &str) -> Result<String> {
    Ok(sqlx::query_scalar::<_, String>(
        "WITH ins AS (INSERT INTO bm_options (name, value) VALUES ($1, $2)
                      ON CONFLICT (name) DO NOTHING RETURNING value)
         SELECT value FROM ins UNION ALL SELECT value FROM bm_options WHERE name = $1 LIMIT 1",
    )
    .bind(name)
    .bind(value)
    .fetch_one(pg)
    .await?)
}

/// A string option written by Go's options manager, which stores values as
/// JSON (`"text"`); plain values are returned as they are.
pub async fn get_string(pg: &PgPool, name: &str) -> Result<Option<String>> {
    Ok(get(pg, name)
        .await?
        .map(|raw| serde_json::from_str::<String>(&raw).unwrap_or(raw))
        .filter(|v| !v.trim().is_empty()))
}
