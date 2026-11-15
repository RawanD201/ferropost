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
