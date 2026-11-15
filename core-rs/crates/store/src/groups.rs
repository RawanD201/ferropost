//! Contact groups (`bm_contact_groups`).

use anyhow::Result;
use sqlx::PgPool;

pub async fn name(pg: &PgPool, id: i32) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT name FROM bm_contact_groups WHERE id = $1")
            .bind(id)
            .fetch_optional(pg)
            .await?,
    )
}
