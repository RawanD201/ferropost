//! Email templates (`email_templates`).

use anyhow::Result;
use ferropost_domain::paging::{Page, PageRequest};
use ferropost_domain::templates::EmailTemplate;
use sqlx::PgPool;

use crate::{Write, like_contains};

// `temp_name` and `chat_id` are nullable in the Go schema.
const COLUMNS: &str = "id, COALESCE(temp_name, '') AS temp_name, add_type, content, render,
                       create_time, update_time, COALESCE(chat_id, '') AS chat_id";

pub struct NewTemplate<'a> {
    pub name: &'a str,
    pub add_type: i16,
    pub content: &'a str,
    pub render: &'a str,
    pub chat_id: &'a str,
    pub now: i32,
}

/// Inserts a template; `None` when the name is taken (`UNIQUE(temp_name)`).
pub async fn create(pg: &PgPool, t: &NewTemplate<'_>) -> Result<Option<i32>> {
    Ok(sqlx::query_scalar::<_, i32>(
        "INSERT INTO email_templates (temp_name, add_type, content, render, create_time, update_time, chat_id)
         VALUES ($1, $2, $3, $4, $5, $5, $6)
         ON CONFLICT (temp_name) DO NOTHING
         RETURNING id",
    )
    .bind(t.name)
    .bind(t.add_type)
    .bind(t.content)
    .bind(t.render)
    .bind(t.now)
    .bind(t.chat_id)
    .fetch_optional(pg)
    .await?)
}

pub async fn get(pg: &PgPool, id: i32) -> Result<Option<EmailTemplate>> {
    let sql = format!("SELECT {COLUMNS} FROM email_templates WHERE id = $1");
    Ok(sqlx::query_as::<_, EmailTemplate>(&sql)
        .bind(id)
        .fetch_optional(pg)
        .await?)
}

/// Deletes a template and returns what was deleted.
pub async fn delete(pg: &PgPool, id: i32) -> Result<Option<EmailTemplate>> {
    let sql = format!("DELETE FROM email_templates WHERE id = $1 RETURNING {COLUMNS}");
    Ok(sqlx::query_as::<_, EmailTemplate>(&sql)
        .bind(id)
        .fetch_optional(pg)
        .await?)
}

/// Updates the fields that are `Some` and non-empty (Go ignored empty
/// strings), always touching `update_time`.
pub async fn update(
    pg: &PgPool,
    id: i32,
    name: Option<&str>,
    content: Option<&str>,
    render: Option<&str>,
    now: i32,
) -> Result<Write> {
    let result = sqlx::query(
        "UPDATE email_templates
            SET temp_name = COALESCE($2, temp_name),
                content = COALESCE($3, content),
                render = COALESCE($4, render),
                update_time = $5
          WHERE id = $1",
    )
    .bind(id)
    .bind(name.filter(|s| !s.is_empty()))
    .bind(content.filter(|s| !s.is_empty()))
    .bind(render.filter(|s| !s.is_empty()))
    .bind(now)
    .execute(pg)
    .await;
    match result {
        Ok(done) if done.rows_affected() == 0 => Ok(Write::NotFound),
        Ok(_) => Ok(Write::Done),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(Write::Duplicate),
        Err(e) => Err(e.into()),
    }
}

pub async fn list(
    pg: &PgPool,
    keyword: Option<&str>,
    add_type: Option<i16>,
    page: PageRequest,
) -> Result<Page<EmailTemplate>> {
    let pattern = keyword.map(like_contains);
    const FILTER: &str = "WHERE ($1::text IS NULL OR temp_name LIKE $1 ESCAPE '\\')
                            AND ($2::smallint IS NULL OR add_type = $2)";

    let count_sql = format!("SELECT COUNT(*) FROM email_templates {FILTER}");
    let count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(&pattern)
        .bind(add_type)
        .fetch_one(pg);
    let list_sql = format!(
        "SELECT {COLUMNS} FROM email_templates {FILTER}
          ORDER BY create_time DESC, id DESC LIMIT $3 OFFSET $4"
    );
    let list = sqlx::query_as::<_, EmailTemplate>(&list_sql)
        .bind(&pattern)
        .bind(add_type)
        .bind(page.limit)
        .bind(page.offset)
        .fetch_all(pg);

    let (total, list) = tokio::try_join!(count, list)?;
    Ok(Page { total, list })
}

pub async fn all(pg: &PgPool) -> Result<Vec<EmailTemplate>> {
    let sql = format!("SELECT {COLUMNS} FROM email_templates ORDER BY create_time DESC, id DESC");
    Ok(sqlx::query_as::<_, EmailTemplate>(&sql)
        .fetch_all(pg)
        .await?)
}

/// Puts an AI chat's latest HTML into the template made from it (Go's
/// `ModifyHtml`/`WriteHtml` did the same).
pub async fn set_chat_content(pg: &PgPool, chat_id: &str, content: &str, now: i32) -> Result<u64> {
    Ok(
        sqlx::query("UPDATE email_templates SET content = $2, update_time = $3 WHERE chat_id = $1")
            .bind(chat_id)
            .bind(content)
            .bind(now)
            .execute(pg)
            .await?
            .rows_affected(),
    )
}
