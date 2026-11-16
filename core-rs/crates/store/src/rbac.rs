//! Roles and permissions (`account_role`, `role`, `role_permission`,
//! `permission`).

use anyhow::Result;
use ferropost_domain::rbac::RouteInfo;
use sqlx::PgPool;

/// Names of the roles assigned to an account.
pub async fn account_role_names(pg: &PgPool, account_id: i64) -> Result<Vec<String>> {
    let names = sqlx::query_scalar::<_, String>(
        "SELECT r.role_name
           FROM role r
           JOIN account_role ar ON ar.role_id = r.role_id
          WHERE ar.account_id = $1",
    )
    .bind(account_id)
    .fetch_all(pg)
    .await?;
    Ok(names)
}

/// True when one of the account's roles grants `route`.
pub async fn has_permission(pg: &PgPool, account_id: i64, route: &RouteInfo) -> Result<bool> {
    let granted = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
             SELECT 1
               FROM permission p
               JOIN role_permission rp ON rp.permission_id = p.permission_id
               JOIN account_role ar ON ar.role_id = rp.role_id
              WHERE ar.account_id = $1
                AND p.module = $2
                AND p.action = $3
                AND p.resource = $4
         )",
    )
    .bind(account_id)
    .bind(&route.module)
    .bind(&route.action)
    .bind(&route.resource)
    .fetch_one(pg)
    .await?;
    Ok(granted)
}

/// What login needs of an account.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginAccount {
    pub account_id: i64,
    pub username: String,
    /// bcrypt hash.
    pub password: String,
    pub email: String,
    pub status: i32,
    pub language: String,
}

const LOGIN_COLUMNS: &str = "account_id::bigint AS account_id, username, password, email,
    status::int AS status, COALESCE(language, 'en') AS language";

pub async fn account_by_username(pg: &PgPool, username: &str) -> Result<Option<LoginAccount>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {LOGIN_COLUMNS} FROM account WHERE username = $1"
    ))
    .bind(username)
    .fetch_optional(pg)
    .await?)
}

pub async fn account_by_id(pg: &PgPool, account_id: i64) -> Result<Option<LoginAccount>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {LOGIN_COLUMNS} FROM account WHERE account_id = $1"
    ))
    .bind(account_id as i32)
    .fetch_optional(pg)
    .await?)
}

pub async fn touch_login(pg: &PgPool, account_id: i64, now: i32) -> Result<()> {
    sqlx::query("UPDATE account SET last_login_time = $2 WHERE account_id = $1")
        .bind(account_id as i32)
        .bind(now)
        .execute(pg)
        .await?;
    Ok(())
}

/// Status and role names of an account, or `None` when it no longer
/// exists (Go kept honouring tokens of deleted and disabled accounts).
pub async fn account_access(pg: &PgPool, account_id: i64) -> Result<Option<(i32, Vec<String>)>> {
    let status: Option<i32> =
        sqlx::query_scalar("SELECT status::int FROM account WHERE account_id = $1")
            .bind(account_id as i32)
            .fetch_optional(pg)
            .await?;
    match status {
        Some(status) => Ok(Some((status, account_role_names(pg, account_id).await?))),
        None => Ok(None),
    }
}
