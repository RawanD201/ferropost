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

/// The console administrator whose login `.env` holds (`ADMIN_USERNAME`,
/// `ADMIN_PASSWORD`), found as Go's start-up sync finds it: the first
/// account with the admin role, else the account named `username`.
pub async fn admin_account_id(pg: &PgPool, username: &str) -> Result<Option<i64>> {
    let by_role: Option<i64> = sqlx::query_scalar(
        "SELECT ar.account_id::bigint FROM account_role ar JOIN role r ON r.role_id = ar.role_id
          WHERE r.role_name = 'admin' ORDER BY ar.account_id LIMIT 1",
    )
    .fetch_optional(pg)
    .await?;
    if by_role.is_some() {
        return Ok(by_role);
    }
    Ok(
        sqlx::query_scalar("SELECT account_id::bigint FROM account WHERE username = $1")
            .bind(username)
            .fetch_optional(pg)
            .await?,
    )
}

/// Whether another account already uses `username`.
pub async fn username_taken(pg: &PgPool, username: &str, except: i64) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM account WHERE username = $1 AND account_id <> $2)",
    )
    .bind(username)
    .bind(except as i32)
    .fetch_one(pg)
    .await?)
}

/// Changes an account's user name and/or password hash.
pub async fn set_login(
    pg: &PgPool,
    account_id: i64,
    username: Option<&str>,
    password_hash: Option<&str>,
    now: i32,
) -> Result<()> {
    sqlx::query(
        "UPDATE account SET username = COALESCE($2, username), password = COALESCE($3, password),
                update_time = $4
          WHERE account_id = $1",
    )
    .bind(account_id as i32)
    .bind(username)
    .bind(password_hash)
    .bind(now)
    .execute(pg)
    .await?;
    Ok(())
}

/// An account's email address.
pub async fn email_of(pg: &PgPool, account_id: i64) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT email FROM account WHERE account_id = $1")
            .bind(account_id as i32)
            .fetch_optional(pg)
            .await?,
    )
}
