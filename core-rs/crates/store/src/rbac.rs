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
