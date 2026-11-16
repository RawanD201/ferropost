//! Mailboxes (`mailbox`) and the domain usage derived from them.

use anyhow::Result;
use ferropost_domain::mailboxes::Mailbox;
use sqlx::PgPool;

use crate::{Write, like_contains};

const COLUMNS: &str = "username, password, password_encode, full_name, is_admin::int AS is_admin,
    maildir, quota, local_part, domain, create_time::bigint AS create_time,
    update_time::bigint AS update_time, active::int AS active,
    COALESCE(used_quota, 0) AS used_quota, COALESCE(quota_active, 1)::int AS quota_active";

/// The stored reversible password (`password_encode`) of a mailbox.
pub async fn encoded_password(pg: &PgPool, username: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT password_encode FROM mailbox WHERE username = $1 AND password_encode <> ''",
    )
    .bind(username)
    .fetch_optional(pg)
    .await?)
}

pub struct NewMailbox<'a> {
    pub username: &'a str,
    pub local_part: &'a str,
    pub domain: &'a str,
    pub full_name: &'a str,
    /// Dovecot hash.
    pub password_hash: &'a str,
    /// Reversible copy (hex of base64), as Go wrote.
    pub password_encoded: &'a str,
    pub quota: i64,
    pub quota_active: i32,
    pub is_admin: i32,
    pub active: i32,
    pub now: i32,
}

impl<'a> NewMailbox<'a> {
    /// A plain mailbox with the quota on (what system mail creates).
    pub fn basic(
        username: &'a str,
        local_part: &'a str,
        domain: &'a str,
        password_hash: &'a str,
        password_encoded: &'a str,
        quota: i64,
        now: i32,
    ) -> Self {
        Self {
            username,
            local_part,
            domain,
            full_name: local_part,
            password_hash,
            password_encoded,
            quota,
            quota_active: 1,
            is_admin: 0,
            active: 1,
            now,
        }
    }
}

const INSERT: &str =
    "INSERT INTO mailbox (username, password, password_encode, full_name, is_admin,
        maildir, quota, local_part, domain, create_time, update_time, active, quota_active)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11, $12)
     ON CONFLICT (username) DO NOTHING";

/// Inserts a mailbox. Returns `false` when it already exists.
pub async fn insert(pg: &PgPool, m: &NewMailbox<'_>) -> Result<bool> {
    let done = sqlx::query(INSERT)
        .bind(m.username)
        .bind(m.password_hash)
        .bind(m.password_encoded)
        .bind(m.full_name)
        .bind(m.is_admin as i16)
        .bind(format!("{}@{}/", m.local_part, m.domain))
        .bind(m.quota)
        .bind(m.local_part)
        .bind(m.domain)
        .bind(m.now)
        .bind(m.active as i16)
        .bind(m.quota_active as i16)
        .execute(pg)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// Inserts mailboxes in one transaction; returns the addresses created
/// (existing ones are skipped; Go counted them as created).
pub async fn insert_many(pg: &PgPool, mailboxes: &[NewMailbox<'_>]) -> Result<Vec<String>> {
    let mut tx = pg.begin().await?;
    let mut created = Vec::new();
    for m in mailboxes {
        let done = sqlx::query(INSERT)
            .bind(m.username)
            .bind(m.password_hash)
            .bind(m.password_encoded)
            .bind(m.full_name)
            .bind(m.is_admin as i16)
            .bind(format!("{}@{}/", m.local_part, m.domain))
            .bind(m.quota)
            .bind(m.local_part)
            .bind(m.domain)
            .bind(m.now)
            .bind(m.active as i16)
            .bind(m.quota_active as i16)
            .execute(&mut *tx)
            .await?;
        if done.rows_affected() == 1 {
            created.push(m.username.to_owned());
        }
    }
    tx.commit().await?;
    Ok(created)
}

pub async fn get(pg: &PgPool, username: &str) -> Result<Option<Mailbox>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mailbox WHERE username = $1"
    ))
    .bind(username)
    .fetch_optional(pg)
    .await?)
}

/// A page of mailboxes, newest first.
pub async fn list(
    pg: &PgPool,
    domain: Option<&str>,
    keyword: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(i64, Vec<Mailbox>)> {
    let pattern = keyword.map(like_contains);
    let filter = "($1::text IS NULL OR domain = $1) AND ($2::text IS NULL OR username LIKE $2)";
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM mailbox WHERE {filter}"))
        .bind(domain)
        .bind(&pattern)
        .fetch_one(pg)
        .await?;
    let list = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mailbox WHERE {filter}
          ORDER BY create_time DESC, username LIMIT $3 OFFSET $4"
    ))
    .bind(domain)
    .bind(&pattern)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pg)
    .await?;
    Ok((total, list))
}

pub async fn all(pg: &PgPool, domain: Option<&str>) -> Result<Vec<Mailbox>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mailbox WHERE ($1::text IS NULL OR domain = $1) ORDER BY username"
    ))
    .bind(domain)
    .fetch_all(pg)
    .await?)
}

pub async fn usernames(pg: &PgPool, domain: Option<&str>) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT username FROM mailbox WHERE ($1::text IS NULL OR domain = $1) ORDER BY username",
    )
    .bind(domain)
    .fetch_all(pg)
    .await?)
}

/// Changes of `mailbox/update`; `None` keeps the value.
#[derive(Debug, Clone, Default)]
pub struct MailboxChanges {
    pub full_name: Option<String>,
    /// `(hash, encoded)`.
    pub credentials: Option<(String, String)>,
    pub is_admin: Option<i32>,
    pub quota: Option<i64>,
    pub active: Option<i32>,
    pub quota_active: Option<i32>,
}

/// Applies the changes and returns the row before and after.
pub async fn update(
    pg: &PgPool,
    username: &str,
    c: &MailboxChanges,
    now: i32,
) -> Result<Option<(Mailbox, Mailbox)>> {
    let mut tx = pg.begin().await?;
    let before: Option<Mailbox> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM mailbox WHERE username = $1 FOR UPDATE"
    ))
    .bind(username)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(before) = before else {
        return Ok(None);
    };
    let (hash, encoded) = c.credentials.clone().unzip();
    let after = sqlx::query_as(&format!(
        "UPDATE mailbox SET full_name = COALESCE($2, full_name), password = COALESCE($3, password),
            password_encode = COALESCE($4, password_encode), is_admin = COALESCE($5, is_admin),
            quota = COALESCE($6, quota), active = COALESCE($7, active),
            quota_active = COALESCE($8, quota_active), update_time = $9
          WHERE username = $1 RETURNING {COLUMNS}"
    ))
    .bind(username)
    .bind(&c.full_name)
    .bind(hash)
    .bind(encoded)
    .bind(c.is_admin.map(|v| v as i16))
    .bind(c.quota)
    .bind(c.active.map(|v| v as i16))
    .bind(c.quota_active.map(|v| v as i16))
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((before, after)))
}

/// Deletes mailboxes; returns the addresses deleted. Mail on disk is kept,
/// as in Go.
pub async fn delete_many(pg: &PgPool, usernames: &[String]) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("DELETE FROM mailbox WHERE username = ANY($1) RETURNING username")
            .bind(usernames)
            .fetch_all(pg)
            .await?,
    )
}

/// Whether the domain is one this server handles.
pub async fn domain_exists(pg: &PgPool, domain: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM domain WHERE domain = $1)")
            .bind(domain)
            .fetch_one(pg)
            .await?,
    )
}

/// Lower-cases addresses written with capitals (Go's start-up
/// `NormalizeMailboxes`); returns how many changed. A row whose
/// lower-case form already exists is left alone instead of failing all.
pub async fn normalise_case(pg: &PgPool) -> Result<u64> {
    Ok(sqlx::query(
        "UPDATE mailbox m SET username = LOWER(username), local_part = LOWER(local_part),
                domain = LOWER(domain), maildir = LOWER(maildir)
          WHERE username ~ '[A-Z]'
            AND NOT EXISTS (SELECT 1 FROM mailbox o WHERE o.username = LOWER(m.username))",
    )
    .execute(pg)
    .await?
    .rows_affected())
}

/// `(username, local_part, domain, used_quota, quota, quota_active)` of
/// active mailboxes.
pub type QuotaRow = (String, String, String, i64, i64, i32);

pub async fn quota_rows(pg: &PgPool, quota_on_only: bool) -> Result<Vec<QuotaRow>> {
    Ok(sqlx::query_as(
        "SELECT username, local_part, domain, COALESCE(used_quota, 0), quota,
                COALESCE(quota_active, 1)::int
           FROM mailbox
          WHERE active = 1 AND (NOT $1 OR COALESCE(quota_active, 1) = 1)
          ORDER BY username",
    )
    .bind(quota_on_only)
    .fetch_all(pg)
    .await?)
}

/// Stores measured usage and refreshes each domain's total
/// (`domain.current_usage`), in one transaction.
pub async fn store_usage(pg: &PgPool, usage: &[(String, i64)]) -> Result<()> {
    let mut tx = pg.begin().await?;
    let (users, used): (Vec<&str>, Vec<i64>) = usage.iter().map(|(u, b)| (u.as_str(), *b)).unzip();
    sqlx::query(
        "UPDATE mailbox m SET used_quota = u.used
           FROM unnest($1::text[], $2::bigint[]) AS u(username, used)
          WHERE m.username = u.username AND COALESCE(m.used_quota, 0) <> u.used",
    )
    .bind(&users)
    .bind(&used)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE domain d SET current_usage = s.usage
           FROM (SELECT domain, COALESCE(SUM(used_quota), 0)::bigint AS usage
                   FROM mailbox WHERE active = 1 GROUP BY domain) s
          WHERE d.domain = s.domain",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `(domain, quota, used)` of domains with a quota.
pub async fn domain_quotas(pg: &PgPool) -> Result<Vec<(String, i64, i64)>> {
    Ok(sqlx::query_as(
        "SELECT domain, quota, COALESCE(current_usage, 0) FROM domain WHERE quota > 0 ORDER BY domain",
    )
    .fetch_all(pg)
    .await?)
}

/// Active administrator mailboxes of a domain, who get its quota alerts.
pub async fn domain_admins(pg: &PgPool, domain: &str) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT username FROM mailbox WHERE domain = $1 AND is_admin = 1 AND active = 1 ORDER BY username",
    )
    .bind(domain)
    .fetch_all(pg)
    .await?)
}

/// Inserts a mailbox, telling a duplicate apart.
pub async fn create(pg: &PgPool, m: &NewMailbox<'_>) -> Result<Write> {
    Ok(if insert(pg, m).await? {
        Write::Done
    } else {
        Write::Duplicate
    })
}
