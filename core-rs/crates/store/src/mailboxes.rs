//! Mailboxes (`mailbox`), as far as sending system mail needs them.

use anyhow::Result;
use sqlx::PgPool;

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
    /// Dovecot hash (MD5-CRYPT, as Go wrote).
    pub password_hash: &'a str,
    /// Reversible copy (hex of base64), as Go wrote.
    pub password_encoded: &'a str,
    pub quota: i64,
    pub now: i32,
}

/// Inserts a mailbox (Go's `mail_boxes.Add` row). Returns `false` when it
/// already exists.
pub async fn insert(pg: &PgPool, m: &NewMailbox<'_>) -> Result<bool> {
    let done = sqlx::query(
        "INSERT INTO mailbox (username, password, password_encode, full_name, is_admin, maildir,
                              quota, local_part, domain, create_time, update_time, active)
         VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8, $9, $9, 1)
         ON CONFLICT (username) DO NOTHING",
    )
    .bind(m.username)
    .bind(m.password_hash)
    .bind(m.password_encoded)
    .bind(m.full_name)
    .bind(format!("{}@{}/", m.local_part, m.domain))
    .bind(m.quota)
    .bind(m.local_part)
    .bind(m.domain)
    .bind(m.now)
    .execute(pg)
    .await?;
    Ok(done.rows_affected() == 1)
}
