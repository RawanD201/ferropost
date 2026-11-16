//! SMTP relays: `bm_relay_config`, the sender domains bound to each
//! (`bm_relay_domain_mapping`) and the transports Postfix picks per sender
//! domain (`bm_domain_smtp_transport`).

use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;

/// A relay row; `auth_password` is encrypted.
#[derive(Debug, Clone, Default, Serialize, sqlx::FromRow)]
pub struct RelayRow {
    pub id: i64,
    pub remark: String,
    pub rtype: String,
    pub relay_host: String,
    pub relay_port: String,
    pub auth_user: String,
    #[serde(skip)]
    pub auth_password: String,
    pub ip: String,
    pub host: String,
    pub helo_name: String,
    pub skip_tls_verify: i32,
    pub smtp_name: String,
    pub active: i32,
    pub auth_method: String,
    pub create_time: i32,
    pub update_time: i32,
}

const COLUMNS: &str = "id, COALESCE(remark, '') AS remark, COALESCE(rtype, '') AS rtype,
    relay_host, relay_port, auth_user, auth_password, COALESCE(ip, '') AS ip,
    COALESCE(host, '') AS host, COALESCE(helo_name, '') AS helo_name,
    COALESCE(skip_tls_verify, 0)::int AS skip_tls_verify, COALESCE(smtp_name, '') AS smtp_name,
    active::int AS active, COALESCE(auth_method, '') AS auth_method, create_time, update_time";

/// Newest first; `keyword` matches remark, host, user or name.
pub async fn list(
    pg: &PgPool,
    keyword: Option<&str>,
    rtype: Option<&str>,
) -> Result<Vec<RelayRow>> {
    let pattern = keyword.map(|k| {
        format!(
            "%{}%",
            k.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM bm_relay_config
          WHERE ($1::text IS NULL OR remark ILIKE $1 OR relay_host ILIKE $1
                 OR auth_user ILIKE $1 OR smtp_name ILIKE $1)
            AND ($2::text IS NULL OR rtype = $2)
          ORDER BY create_time DESC, id DESC"
    ))
    .bind(pattern)
    .bind(rtype)
    .fetch_all(pg)
    .await?)
}

pub async fn get(pg: &PgPool, id: i64) -> Result<Option<RelayRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM bm_relay_config WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pg)
    .await?)
}

pub async fn active(pg: &PgPool) -> Result<Vec<RelayRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM bm_relay_config WHERE active = 1 ORDER BY id"
    ))
    .fetch_all(pg)
    .await?)
}

/// A relay with this exact server and login, for reusing its stored
/// password.
pub async fn find_login(
    pg: &PgPool,
    host: &str,
    port: &str,
    user: &str,
) -> Result<Option<RelayRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM bm_relay_config
          WHERE lower(relay_host) = lower($1) AND relay_port = $2 AND auth_user = $3
            AND auth_password <> ''
          ORDER BY update_time DESC LIMIT 1"
    ))
    .bind(host)
    .bind(port)
    .bind(user)
    .fetch_optional(pg)
    .await?)
}

/// `(relay_id, domain)` for the relays, oldest binding first, without
/// Go's optional `@`.
pub async fn domains_of(pg: &PgPool, ids: &[i64]) -> Result<Vec<(i64, String)>> {
    Ok(sqlx::query_as(
        "SELECT relay_id, ltrim(sender_domain, '@') FROM bm_relay_domain_mapping
          WHERE relay_id = ANY($1) ORDER BY create_time, id",
    )
    .bind(ids)
    .fetch_all(pg)
    .await?)
}

/// The domains among `domains` that exist in `domain`.
pub async fn known_domains(pg: &PgPool, domains: &[String]) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT lower(domain) FROM domain WHERE lower(domain) = ANY($1)")
            .bind(domains)
            .fetch_all(pg)
            .await?,
    )
}

/// Active domains and whether a relay is bound to each.
pub async fn domain_bindings(pg: &PgPool) -> Result<Vec<(String, bool)>> {
    Ok(sqlx::query_as(
        "SELECT d.domain, EXISTS (SELECT 1 FROM bm_relay_domain_mapping m
                                   WHERE ltrim(m.sender_domain, '@') = d.domain)
           FROM domain d WHERE d.active = 1 ORDER BY d.create_time, d.domain",
    )
    .fetch_all(pg)
    .await?)
}

/// Fields of a new relay (`auth_password` encrypted).
#[derive(Debug, Clone, Default)]
pub struct NewRelay {
    pub remark: String,
    pub rtype: String,
    pub relay_host: String,
    pub relay_port: String,
    pub auth_user: String,
    pub auth_password: String,
    pub ip: String,
    pub host: String,
    pub active: i16,
    pub auth_method: String,
    pub skip_tls_verify: i16,
    pub helo_name: String,
    pub smtp_name: String,
}

/// Locks the bindings so two requests cannot bind one domain twice, then
/// returns the domains among `domains` already bound to another relay.
async fn taken(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    domains: &[String],
    except: i64,
) -> Result<Vec<String>> {
    sqlx::query("LOCK TABLE bm_relay_domain_mapping IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await?;
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT ltrim(sender_domain, '@') FROM bm_relay_domain_mapping
          WHERE ltrim(sender_domain, '@') = ANY($1) AND relay_id <> $2",
    )
    .bind(domains)
    .bind(except)
    .fetch_all(&mut **tx)
    .await?)
}

async fn bind(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: i64,
    domains: &[String],
    now: i32,
) -> Result<()> {
    sqlx::query("DELETE FROM bm_relay_domain_mapping WHERE relay_id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO bm_relay_domain_mapping (relay_id, sender_domain, create_time)
         SELECT $1, d, $3 FROM unnest($2::text[]) AS d",
    )
    .bind(id)
    .bind(domains)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Creates a relay bound to `domains`; `Err` lists domains another relay
/// already has.
pub async fn create(
    pg: &PgPool,
    relay: &NewRelay,
    domains: &[String],
    now: i32,
) -> Result<std::result::Result<i64, Vec<String>>> {
    let mut tx = pg.begin().await?;
    let conflicts = taken(&mut tx, domains, 0).await?;
    if !conflicts.is_empty() {
        return Ok(Err(conflicts));
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO bm_relay_config (remark, rtype, relay_host, relay_port, auth_user,
             auth_password, ip, host, active, auth_method, skip_tls_verify, helo_name,
             smtp_name, create_time, update_time)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
         RETURNING id",
    )
    .bind(&relay.remark)
    .bind(&relay.rtype)
    .bind(&relay.relay_host)
    .bind(&relay.relay_port)
    .bind(&relay.auth_user)
    .bind(&relay.auth_password)
    .bind(&relay.ip)
    .bind(&relay.host)
    .bind(relay.active)
    .bind(&relay.auth_method)
    .bind(relay.skip_tls_verify)
    .bind(&relay.helo_name)
    .bind(&relay.smtp_name)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    bind(&mut tx, id, domains, now).await?;
    tx.commit().await?;
    Ok(Ok(id))
}

/// Changes to a relay; `None` keeps the stored value.
#[derive(Debug, Clone, Default)]
pub struct RelayChanges {
    pub remark: Option<String>,
    pub rtype: Option<String>,
    pub relay_host: Option<String>,
    pub relay_port: Option<String>,
    pub auth_user: Option<String>,
    pub auth_password: Option<String>,
    pub ip: Option<String>,
    pub host: Option<String>,
    pub active: Option<i16>,
    pub auth_method: Option<String>,
    pub skip_tls_verify: Option<i16>,
    pub helo_name: Option<String>,
    pub smtp_name: Option<String>,
}

/// Applies `changes` and, when given, rebinds the relay to `domains`.
/// `Err` lists domains another relay already has.
pub async fn update(
    pg: &PgPool,
    id: i64,
    changes: &RelayChanges,
    domains: Option<&[String]>,
    now: i32,
) -> Result<std::result::Result<(), Vec<String>>> {
    let mut tx = pg.begin().await?;
    if let Some(domains) = domains {
        let conflicts = taken(&mut tx, domains, id).await?;
        if !conflicts.is_empty() {
            return Ok(Err(conflicts));
        }
        bind(&mut tx, id, domains, now).await?;
    }
    sqlx::query(
        "UPDATE bm_relay_config SET
             remark = COALESCE($2, remark), rtype = COALESCE($3, rtype),
             relay_host = COALESCE($4, relay_host), relay_port = COALESCE($5, relay_port),
             auth_user = COALESCE($6, auth_user), auth_password = COALESCE($7, auth_password),
             ip = COALESCE($8, ip), host = COALESCE($9, host), active = COALESCE($10, active),
             auth_method = COALESCE($11, auth_method),
             skip_tls_verify = COALESCE($12, skip_tls_verify),
             helo_name = COALESCE($13, helo_name), smtp_name = COALESCE($14, smtp_name),
             update_time = $15
         WHERE id = $1",
    )
    .bind(id)
    .bind(&changes.remark)
    .bind(&changes.rtype)
    .bind(&changes.relay_host)
    .bind(&changes.relay_port)
    .bind(&changes.auth_user)
    .bind(&changes.auth_password)
    .bind(&changes.ip)
    .bind(&changes.host)
    .bind(changes.active)
    .bind(&changes.auth_method)
    .bind(changes.skip_tls_verify)
    .bind(&changes.helo_name)
    .bind(&changes.smtp_name)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Ok(()))
}

/// Deletes a relay and its bindings; returns its name and domains.
pub async fn delete(pg: &PgPool, id: i64) -> Result<Option<(String, Vec<String>)>> {
    let mut tx = pg.begin().await?;
    let name: Option<String> = sqlx::query_scalar(
        "DELETE FROM bm_relay_config WHERE id = $1 RETURNING COALESCE(smtp_name, '')",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(name) = name else {
        return Ok(None);
    };
    let domains: Vec<String> = sqlx::query_scalar(
        "DELETE FROM bm_relay_domain_mapping WHERE relay_id = $1
         RETURNING ltrim(sender_domain, '@')",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some((name, domains)))
}

/// Domains bound to an active relay: the relay provider signs their mail,
/// so rspamd does not.
pub async fn relayed_domains(pg: &PgPool) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT lower(ltrim(m.sender_domain, '@')) FROM bm_relay_domain_mapping m
           JOIN bm_relay_config c ON c.id = m.relay_id WHERE c.active = 1",
    )
    .fetch_all(pg)
    .await?)
}

/// Every domain, oldest first (rspamd signs for each).
pub async fn all_domains(pg: &PgPool) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT domain FROM domain ORDER BY create_time, domain")
            .fetch_all(pg)
            .await?,
    )
}

/// Replaces the relay transports with `routes` (`(@domain, service)`).
/// A relay takes a domain over from another transport kind, as in Go.
pub async fn replace_relay_transports(pg: &PgPool, routes: &[(String, String)]) -> Result<()> {
    let (domains, names): (Vec<&str>, Vec<&str>) =
        routes.iter().map(|(d, n)| (d.as_str(), n.as_str())).unzip();
    let mut tx = pg.begin().await?;
    sqlx::query(
        "DELETE FROM bm_domain_smtp_transport WHERE atype = 'relay' AND NOT (domain = ANY($1))",
    )
    .bind(&domains)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO bm_domain_smtp_transport (domain, smtp_name, atype)
         SELECT d, n, 'relay' FROM unnest($1::text[], $2::text[]) AS t(d, n)
         ON CONFLICT (domain) DO UPDATE SET smtp_name = EXCLUDED.smtp_name, atype = 'relay'",
    )
    .bind(&domains)
    .bind(&names)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Whether transports other than relays (dedicated IPs) exist; they need
/// the same `main.cf` maps.
pub async fn other_transports(pg: &PgPool) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM bm_domain_smtp_transport WHERE atype <> 'relay')",
    )
    .fetch_one(pg)
    .await?)
}
