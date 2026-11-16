//! The console IP whitelist (`set/add/delete_ip_whitelist`).
//!
//! Differences from Go: ranges in CIDR notation are accepted (the edge
//! already honoured them); a change that would shut out the address making
//! it is refused; emptying the list also switches the whitelist off (Go did
//! that only when deleting the last entry one by one, so clearing the list
//! left the console open to nobody); changes apply at once instead of after
//! a core restart.

use std::net::IpAddr;

use axum::extract::State;
use axum::routing::post;
use axum::{Extension, Router};
use ferropost_domain::audit::LogType;
use ipnet::IpNet;
use serde::Deserialize;

use super::now;
use crate::audit::Audit;
use crate::body::ApiBody;
use crate::conn::ClientIp;
use crate::de::opt_i64;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/settings/set_ip_whitelist", post(set))
        .route("/api/settings/add_ip_whitelist", post(add))
        .route("/api/settings/delete_ip_whitelist", post(delete))
}

/// An address or range in its canonical text form, with Go's `ip_type`.
fn parse(entry: &str) -> Option<(String, i16, IpNet)> {
    let net = crate::edge::parse_net(entry)?;
    let text = if net.prefix_len() == net.max_prefix_len() {
        net.addr().to_canonical().to_string()
    } else {
        net.trunc().to_string()
    };
    let kind = if matches!(net, IpNet::V4(_)) { 1 } else { 2 };
    Some((text, kind, net))
}

fn enabled(state: &AppState) -> bool {
    state.config.env.flag("IP_WHITELIST_ENABLE")
}

/// Refuses a whitelist that would block `caller` (loopback and the
/// server's own address always pass, as at the edge).
pub(super) async fn ensure_caller_allowed(
    state: &AppState,
    lang: &str,
    caller: Option<IpAddr>,
    nets: &[IpNet],
) -> Result<(), ApiError> {
    let Some(ip) = caller else {
        return Ok(());
    };
    if ip.is_loopback()
        || nets.iter().any(|n| n.contains(&ip))
        || crate::edge::server_public_ip(state).await == Some(ip)
    {
        return Ok(());
    }
    Err(ApiError::Rejected(state.i18n.tr(
        lang,
        "This would block your own address {}: add it to the IP whitelist first",
        &[&ip],
    )))
}

async fn current_nets(state: &AppState) -> Result<Vec<IpNet>, ApiError> {
    Ok(ferropost_store::whitelist::entries(&state.store.pg)
        .await?
        .iter()
        .filter_map(|e| crate::edge::parse_net(e))
        .collect())
}

/// Switches the whitelist off once it has no entries left.
fn disable_when_empty(state: &AppState, remaining: usize) -> Result<(), ApiError> {
    if remaining == 0 && enabled(state) {
        state
            .config
            .env
            .update(&[("IP_WHITELIST_ENABLE", "false")])
            .map_err(|e| anyhow::anyhow!("Failed to update environment variable file: {e}"))?;
    }
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SetBody {
    ip_list: Vec<String>,
}

async fn set(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    caller: Option<Extension<ClientIp>>,
    ApiBody(body): ApiBody<SetBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let mut entries: Vec<(String, i16)> = Vec::new();
    let mut nets = Vec::new();
    for raw in body
        .ip_list
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let (ip, kind, net) = parse(raw).ok_or_else(|| {
            ApiError::Validation(state.i18n.tr(&lang, "Invalid IP address: {}", &[&raw]))
        })?;
        if !entries.iter().any(|(e, _)| *e == ip) {
            entries.push((ip, kind));
            nets.push(net);
        }
    }
    if enabled(&state) && !entries.is_empty() {
        ensure_caller_allowed(&state, &lang, caller.map(|c| c.0.0), &nets).await?;
    }
    ferropost_store::whitelist::replace(&state.store.pg, &entries, now()).await?;
    state.caches.whitelist.invalidate_all();
    disable_when_empty(&state, entries.len())?;
    let list: Vec<&str> = entries.iter().map(|(ip, _)| ip.as_str()).collect();
    audit
        .record(
            LogType::Settings,
            &format!("Set the IP whitelist: [{}]", list.join(", ")),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "IP whitelist updated successfully", &[]),
        (),
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AddBody {
    ip: String,
}

async fn add(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<AddBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let raw = body.ip.trim();
    if raw.is_empty() {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "IP cannot be empty",
            &[],
        )));
    }
    let (ip, kind, _) = parse(raw).ok_or_else(|| {
        ApiError::Validation(state.i18n.tr(&lang, "Invalid IP address: {}", &[&raw]))
    })?;
    if !ferropost_store::whitelist::add(&state.store.pg, &ip, kind, now()).await? {
        return Err(ApiError::Conflict(state.i18n.tr(
            &lang,
            "This IP is already in the whitelist",
            &[],
        )));
    }
    state.caches.whitelist.invalidate_all();
    audit
        .record(
            LogType::Settings,
            &format!("Add whitelist ip :{ip} successfully"),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "IP added to whitelist successfully", &[]),
        (),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct DeleteBody {
    #[serde(default, deserialize_with = "opt_i64")]
    id: Option<i64>,
}

async fn delete(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    caller: Option<Extension<ClientIp>>,
    ApiBody(body): ApiBody<DeleteBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let id = body
        .id
        .filter(|id| *id > 0)
        .and_then(|id| i32::try_from(id).ok())
        .ok_or_else(|| ApiError::Rejected(state.i18n.tr(&lang, "ID cannot be empty", &[])))?;
    let pg = &state.store.pg;
    let listed = ferropost_store::whitelist::list(pg).await?;
    let Some(target) = listed.iter().find(|e| e.id == id) else {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "The IP whitelist does not exist",
            &[],
        )));
    };
    let remaining: Vec<IpNet> = listed
        .iter()
        .filter(|e| e.id != id)
        .filter_map(|e| crate::edge::parse_net(&e.ip))
        .collect();
    if enabled(&state) && !remaining.is_empty() {
        ensure_caller_allowed(&state, &lang, caller.map(|c| c.0.0), &remaining).await?;
    }
    if ferropost_store::whitelist::delete(pg, id).await?.is_none() {
        return Err(ApiError::NotFound(state.i18n.tr(
            &lang,
            "The IP whitelist does not exist",
            &[],
        )));
    }
    state.caches.whitelist.invalidate_all();
    disable_when_empty(&state, current_nets(&state).await?.len())?;
    audit
        .record(
            LogType::Settings,
            &format!("Removed whitelist ip :{} successfully", target.ip),
        )
        .await;
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "IP removed from whitelist successfully", &[]),
        (),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_entries() {
        assert_eq!(
            parse(" 203.0.113.9 ").map(|p| (p.0, p.1)),
            Some(("203.0.113.9".into(), 1))
        );
        assert_eq!(
            parse("10.1.2.3/8").map(|p| p.0).as_deref(),
            Some("10.0.0.0/8")
        );
        assert_eq!(
            parse("::ffff:192.0.2.1").map(|p| (p.0, p.1)),
            Some(("192.0.2.1".into(), 1))
        );
        assert_eq!(
            parse("2001:DB8::1").map(|p| (p.0, p.1)),
            Some(("2001:db8::1".into(), 2))
        );
        assert!(parse("nope").is_none());
    }
}
