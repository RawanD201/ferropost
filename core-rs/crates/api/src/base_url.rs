//! Public URL of the console, used in links inside mail (Go:
//! `domains/baseurl.go`).
//!
//! `reverse_proxy_domain` wins when set. Otherwise `https://` plus, for a
//! sender's domain, its mail host name when that resolves to this server,
//! or the configured host name (`BILLIONMAIL_HOSTNAME`), or the server IP;
//! with the HTTPS port unless it is 443.

use crate::state::AppState;

pub async fn global(state: &AppState) -> String {
    for_sender(state, "").await
}

/// Base URL for links in mail from `sender`.
pub async fn for_sender(state: &AppState, sender: &str) -> String {
    let domain = sender
        .split_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .filter(|d| ferropost_domain::mail::is_safe_hostname(d))
        .unwrap_or_default();
    let st = state.clone();
    state
        .caches
        .base_urls
        .get_with(domain.clone(), async move { compute(&st, &domain).await })
        .await
}

async fn compute(state: &AppState, domain: &str) -> String {
    let pg = &state.store.pg;
    if let Ok(Some(proxy)) = ferropost_store::options::get_string(pg, "reverse_proxy_domain").await
    {
        return proxy.trim_end_matches('/').to_owned();
    }
    let port = match state.config.https_port {
        443 => String::new(),
        port => format!(":{port}"),
    };
    let server_ip = crate::edge::server_public_ip(state).await;

    if !domain.is_empty() {
        let host = ferropost_store::domains::mail_hostname(pg, domain)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| ferropost_domain::mail::mx_hostname_fallback(domain));
        if let Some(ip) = server_ip
            && resolves_to(&host, ip).await
        {
            return format!("https://{host}{port}");
        }
    }

    let host = state
        .config
        .env
        .get("BILLIONMAIL_HOSTNAME")
        .filter(|h| h != "mail.example.com")
        .or_else(|| server_ip.map(|ip| ip.to_string()))
        .unwrap_or_else(|| "localhost".to_owned());
    format!("https://{host}{port}")
}

async fn resolves_to(host: &str, ip: std::net::IpAddr) -> bool {
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host, 443)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs.any(|a| a.ip().to_canonical() == ip),
        _ => false,
    }
}
