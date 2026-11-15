//! Policies applied to every request before routing: client IP resolution,
//! base-path stripping, the console IP whitelist, the safe entrance and the
//! access log.
//!
//! These used to live in Go. While Go runs behind this service it is started
//! in internal mode, which disables its own safe-entrance check (Go would only
//! ever see `127.0.0.1` and has no access to the cookie issued here).

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{COOKIE, HOST, LOCATION, REFERER, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bm_domain::web;
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use sha2::Sha256;

use crate::access_log::AccessEntry;
use crate::auth::bearer_token;
use crate::conn::{ClientIp, ConnInfo, client_ip};
use crate::envelope::ApiResponse;
use crate::proxy::Proxied;
use crate::state::AppState;

/// Liveness endpoint, answered only to loopback peers (container health
/// checks) and never logged.
pub const HEALTH_PATH: &str = "/__bm/health";
pub const ENTRANCE_COOKIE: &str = "bm_entrance";
/// Go's session lifetime for the same purpose.
const ENTRANCE_TTL_SECS: i64 = 30 * 24 * 3600;

type HmacSha256 = Hmac<Sha256>;

pub async fn edge(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let started = Instant::now();
    let conn = req.extensions().get::<ConnInfo>().copied();
    // A missing ConnInfo never happens in production; fail closed rather than
    // pretending the request came from loopback.
    let peer = conn.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| {
        c.peer.ip().to_canonical()
    });
    let tls = conn.is_some_and(|c| c.tls);

    if req.uri().path() == HEALTH_PATH && peer.is_loopback() {
        return (StatusCode::OK, "ok").into_response();
    }

    let ip = client_ip(peer, req.headers(), &state.config.trusted_proxies);
    req.extensions_mut().insert(ClientIp(ip));

    let base = state.config.web_base_path();
    rewrite_base_path(&mut req, &base);

    let entry = access_entry(&req, tls, ip);
    let response = match gate(&state, req.uri().path(), req.headers(), ip, tls, &base).await {
        Some(rejection) => rejection,
        None => next.run(req).await,
    };
    if response.extensions().get::<Proxied>().is_none() {
        state
            .access_log
            .record(&entry, response.status(), started.elapsed());
    }
    response
}

/// Returns a response when the request must not reach a handler.
async fn gate(
    state: &AppState,
    path: &str,
    headers: &HeaderMap,
    ip: IpAddr,
    tls: bool,
    base: &str,
) -> Option<Response> {
    let env = &state.config.env;

    if env.flag("IP_WHITELIST_ENABLE")
        && !web::whitelist_exempt(path)
        && !ip_allowed(state, ip).await
    {
        tracing::info!(%ip, path, "blocked by IP whitelist");
        return Some((StatusCode::FORBIDDEN, "IP not allowed").into_response());
    }

    // Without a SafePath there is nothing more to enforce.
    let safe_path = env
        .get("SafePath")
        .map(|v| web::normalize_safe_path(&v).to_owned())
        .filter(|v| !v.is_empty())?;

    if path.strip_prefix('/') == Some(safe_path.as_str()) {
        return Some(enter(&state.entrance_key, &safe_path, tls, base));
    }

    if web::safe_entrance_exempt(path)
        || has_entrance(headers, &state.entrance_key, &safe_path, now())
        || is_static_file(&state.config.root, path).await
    {
        return None;
    }

    if path.starts_with("/api/") {
        // API tokens are meant for scripts that never visit the entrance.
        let api_token = bearer_token(headers)
            .and_then(|t| state.jwt.verify(t))
            .is_some_and(|claims| claims.api_token);
        if api_token {
            return None;
        }
        let denied = ApiResponse {
            success: false,
            code: 404,
            msg: "access denied".to_owned(),
            data: (),
        };
        return Some(denied.into_response());
    }

    Some(StatusCode::NOT_FOUND.into_response())
}

fn rewrite_base_path(req: &mut Request, base: &str) {
    let Some(stripped) = web::strip_base_path(base, req.uri().path()) else {
        return;
    };
    let path_and_query = match req.uri().query() {
        Some(query) => format!("{stripped}?{query}"),
        None => stripped.to_owned(),
    };
    let mut parts = req.uri().clone().into_parts();
    parts.path_and_query = path_and_query.parse().ok();
    if let Ok(uri) = Uri::from_parts(parts) {
        *req.uri_mut() = uri;
    }
}

fn access_entry(req: &Request, tls: bool, ip: IpAddr) -> AccessEntry {
    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    AccessEntry {
        method: req.method().clone(),
        scheme: if tls { "https" } else { "http" },
        host: request_host(req).unwrap_or_default(),
        uri: req
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned()),
        version: req.version(),
        client_ip: ip,
        referer: header(REFERER),
        user_agent: header(USER_AGENT),
    }
}

/// Host from the `Host` header (HTTP/1) or the URI authority (HTTP/2).
pub fn request_host(req: &Request) -> Option<String> {
    req.headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()))
}

async fn ip_allowed(state: &AppState, ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }

    let pg = state.store.pg.clone();
    let entries = state
        .caches
        .whitelist
        .try_get_with((), async move {
            let raw = bm_store::whitelist::entries(&pg).await?;
            Ok::<_, anyhow::Error>(Arc::new(raw.iter().filter_map(|s| parse_net(s)).collect()))
        })
        .await;
    match entries {
        Ok(nets) if nets.iter().any(|net| net.contains(&ip)) => return true,
        Ok(_) => {}
        // Same fallback as Go: only loopback and the server's own address.
        Err(err) => tracing::error!(error = %format!("{err:#}"), "load IP whitelist"),
    }

    let server_ip = match state.config.server_ip {
        Some(configured) => Some(configured),
        None => state.caches.server_ip.get_with((), fetch_public_ip()).await,
    };
    server_ip == Some(ip)
}

/// Whitelist entries are single addresses; CIDR ranges are accepted too.
fn parse_net(entry: &str) -> Option<IpNet> {
    let entry = entry.trim();
    entry.parse::<IpNet>().ok().or_else(|| {
        entry
            .parse::<IpAddr>()
            .ok()
            .map(|ip| IpNet::from(ip.to_canonical()))
    })
}

/// The server's public address, which Go always allowed through the
/// whitelist. Uses the same lookup services as Go.
async fn fetch_public_ip() -> Option<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    for url in [
        "https://ifconfig.me/ip",
        "https://www.aapanel.com/api/common/getClientIP",
    ] {
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        if let Ok(body) = response.text().await
            && let Ok(ip) = body.trim().parse::<IpAddr>()
        {
            return Some(ip.to_canonical());
        }
    }
    tracing::warn!("could not determine the server's public IP");
    None
}

async fn is_static_file(root: &Path, path: &str) -> bool {
    let Some(rel) = path.strip_prefix('/') else {
        return false;
    };
    if rel.is_empty() || rel.ends_with('/') || rel.contains("..") || rel.contains(['\\', '%', '\0'])
    {
        return false;
    }
    for dir in ["public/dist", "public/html"] {
        if tokio::fs::metadata(root.join(dir).join(rel))
            .await
            .is_ok_and(|m| m.is_file())
        {
            return true;
        }
    }
    false
}

// ---- safe entrance cookie -------------------------------------------------

pub fn derive_entrance_key(secret: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"billionmail/safe-entrance/v1");
    mac.finalize().into_bytes().into()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn entrance_mac(key: &[u8; 32], safe_path: &str, expires: i64) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    // Binding the SafePath means changing it invalidates every old cookie.
    mac.update(format!("{expires}:{safe_path}").as_bytes());
    mac
}

pub fn entrance_cookie_value(key: &[u8; 32], safe_path: &str, expires: i64) -> String {
    let tag = entrance_mac(key, safe_path, expires)
        .finalize()
        .into_bytes();
    format!("{expires}.{}", hex::encode(tag))
}

fn has_entrance(headers: &HeaderMap, key: &[u8; 32], safe_path: &str, now: i64) -> bool {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| *name == ENTRANCE_COOKIE)
        .any(|(_, value)| entrance_valid(value, key, safe_path, now))
}

fn entrance_valid(value: &str, key: &[u8; 32], safe_path: &str, now: i64) -> bool {
    let Some((expires, tag)) = value.split_once('.') else {
        return false;
    };
    let (Ok(expires), Ok(tag)) = (expires.parse::<i64>(), hex::decode(tag)) else {
        return false;
    };
    expires > now
        && entrance_mac(key, safe_path, expires)
            .verify_slice(&tag)
            .is_ok()
}

fn enter(key: &[u8; 32], safe_path: &str, tls: bool, base: &str) -> Response {
    let value = entrance_cookie_value(key, safe_path, now() + ENTRANCE_TTL_SECS);
    let secure = if tls { "; Secure" } else { "" };
    let cookie = format!(
        "{ENTRANCE_COOKIE}={value}; Path=/; Max-Age={ENTRANCE_TTL_SECS}; HttpOnly; SameSite=Lax{secure}"
    );
    Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, web::base_root(base))
        .header(SET_COOKIE, cookie)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const KEY: [u8; 32] = [7; 32];

    fn cookie_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(value).expect("header"));
        headers
    }

    #[test]
    fn entrance_cookie_roundtrip() {
        let value = entrance_cookie_value(&KEY, "abc", 2_000);
        let headers = cookie_headers(&format!("other=1; {ENTRANCE_COOKIE}={value}"));
        assert!(has_entrance(&headers, &KEY, "abc", 1_000));
    }

    #[test]
    fn entrance_cookie_rejections() {
        let value = entrance_cookie_value(&KEY, "abc", 2_000);
        let headers = cookie_headers(&format!("{ENTRANCE_COOKIE}={value}"));
        assert!(!has_entrance(&headers, &KEY, "abc", 2_000), "expired");
        assert!(
            !has_entrance(&headers, &KEY, "changed", 1_000),
            "safe path changed"
        );
        assert!(!has_entrance(&headers, &[8; 32], "abc", 1_000), "other key");

        let forged = format!(
            "{ENTRANCE_COOKIE}=9999999999.{}",
            value.split_once('.').expect("dot").1
        );
        assert!(
            !has_entrance(&cookie_headers(&forged), &KEY, "abc", 1_000),
            "extended expiry"
        );
        assert!(!has_entrance(
            &cookie_headers("bm_entrance=garbage"),
            &KEY,
            "abc",
            1_000
        ));
        assert!(!has_entrance(&HeaderMap::new(), &KEY, "abc", 1_000));
    }

    #[test]
    fn whitelist_entries() {
        assert_eq!(
            parse_net("192.0.2.1"),
            Some("192.0.2.1/32".parse().expect("net"))
        );
        assert_eq!(
            parse_net(" 2001:db8::/32 "),
            Some("2001:db8::/32".parse().expect("net"))
        );
        assert_eq!(parse_net("not-an-ip"), None);
    }

    #[tokio::test]
    async fn static_file_detection() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("public/dist/assets")).expect("mkdir");
        std::fs::write(dir.path().join("public/dist/assets/app.js"), "x").expect("write");
        assert!(is_static_file(dir.path(), "/assets/app.js").await);
        assert!(!is_static_file(dir.path(), "/assets").await);
        assert!(!is_static_file(dir.path(), "/").await);
        assert!(!is_static_file(dir.path(), "/assets/../assets/app.js").await);
        assert!(!is_static_file(dir.path(), "/missing.js").await);
    }

    #[test]
    fn base_path_rewrite() {
        let mut req = Request::builder()
            .uri("/billionmail/api/tags/list?page=2")
            .body(Body::empty())
            .expect("request");
        rewrite_base_path(&mut req, "/billionmail");
        assert_eq!(req.uri(), "/api/tags/list?page=2");

        let mut req = Request::builder()
            .uri("/other")
            .body(Body::empty())
            .expect("request");
        rewrite_base_path(&mut req, "/billionmail");
        assert_eq!(req.uri(), "/other");
    }
}
