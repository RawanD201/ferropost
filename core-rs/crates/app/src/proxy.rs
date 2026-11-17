//! Reverse proxy to the Go core for every route not yet ported.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::{Context, bail};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{CONNECTION, HOST, SET_COOKIE};
use axum::http::uri::{Authority, PathAndQuery, Scheme};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, Version};
use axum::response::{IntoResponse, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::conn::{ClientIp, ConnInfo};
use crate::edge::request_host;
use crate::envelope::ApiError;
use crate::state::AppState;

/// Marks responses produced by Go (which writes its own access log).
#[derive(Debug, Clone, Copy)]
pub struct Proxied;

/// Hop-by-hop headers (RFC 9110 §7.6.1) that must not be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers GoFrame's `GetClientIp` trusts. Client-supplied values are removed
/// and replaced with the address resolved at the edge.
const CLIENT_IP_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "proxy-client-ip",
    "wl-proxy-client-ip",
    "http_client_ip",
    "http_x_forwarded_for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "forwarded",
];

#[derive(Clone)]
pub struct Upstream {
    client: Client<HttpConnector, Body>,
    scheme: Scheme,
    authority: Authority,
}

impl Upstream {
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let uri: Uri = base
            .parse()
            .with_context(|| format!("invalid upstream URL {base:?}"))?;
        let scheme = uri
            .scheme()
            .cloned()
            .context("upstream URL needs a scheme")?;
        if scheme != Scheme::HTTP {
            bail!("upstream must be plain http:// on a private address, got {base:?}");
        }
        let authority = uri
            .authority()
            .cloned()
            .context("upstream URL needs a host")?;

        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(32)
            .build(connector);

        Ok(Self {
            client,
            scheme,
            authority,
        })
    }

    pub async fn send(
        &self,
        req: Request,
        client_ip: IpAddr,
        tls: bool,
    ) -> Result<Response, hyper_util::client::legacy::Error> {
        let host = request_host(&req);
        let (mut parts, body) = req.into_parts();

        let path_and_query = parts
            .uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        let mut uri = parts.uri.clone().into_parts();
        uri.scheme = Some(self.scheme.clone());
        uri.authority = Some(self.authority.clone());
        uri.path_and_query = Some(path_and_query);
        if let Ok(uri) = Uri::from_parts(uri) {
            parts.uri = uri;
        }
        // Clients may speak HTTP/2 to us; Go is reached over HTTP/1.1.
        parts.version = Version::HTTP_11;
        prepare_request_headers(&mut parts.headers, host.as_deref(), client_ip, tls);

        let response = self
            .client
            .request(Request::from_parts(parts, body))
            .await?;
        let (mut parts, body) = response.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        if tls {
            secure_cookies(&mut parts.headers);
        }
        let mut response = Response::from_parts(parts, Body::new(body));
        response.extensions_mut().insert(Proxied);
        Ok(response)
    }
}

/// Fallback handler: forwards the request to Go unchanged (apart from
/// forwarding headers) and streams the answer back.
pub async fn forward(State(state): State<AppState>, req: Request) -> Response {
    let tls = req.extensions().get::<ConnInfo>().is_some_and(|c| c.tls);
    let ip = req
        .extensions()
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);
    let is_api = req.uri().path().starts_with("/api/");

    let Some(upstream) = &state.upstream else {
        return if is_api {
            ApiError::NotFound("not found".to_owned()).into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        };
    };
    match upstream.send(req, ip, tls).await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(error = %err, "go core unreachable");
            if is_api {
                ApiError::Unavailable("go core".to_owned()).into_response()
            } else {
                (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
            }
        }
    }
}

fn prepare_request_headers(
    headers: &mut HeaderMap,
    host: Option<&str>,
    client_ip: IpAddr,
    tls: bool,
) {
    strip_hop_by_hop(headers);
    for name in CLIENT_IP_HEADERS {
        headers.remove(*name);
    }

    let ip = HeaderValue::from_str(&client_ip.to_string())
        .unwrap_or(HeaderValue::from_static("0.0.0.0"));
    headers.insert(HeaderName::from_static("x-forwarded-for"), ip.clone());
    headers.insert(HeaderName::from_static("x-real-ip"), ip);
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(if tls { "https" } else { "http" }),
    );
    if let Some(host) = host.and_then(|h| HeaderValue::from_str(h).ok()) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), host.clone());
        // Go builds absolute URLs (tracking, unsubscribe) from Host.
        headers.insert(HOST, host);
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

/// Go now sees plain HTTP, so cookies it sets for HTTPS clients get the
/// `Secure` attribute added back here.
fn secure_cookies(headers: &mut HeaderMap) {
    let cookies: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    if cookies.is_empty() {
        return;
    }
    headers.remove(SET_COOKIE);
    for cookie in cookies {
        let value = match cookie.to_str() {
            Ok(text)
                if !text
                    .split(';')
                    .any(|attr| attr.trim().eq_ignore_ascii_case("secure")) =>
            {
                HeaderValue::from_str(&format!("{text}; Secure")).unwrap_or(cookie)
            }
            _ => cookie,
        };
        headers.append(SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_headers_are_sanitised() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        headers.insert("proxy-client-ip", HeaderValue::from_static("127.0.0.1"));
        headers.insert(
            "http_x_forwarded_for",
            HeaderValue::from_static("127.0.0.1"),
        );
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        headers.insert("x-secret", HeaderValue::from_static("1"));
        headers.insert("authorization", HeaderValue::from_static("Bearer t"));

        let ip: IpAddr = "203.0.113.7".parse().expect("ip");
        prepare_request_headers(&mut headers, Some("mail.example.com"), ip, true);

        assert_eq!(headers["x-forwarded-for"], "203.0.113.7");
        assert_eq!(headers["x-real-ip"], "203.0.113.7");
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(headers["host"], "mail.example.com");
        assert_eq!(headers["authorization"], "Bearer t");
        assert!(!headers.contains_key("proxy-client-ip"));
        assert!(!headers.contains_key("http_x_forwarded_for"));
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("x-secret"));
    }

    #[test]
    fn cookies_get_secure_once() {
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("billion_mail=abc; Path=/; HttpOnly"),
        );
        headers.append(SET_COOKIE, HeaderValue::from_static("x=1; Secure"));
        secure_cookies(&mut headers);
        let values: Vec<_> = headers.get_all(SET_COOKIE).iter().collect();
        assert_eq!(
            values,
            ["billion_mail=abc; Path=/; HttpOnly; Secure", "x=1; Secure"]
        );
    }

    #[test]
    fn upstream_must_be_plain_http() {
        assert!(Upstream::new("http://127.0.0.1:8181").is_ok());
        assert!(Upstream::new("https://example.com").is_err());
        assert!(Upstream::new("not a url").is_err());
    }
}
