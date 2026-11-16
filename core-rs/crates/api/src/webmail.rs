//! Roundcube at `/roundcube/` (Go: `phpfpm.PHPFpmHandlerFactory`): its
//! PHP scripts through PHP-FPM's FastCGI socket, its other files from the
//! shared `webmail-data` folder.
//!
//! Differences from Go: Roundcube's private folders (`config`, `temp`,
//! `logs`, `bin`, `SQL`, `installer`), hidden files and its README/composer
//! files are refused, as its own web server guide does (Go served them, its
//! logs included); PHP sees the visitor's address (Go passed this
//! process's own, so Roundcube's per-address protections saw one client)
//! and this server's port (Go passed the visitor's); a `Proxy` request
//! header is dropped (httpoxy); the response streams instead of being
//! buffered whole.

use std::convert::Infallible;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::fastcgi::{self, END_REQUEST, STDERR, STDOUT};
use crate::state::AppState;
use crate::static_files::{self, Caching};
use crate::{ClientIp, ConnInfo};

/// Largest request body passed to PHP (attachments).
const MAX_BODY: usize = 64 * 1024 * 1024;
const CONNECT: Duration = Duration::from_secs(5);
const READ: Duration = Duration::from_secs(300);

/// Paths Roundcube's own web server configuration refuses.
fn private(rel: &str) -> bool {
    let first = rel.split('/').next().unwrap_or_default();
    let name = rel.rsplit('/').next().unwrap_or_default();
    ["bin", "SQL", "config", "temp", "logs", "installer"].contains(&first)
        || rel.split('/').any(|s| s.starts_with('.'))
        || [
            "README",
            "INSTALL",
            "LICENSE",
            "CHANGELOG",
            "UPGRADING",
            "composer.",
        ]
        .iter()
        .any(|p| name.starts_with(p))
}

/// `/roundcube` and everything below it.
pub async fn handle(State(state): State<AppState>, req: Request) -> Response {
    let path = req.uri().path();
    let rel = path
        .strip_prefix("/roundcube")
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_owned();
    let rel = if rel.is_empty() {
        "index.php".to_owned()
    } else {
        rel
    };
    if static_files::relative(&format!("/{rel}")).is_none() || private(&rel) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if rel.ends_with(".php") {
        return php(&state, req, &rel).await;
    }
    let file = state.config.webmail_root.join(&rel);
    match static_files::file(&file, req.method(), req.headers(), Caching::Revalidate).await {
        Some(response) => response,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn parameters(state: &AppState, req: &Request, rel: &str) -> Vec<(String, String)> {
    let tls = req.extensions().get::<ConnInfo>().is_some_and(|c| c.tls);
    let client = req
        .extensions()
        .get::<ClientIp>()
        .map(|c| c.0.to_string())
        .unwrap_or_default();
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let server_name = host
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(host, |(name, _)| name);
    let script_root = state.config.webmail_script_root.trim_end_matches('/');
    let query = req.uri().query().unwrap_or_default();
    let request_uri = format!(
        "{}{}",
        state.config.web_base_path(),
        req.uri().path_and_query().map_or("/", |p| p.as_str())
    );
    let port = if tls {
        state.config.https_port
    } else {
        state.config.http_port
    };
    let header_value = |name: header::HeaderName| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let mut params: Vec<(String, String)> = [
        ("SCRIPT_FILENAME", format!("{script_root}/{rel}")),
        ("SCRIPT_NAME", format!("/{rel}")),
        ("PATH_INFO", format!("/{rel}")),
        ("DOCUMENT_ROOT", script_root.to_owned()),
        ("REQUEST_METHOD", req.method().to_string()),
        ("REQUEST_URI", request_uri),
        ("QUERY_STRING", query.to_owned()),
        ("CONTENT_TYPE", header_value(header::CONTENT_TYPE)),
        ("CONTENT_LENGTH", header_value(header::CONTENT_LENGTH)),
        ("REMOTE_ADDR", client),
        ("SERVER_NAME", server_name.to_owned()),
        ("SERVER_PORT", port.to_string()),
        ("SERVER_PROTOCOL", "HTTP/1.1".to_owned()),
        ("HTTPS", if tls { "on" } else { "off" }.to_owned()),
        ("REQUEST_TIME", chrono::Utc::now().timestamp().to_string()),
        ("GATEWAY_INTERFACE", "CGI/1.1".to_owned()),
        ("SERVER_SOFTWARE", "ferropost".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    for (name, value) in req.headers() {
        if [header::CONTENT_TYPE, header::CONTENT_LENGTH].contains(name) || name.as_str() == "proxy"
        {
            continue;
        }
        let key = format!(
            "HTTP_{}",
            name.as_str().to_ascii_uppercase().replace('-', "_")
        );
        if params.iter().any(|(k, _)| *k == key) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            params.push((key, value.to_owned()));
        }
    }
    params
}

fn bad_gateway(err: &dyn std::fmt::Display) -> Response {
    tracing::warn!(error = %err, "webmail (PHP-FPM) unavailable");
    (StatusCode::BAD_GATEWAY, "Webmail is unavailable").into_response()
}

async fn php(state: &AppState, req: Request, rel: &str) -> Response {
    let params = parameters(state, &req, rel);
    let socket = state.config.php_fpm_socket.clone();
    let stream = match tokio::time::timeout(CONNECT, UnixStream::connect(&socket)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return bad_gateway(&err),
        Err(_) => return bad_gateway(&"connection timed out"),
    };
    let (mut reader, mut writer) = stream.into_split();
    let mut head = fastcgi::begin_request();
    head.extend(fastcgi::params(&params));
    if let Err(err) = writer.write_all(&head).await {
        return bad_gateway(&err);
    }
    let mut body = req.into_body().into_data_stream();
    let mut sent = 0usize;
    while let Some(chunk) = body.next().await {
        let Ok(chunk) = chunk else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        sent += chunk.len();
        if sent > MAX_BODY {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        if let Err(err) = writer.write_all(&fastcgi::stdin(&chunk)).await {
            return bad_gateway(&err);
        }
    }
    if let Err(err) = writer
        .write_all(&fastcgi::record(fastcgi::STDIN, &[]))
        .await
    {
        return bad_gateway(&err);
    }

    // The CGI headers first; then the rest of the output streams.
    let mut output = Vec::new();
    let head = loop {
        let record = match tokio::time::timeout(READ, fastcgi::read_record(&mut reader)).await {
            Ok(Ok(Some(record))) => record,
            Ok(Ok(None)) => return bad_gateway(&"PHP-FPM closed the connection"),
            Ok(Err(err)) => return bad_gateway(&err),
            Err(_) => return bad_gateway(&"PHP-FPM took too long"),
        };
        match record.kind {
            STDOUT => {
                output.extend_from_slice(&record.content);
                if let Some(parsed) = fastcgi::split_headers(&output) {
                    break parsed;
                }
            }
            STDERR => tracing::warn!(
                message = %String::from_utf8_lossy(&record.content).chars().take(500).collect::<String>(),
                "webmail PHP error"
            ),
            END_REQUEST => return bad_gateway(&"PHP-FPM sent no headers"),
            _ => {}
        }
    };
    let first = Bytes::copy_from_slice(&output[head.body_start..]);
    let (tx, mut rx) = mpsc::channel::<Bytes>(32);
    tokio::spawn(async move {
        if !first.is_empty() && tx.send(first).await.is_err() {
            return;
        }
        loop {
            match tokio::time::timeout(READ, fastcgi::read_record(&mut reader)).await {
                Ok(Ok(Some(record))) => match record.kind {
                    STDOUT if !record.content.is_empty() => {
                        if tx.send(Bytes::from(record.content)).await.is_err() {
                            return;
                        }
                    }
                    STDERR => tracing::warn!(
                        message = %String::from_utf8_lossy(&record.content).chars().take(500).collect::<String>(),
                        "webmail PHP error"
                    ),
                    END_REQUEST => return,
                    _ => {}
                },
                _ => return,
            }
        }
    });
    let mut response = Response::new(Body::from_stream(futures_util::stream::poll_fn(
        move |cx| rx.poll_recv(cx).map(|item| item.map(Ok::<_, Infallible>)),
    )));
    *response.status_mut() = head.status;
    for (name, value) in head.headers {
        response.headers_mut().append(name, value);
    }
    if !response.headers().contains_key(header::CONTENT_TYPE) {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_paths() {
        for path in [
            "config/config.inc.php",
            "logs/errors.log",
            "temp/x",
            "installer/index.php",
            ".htaccess",
            "plugins/x/.git/config",
            "composer.json",
            "README.md",
        ] {
            assert!(private(path), "{path}");
        }
        for path in [
            "index.php",
            "skins/elastic/styles.css",
            "program/js/app.js",
            "plugins/x/x.js",
        ] {
            assert!(!private(path), "{path}");
        }
    }
}
