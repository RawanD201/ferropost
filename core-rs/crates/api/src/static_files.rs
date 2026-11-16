//! The console's files (Go's static server and its catch-all route):
//! `public/dist` (the built console), then `public/html` (subscription
//! pages), else the console's `index.html` for its own client-side routes.
//!
//! Differences from Go: built assets under `/static/` (their names carry a
//! content hash) are cached for a year and everything else revalidated
//! with an ETag; once Go is gone, unknown `/api/` routes get an envelope,
//! not a bare 404.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::envelope::ApiError;
use crate::state::AppState;

/// The type of a file, by its extension.
pub fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// A request path as a file path below a folder: no traversal, no
/// encoded or hidden names.
pub fn relative(path: &str) -> Option<&str> {
    let rel = path.strip_prefix('/')?;
    let safe = !rel.contains(['\\', '%', '\0'])
        && rel
            .split('/')
            .all(|segment| segment != ".." && !(segment.starts_with('.') && segment.len() > 1));
    safe.then_some(rel)
}

/// How long a browser may keep a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caching {
    Revalidate,
    Immutable,
}

/// Serves a file (`None` when it is not one), answering `If-None-Match`.
pub async fn file(
    path: &Path,
    method: &Method,
    headers: &HeaderMap,
    caching: Caching,
) -> Option<Response> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    if !meta.is_file() {
        return None;
    }
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    let etag = format!("W/\"{:x}-{modified:x}\"", meta.len());
    let cache = match caching {
        Caching::Revalidate => "no-cache",
        Caching::Immutable => "public, max-age=31536000, immutable",
    };
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|tag| tag.trim() == etag));
    let mut response = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else if method == Method::HEAD {
        let mut r = Body::empty().into_response();
        if let Ok(len) = HeaderValue::from_str(&meta.len().to_string()) {
            r.headers_mut().insert(header::CONTENT_LENGTH, len);
        }
        r
    } else {
        tokio::fs::read(path).await.ok()?.into_response()
    };
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(path)),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(tag) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, tag);
    }
    Some(response)
}

fn folders(state: &AppState) -> [PathBuf; 2] {
    let public = state.config.root.join("public");
    [public.join("dist"), public.join("html")]
}

/// The router's fallback.
pub async fn fallback(State(state): State<AppState>, req: Request) -> Response {
    let path = req.uri().path().to_owned();
    // While Go still runs it answers what is not served here: routes of
    // jobs Rust does not own yet (campaigns) and its API documentation.
    let api = path.starts_with("/api/") || path == "/api";
    let go_docs = path == "/api.json" || path == "/swagger" || path.starts_with("/swagger/");
    if (api || go_docs) && state.upstream.is_some() {
        return crate::proxy::forward(State(state), req).await;
    }
    if api {
        return ApiError::NotFound("not found".to_owned()).into_response();
    }
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::NOT_FOUND.into_response();
    }
    let [dist, html] = folders(&state);
    if let Some(rel) = relative(&path).filter(|r| !r.is_empty() && !r.ends_with('/')) {
        let caching = if rel.starts_with("static/") {
            Caching::Immutable
        } else {
            Caching::Revalidate
        };
        for dir in [&dist, &html] {
            if let Some(response) = file(&dir.join(rel), &method, req.headers(), caching).await {
                return response;
            }
        }
        // A missing asset is missing, not the console's page.
        if rel.starts_with("static/") {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    match file(
        &dist.join("index.html"),
        &method,
        req.headers(),
        Caching::Revalidate,
    )
    .await
    {
        Some(response) => response,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(
            relative("/static/js/app.1a2b.js"),
            Some("static/js/app.1a2b.js")
        );
        assert_eq!(relative("/"), Some(""));
        assert_eq!(relative("/../.env"), None);
        assert_eq!(relative("/static/%2e%2e/x"), None);
        assert_eq!(relative("/.env"), None);
        assert_eq!(relative("/a/.git/config"), None);
        assert_eq!(content_type(Path::new("x.WOFF2")), "font/woff2");
        assert_eq!(content_type(Path::new("noext")), "application/octet-stream");
    }
}
