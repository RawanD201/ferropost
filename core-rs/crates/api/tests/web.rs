//! The console's files and Roundcube: built assets cached, other files
//! revalidated, client-side routes answered with `index.html`, unknown API
//! routes with an envelope; Roundcube's scripts through a (fake) PHP-FPM
//! socket, its private folders refused.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use common::*;
use ferropost_api::ConnInfo;
use ferropost_api::fastcgi::{self, END_REQUEST, PARAMS, STDIN, STDOUT};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// What the fake PHP-FPM was sent.
#[derive(Default, Clone)]
struct Seen {
    params: Vec<(String, String)>,
    stdin: Vec<u8>,
}

fn decode_params(mut data: &[u8]) -> Vec<(String, String)> {
    let length = |data: &mut &[u8]| -> usize {
        if data[0] & 0x80 == 0 {
            let n = usize::from(data[0]);
            *data = &data[1..];
            n
        } else {
            let n = u32::from_be_bytes([data[0] & 0x7f, data[1], data[2], data[3]]) as usize;
            *data = &data[4..];
            n
        }
    };
    let mut pairs = Vec::new();
    while !data.is_empty() {
        let (n, v) = (length(&mut data), length(&mut data));
        let name = String::from_utf8_lossy(&data[..n]).into_owned();
        let value = String::from_utf8_lossy(&data[n..n + v]).into_owned();
        data = &data[n + v..];
        pairs.push((name, value));
    }
    pairs
}

/// Answers one request with a redirect, two cookies and a body sent in two
/// parts.
async fn fake_php_fpm(socket: std::path::PathBuf, seen: Arc<Mutex<Seen>>) {
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind socket");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut params = Vec::new();
                loop {
                    let Ok(Some(record)) = fastcgi::read_record(&mut stream).await else {
                        return;
                    };
                    match record.kind {
                        PARAMS => params.extend_from_slice(&record.content),
                        STDIN if record.content.is_empty() => break,
                        STDIN => seen
                            .lock()
                            .expect("lock")
                            .stdin
                            .extend_from_slice(&record.content),
                        _ => {}
                    }
                }
                seen.lock().expect("lock").params = decode_params(&params);
                let mut out = fastcgi::record(
                    STDOUT,
                    b"Status: 302 Found\r\nLocation: /roundcube/?_task=mail\r\nSet-Cookie: roundcube_sessid=abc; path=/\r\nSet-Cookie: a=b\r\nContent-Type: text/html\r\n\r\n<html>",
                );
                out.extend(fastcgi::record(STDOUT, b"hi</html>"));
                out.extend(fastcgi::record(STDOUT, &[]));
                out.extend(fastcgi::record(END_REQUEST, &[0; 8]));
                let _ = stream.write_all(&out).await;
            });
        }
    });
}

async fn raw(
    app: &axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "console.example.com:8443");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let mut req = builder.body(Body::from(body.to_owned())).expect("request");
    req.extensions_mut().insert(ConnInfo {
        peer: CLIENT.parse().expect("addr"),
        tls: true,
    });
    let response = app.clone().oneshot(req).await.expect("infallible");
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("body").to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn web() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let public = h.core_dir().join("public");
    std::fs::create_dir_all(public.join("dist/static/js")).expect("dist");
    std::fs::create_dir_all(public.join("html")).expect("html");
    std::fs::write(
        public.join("dist/index.html"),
        "<!doctype html><div id=app></div>",
    )
    .expect("index");
    std::fs::write(public.join("dist/static/js/app.1a2b.js"), "console.log(1)").expect("js");
    std::fs::write(public.join("html/unsubscribe.html"), "<p>unsubscribe</p>").expect("html");
    std::fs::write(h.root.path().join(".env"), "SECRET=1").expect("env");
    let app = h.app(&[]);

    // --- Console files --------------------------------------------------------------------------
    let (status, headers, body) = raw(&app, "GET", "/", &[], "").await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "<!doctype html><div id=app></div>")
    );
    assert_eq!(headers["cache-control"], "no-cache");
    let etag = headers["etag"].to_str().expect("etag").to_owned();
    let (status, _, body) = raw(&app, "GET", "/", &[("if-none-match", &etag)], "").await;
    assert_eq!((status, body.as_str()), (StatusCode::NOT_MODIFIED, ""));
    let (status, headers, body) = raw(&app, "GET", "/static/js/app.1a2b.js", &[], "").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "console.log(1)"));
    assert_eq!(headers["content-type"], "text/javascript; charset=utf-8");
    assert_eq!(
        headers["cache-control"],
        "public, max-age=31536000, immutable"
    );
    let (status, _, _) = raw(&app, "GET", "/static/js/gone.js", &[], "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a missing asset is not the console page"
    );
    let (_, _, body) = raw(&app, "GET", "/unsubscribe.html", &[], "").await;
    assert_eq!(body, "<p>unsubscribe</p>");
    for route in [
        "/dashboard",
        "/settings/ai-model",
        "/../.env",
        "/%2e%2e/.env",
    ] {
        let (status, _, body) = raw(&app, "GET", route, &[], "").await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "<!doctype html><div id=app></div>"),
            "{route}"
        );
    }
    let (status, headers, body) = raw(&app, "HEAD", "/", &[], "").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, ""));
    assert_eq!(headers["content-length"], "33");
    let (status, _, _) = raw(&app, "POST", "/dashboard", &[], "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let r = call(&app, "/api/no/such/route", &[], false).await;
    assert_eq!(r.body["go"], true, "Go answers while it runs");
    let r = call(&app, "/swagger", &[], false).await;
    assert_eq!(r.body["go"], true, "Go's API docs while Go runs");
    let without_go = h.app(&[("FERROPOST_GO_UPSTREAM", "none")]);
    let r = call(&without_go, "/api/no/such/route", &[], false).await;
    assert_eq!(r.body["code"], 404, "{}", r.body);
    let (status, _, body) = raw(&without_go, "GET", "/swagger", &[], "").await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "<!doctype html><div id=app></div>"),
        "the console page, as Go answered with its docs off"
    );

    // --- Roundcube ---------------------------------------------------------------------------------
    let webmail = h.root.path().join("webmail-data");
    std::fs::create_dir_all(webmail.join("skins")).expect("skins");
    std::fs::create_dir_all(webmail.join("logs")).expect("logs");
    std::fs::write(webmail.join("skins/app.css"), "body{}").expect("css");
    std::fs::write(webmail.join("logs/errors.log"), "secret session").expect("log");
    let socket = h.root.path().join("php.sock");
    let seen = Arc::new(Mutex::new(Seen::default()));
    fake_php_fpm(socket.clone(), seen.clone()).await;
    let socket_path = socket.display().to_string();
    let app = h.app(&[("FERROPOST_PHP_FPM_SOCKET", &socket_path)]);

    let (status, headers, body) = raw(
        &app,
        "POST",
        "/roundcube/?_task=login",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("proxy", "http://attacker.test:3128"),
            ("user-agent", "TestBrowser/1.0"),
        ],
        "_user=alice&_pass=secret",
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(headers["location"], "/roundcube/?_task=mail");
    assert_eq!(
        headers.get_all("set-cookie").iter().count(),
        2,
        "both cookies"
    );
    assert_eq!(body, "<html>hi</html>");
    let seen = seen.lock().expect("lock").clone();
    let param = |name: &str| {
        seen.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        param("SCRIPT_FILENAME").as_deref(),
        Some("/var/www/html/index.php")
    );
    assert_eq!(
        param("REQUEST_URI").as_deref(),
        Some("/roundcube/?_task=login")
    );
    assert_eq!(param("QUERY_STRING").as_deref(), Some("_task=login"));
    assert_eq!(param("REQUEST_METHOD").as_deref(), Some("POST"));
    assert_eq!(
        param("CONTENT_TYPE").as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        param("REMOTE_ADDR").as_deref(),
        Some("203.0.113.9"),
        "the visitor (Go passed 127.0.0.1)"
    );
    assert_eq!(param("SERVER_NAME").as_deref(), Some("console.example.com"));
    assert_eq!(param("HTTPS").as_deref(), Some("on"));
    assert_eq!(param("HTTP_USER_AGENT").as_deref(), Some("TestBrowser/1.0"));
    assert_eq!(param("HTTP_PROXY"), None, "httpoxy");
    assert_eq!(seen.stdin, b"_user=alice&_pass=secret");

    let (status, _, body) = raw(&app, "GET", "/roundcube/skins/app.css", &[], "").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "body{}"));
    for private in [
        "/roundcube/logs/errors.log",
        "/roundcube/config/config.inc.php",
        "/roundcube/.htaccess",
        "/roundcube/../.env",
    ] {
        let (status, _, body) = raw(&app, "GET", private, &[], "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{private}");
        assert!(!body.contains("secret"), "{private}");
    }
    let offline = h.app(&[("FERROPOST_PHP_FPM_SOCKET", "/nonexistent/php.sock")]);
    let (status, _, _) = raw(&offline, "GET", "/roundcube/", &[], "").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}
