//! Shared harness for the end-to-end tests: real PostgreSQL and Redis, a fake
//! Go upstream, and helpers to call the app like the console does.
//!
//! Tests run only when `FERROPOST_TEST_DATABASE_URL` and
//! `FERROPOST_TEST_REDIS_URL` are set (see `core-rs/README.md`). Each test
//! binary resets the schema, so keep one `#[tokio::test]` per file.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ferropost_api::access_log::AccessLog;
use ferropost_api::{AppState, ConnInfo};
use ferropost_common::{Config, EnvFile};
use ferropost_store::Store;
use fred::prelude::ClientLike;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

pub const SECRET_DB: &str = "dbpass";
pub const SECRET_REDIS: &str = "redispass";
pub const CLIENT: &str = "203.0.113.9:40000";

pub struct Harness {
    pub store: Store,
    pub upstream: String,
    pub root: tempfile::TempDir,
    /// Receives all mail the app sends.
    pub smtp: SmtpSink,
}

impl Harness {
    pub async fn start() -> Option<Self> {
        let (Ok(db), Ok(redis)) = (
            std::env::var("FERROPOST_TEST_DATABASE_URL"),
            std::env::var("FERROPOST_TEST_REDIS_URL"),
        ) else {
            eprintln!(
                "skipping e2e: FERROPOST_TEST_DATABASE_URL / FERROPOST_TEST_REDIS_URL not set"
            );
            return None;
        };

        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "warn".into()),
            )
            .with_test_writer()
            .try_init();
        let upstream = spawn_fake_go().await;
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join("core")).expect("core dir");
        let config = config(&root.path().join("core"), &upstream, &db, &redis, &[]);
        let store = Store::connect(&config).await.expect("connect");
        reset_schema(&store).await;
        Some(Self {
            store,
            upstream,
            root,
            smtp: SmtpSink::start().await,
        })
    }

    /// The core directory (`/opt/billionmail/core` in production). Paths such
    /// as `../logs/core` resolve inside the temporary directory.
    pub fn core_dir(&self) -> std::path::PathBuf {
        self.root.path().join("core")
    }

    /// A fresh app (fresh caches) with extra `.env` values.
    pub fn app(&self, env: &[(&str, &str)]) -> Router {
        ferropost_api::app(self.state(env))
    }

    /// The state behind [`Harness::app`], for starting background work.
    pub fn state(&self, env: &[(&str, &str)]) -> AppState {
        let db = std::env::var("FERROPOST_TEST_DATABASE_URL").expect("db url");
        let redis = std::env::var("FERROPOST_TEST_REDIS_URL").expect("redis url");
        let port = self.smtp.port.to_string();
        let mut extra = env.to_vec();
        extra.push(("FERROPOST_SMTP_PORT", &port));
        let config = config(&self.core_dir(), &self.upstream, &db, &redis, &extra);
        AppState::with_access_log(config, self.store.clone(), AccessLog::disabled()).expect("state")
    }
}

pub fn config(
    root: &Path,
    upstream: &str,
    db: &str,
    redis: &str,
    extra: &[(&str, &str)],
) -> Config {
    let mut env: HashMap<String, String> = HashMap::from([
        ("DBPASS".into(), SECRET_DB.into()),
        ("REDISPASS".into(), SECRET_REDIS.into()),
    ]);
    let mut vars: HashMap<&str, String> = HashMap::from([
        ("FERROPOST_DATABASE_URL", db.to_owned()),
        ("FERROPOST_REDIS_URL", redis.to_owned()),
        ("FERROPOST_GO_UPSTREAM", upstream.to_owned()),
        ("FERROPOST_SERVER_IP", "198.51.100.1".to_owned()),
        // Never reach the Docker daemon of the machine running the tests.
        ("FERROPOST_POSTFIX_CONTAINER", "none".to_owned()),
        ("FERROPOST_DOVECOT_CONTAINER", "none".to_owned()),
        ("FERROPOST_CORE_CONTAINER", "none".to_owned()),
        ("FERROPOST_RSPAMD_CONTAINER", "none".to_owned()),
        ("FERROPOST_DOCKER", "none".to_owned()),
        // Never reach Let's Encrypt.
        (
            "FERROPOST_ACME_DIRECTORY",
            "http://127.0.0.1:9/directory".to_owned(),
        ),
        // Mail goes to the harness's sink, or to a closed port: never to an
        // MTA that happens to listen on the test machine.
        ("FERROPOST_SMTP_HOST", "127.0.0.1".to_owned()),
        ("FERROPOST_SMTP_PORT", "9".to_owned()),
    ]);
    // `FERROPOST_*` values are process environment; the rest is `.env`.
    for (k, v) in extra {
        if k.starts_with("FERROPOST_") {
            vars.insert(k, (*v).to_owned());
        } else {
            env.insert((*k).into(), (*v).into());
        }
    }
    Config::from_sources(root.to_path_buf(), Arc::new(EnvFile::from_map(env)), |k| {
        vars.get(k).cloned()
    })
    .expect("config")
}

/// A message the sink accepted.
#[derive(Debug, Clone, Default)]
pub struct SinkMail {
    /// The `AUTH` user name.
    pub login: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub data: Vec<u8>,
}

/// A minimal SMTP server on a random local port that accepts any login
/// and keeps every message in memory, so tests check real submissions
/// without anything leaving the process.
#[derive(Clone)]
pub struct SmtpSink {
    pub port: u16,
    mails: Arc<std::sync::Mutex<Vec<SinkMail>>>,
}

impl SmtpSink {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind smtp sink");
        let sink = Self {
            port: listener.local_addr().expect("addr").port(),
            mails: Arc::default(),
        };
        let mails = sink.mails.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let mails = mails.clone();
                tokio::spawn(async move {
                    if let Err(err) = smtp_session(stream, mails).await {
                        eprintln!("smtp sink session: {err}");
                    }
                });
            }
        });
        sink
    }

    pub fn mails(&self) -> Vec<SinkMail> {
        self.mails.lock().expect("sink").clone()
    }
}

async fn smtp_session(
    stream: tokio::net::TcpStream,
    mails: Arc<std::sync::Mutex<Vec<SinkMail>>>,
) -> std::io::Result<()> {
    use base64::Engine;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut mail = SinkMail::default();
    let mut line = String::new();
    let path = |arg: &str| {
        let arg = arg.trim();
        arg.split_once('<')
            .and_then(|(_, rest)| rest.split_once('>'))
            .map_or(arg, |(addr, _)| addr)
            .to_owned()
    };
    write.write_all(b"220 sink ESMTP\r\n").await?;
    loop {
        line.clear();
        if read.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let command = line.trim_end().to_owned();
        let upper = command.to_ascii_uppercase();
        let answer = if upper.starts_with("EHLO") {
            "250-sink\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"
        } else if upper.starts_with("HELO") || upper == "NOOP" {
            "250 ok\r\n"
        } else if let Some(initial) = upper.strip_prefix("AUTH PLAIN ").map(|_| &command[11..]) {
            let plain = base64::engine::general_purpose::STANDARD
                .decode(initial.trim())
                .unwrap_or_default();
            let mut parts = plain.split(|b| *b == 0).skip(1);
            mail.login = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
            mail.password = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
            "235 ok\r\n"
        } else if upper.starts_with("MAIL FROM:") {
            mail.from = path(&command[10..]);
            "250 ok\r\n"
        } else if upper.starts_with("RCPT TO:") {
            mail.to.push(path(&command[8..]));
            "250 ok\r\n"
        } else if upper == "DATA" {
            write.write_all(b"354 go ahead\r\n").await?;
            let mut data = Vec::new();
            loop {
                line.clear();
                if read.read_line(&mut line).await? == 0 {
                    return Ok(());
                }
                if line == ".\r\n" {
                    break;
                }
                // Undo dot-stuffing.
                data.extend_from_slice(line.strip_prefix('.').unwrap_or(&line).as_bytes());
            }
            let login = (mail.login.clone(), mail.password.clone());
            let done = std::mem::take(&mut mail);
            mails.lock().expect("sink").push(SinkMail { data, ..done });
            (mail.login, mail.password) = login;
            "250 queued\r\n"
        } else if upper == "RSET" {
            mail.from.clear();
            mail.to.clear();
            "250 ok\r\n"
        } else if upper == "QUIT" {
            write.write_all(b"221 bye\r\n").await?;
            return Ok(());
        } else {
            "502 not implemented\r\n"
        };
        write.write_all(answer.as_bytes()).await?;
    }
}

/// Echoes what Go would receive, so the test can inspect forwarded headers.
pub async fn spawn_fake_go() -> String {
    async fn echo(req: Request) -> Response {
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        let body = json!({
            "go": true,
            "uri": req.uri().to_string(),
            "x_forwarded_for": header("x-forwarded-for"),
            "x_real_ip": header("x-real-ip"),
            "x_forwarded_proto": header("x-forwarded-proto"),
            "host": header("host"),
            "proxy_client_ip": header("proxy-client-ip"),
        });
        (
            [(header::SET_COOKIE, "billion_mail=sess; Path=/; HttpOnly")],
            axum::Json(body),
        )
            .into_response()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(echo))
            .await
            .expect("serve");
    });
    format!("http://{addr}")
}

pub async fn reset_schema(store: &Store) {
    // The real schema: the store's migrations on an empty database.
    for sql in ["DROP SCHEMA public CASCADE", "CREATE SCHEMA public"] {
        sqlx::query(sql).execute(&store.pg).await.expect(sql);
    }
    ferropost_store::migrate(&store.pg)
        .await
        .expect("migrations");
    let statements = [
        // Fixtures.
        "INSERT INTO account (account_id, username, password, email) VALUES
            (1, 'admin', 'x', 'a@example.com'), (2, 'viewer', 'x', 'v@example.com'),
            (3, 'nobody', 'x', 'n@example.com')",
        "INSERT INTO role (role_id, role_name) VALUES (1, 'admin'), (2, 'viewer'), (3, 'empty')",
        "INSERT INTO account_role (account_id, role_id) VALUES (1, 1), (2, 2), (3, 3)",
        "INSERT INTO permission (permission_id, permission_name, module, action, resource)
            VALUES (1, 'tags:read', 'tags', 'read', 'tags')",
        "INSERT INTO role_permission (role_id, permission_id) VALUES (2, 1)",
        "INSERT INTO bm_contact_groups (id, name) VALUES (1, 'Customers'), (2, 'Leads')",
        "INSERT INTO bm_tags (id, group_id, name, create_time) VALUES
            (1, 1, 'vip', 100), (2, 1, '50% off', 300), (3, 2, '50 off', 200),
            (4, 99, 'orphan', 50)",
    ];
    for sql in statements {
        sqlx::query(sql).execute(&store.pg).await.expect(sql);
    }
    sync_sequences(store).await;
    let _: () = store.redis.flushall(false).await.expect("flush redis");
}

/// Moves every serial sequence past the highest seeded ID, so inserts made
/// by the app (or a test) after explicit-ID fixtures do not collide.
pub async fn sync_sequences(store: &Store) {
    let tables: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns
          WHERE table_schema = 'public' AND column_default LIKE 'nextval(%'",
    )
    .fetch_all(&store.pg)
    .await
    .expect("serial columns");
    for (table, column) in tables {
        let sql = format!(
            "SELECT setval(pg_get_serial_sequence('{table}', '{column}'),
                           COALESCE((SELECT MAX({column}) FROM {table}), 0) + 1, false)"
        );
        sqlx::query(&sql).execute(&store.pg).await.expect("setval");
    }
}

pub fn token(account_id: i64, subject: &str, jti: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &json!({
            "accountId": account_id, "username": "u", "roles": null, "apiToken": subject == "api_token",
            "iss": "billion-mail", "sub": subject, "jti": jti,
            "exp": now + 600, "nbf": now - 5, "iat": now - 5
        }),
        &EncodingKey::from_secret(format!("{SECRET_DB}{SECRET_REDIS}").as_bytes()),
    )
    .expect("sign")
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

pub async fn call(app: &Router, uri: &str, headers: &[(&str, &str)], tls: bool) -> Reply {
    send(app, "GET", uri, headers, None, tls).await
}

/// POSTs a JSON body as the console does.
pub async fn post(app: &Router, uri: &str, auth: &str, body: Value) -> Reply {
    send(
        app,
        "POST",
        uri,
        &[("authorization", auth)],
        Some(body),
        false,
    )
    .await
}

/// POSTs an HTML form (`application/x-www-form-urlencoded`).
pub async fn post_form(app: &Router, uri: &str, form: &[(&str, &str)]) -> Reply {
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "console.example.com")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("request");
    req.extensions_mut().insert(ConnInfo {
        peer: CLIENT.parse::<SocketAddr>().expect("addr"),
        tls: false,
    });
    reply(app.clone().oneshot(req).await.expect("infallible")).await
}

pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    json_body: Option<Value>,
    tls: bool,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "console.example.com");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let body = match json_body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let mut req = builder.body(body).expect("request");
    req.extensions_mut().insert(ConnInfo {
        peer: CLIENT.parse::<SocketAddr>().expect("addr"),
        tls,
    });
    reply(app.clone().oneshot(req).await.expect("infallible")).await
}

async fn reply(response: Response) -> Reply {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    Reply {
        status,
        headers,
        body,
    }
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}
