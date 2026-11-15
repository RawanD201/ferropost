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
        })
    }

    /// The core directory (`/opt/billionmail/core` in production). Paths such
    /// as `../logs/core` resolve inside the temporary directory.
    pub fn core_dir(&self) -> std::path::PathBuf {
        self.root.path().join("core")
    }

    /// A fresh app (fresh caches) with extra `.env` values.
    pub fn app(&self, env: &[(&str, &str)]) -> Router {
        let db = std::env::var("FERROPOST_TEST_DATABASE_URL").expect("db url");
        let redis = std::env::var("FERROPOST_TEST_REDIS_URL").expect("redis url");
        let config = config(&self.core_dir(), &self.upstream, &db, &redis, env);
        let state = AppState::with_access_log(config, self.store.clone(), AccessLog::disabled())
            .expect("state");
        ferropost_api::app(state)
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
    env.extend(extra.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    let vars: HashMap<&str, String> = HashMap::from([
        ("FERROPOST_DATABASE_URL", db.to_owned()),
        ("FERROPOST_REDIS_URL", redis.to_owned()),
        ("FERROPOST_GO_UPSTREAM", upstream.to_owned()),
        ("FERROPOST_SERVER_IP", "198.51.100.1".to_owned()),
        // Never reach the Docker daemon of the machine running the tests.
        ("FERROPOST_POSTFIX_CONTAINER", "none".to_owned()),
    ]);
    Config::from_sources(root.to_path_buf(), Arc::new(EnvFile::from_map(env)), |k| {
        vars.get(k).cloned()
    })
    .expect("config")
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
    let statements = [
        "DROP TABLE IF EXISTS role_permission, account_role, permission, role, account,
             bm_contact_tags, bm_contacts, bm_tags, bm_contact_groups, bm_options,
             bm_console_ip_whitelist, bm_operation_logs, email_templates, email_tasks,
             mailstat_message_ids, mailstat_opened, mailstat_clicked, mailstat_send_mails,
             mailstat_senders, mailstat_deferred_mails, recipient_info CASCADE",
        // DDL copied from core/internal/service/database_initialization.
        "CREATE TABLE account (
            account_id SERIAL PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
            status INT NOT NULL DEFAULT 1, language VARCHAR(50) NOT NULL DEFAULT 'en',
            last_login_time INT NOT NULL DEFAULT 0,
            create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()))",
        "CREATE TABLE role (
            role_id SERIAL PRIMARY KEY, role_name VARCHAR(64) NOT NULL UNIQUE,
            description TEXT, status INT NOT NULL DEFAULT 1,
            create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()))",
        "CREATE TABLE permission (
            permission_id SERIAL PRIMARY KEY, permission_name VARCHAR(64) NOT NULL UNIQUE,
            description TEXT, module VARCHAR(64) NOT NULL, action VARCHAR(64) NOT NULL,
            resource VARCHAR(64) NOT NULL, status INT NOT NULL DEFAULT 1,
            create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            update_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            UNIQUE(module, action, resource))",
        "CREATE TABLE account_role (
            id SERIAL PRIMARY KEY, account_id INT NOT NULL, role_id INT NOT NULL,
            create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            UNIQUE(account_id, role_id),
            FOREIGN KEY (account_id) REFERENCES account(account_id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE)",
        "CREATE TABLE role_permission (
            id SERIAL PRIMARY KEY, role_id INT NOT NULL, permission_id INT NOT NULL,
            create_time INT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            UNIQUE(role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permission(permission_id) ON DELETE CASCADE)",
        "CREATE TABLE bm_contact_groups (
            id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, description TEXT,
            create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            token VARCHAR(30) NOT NULL DEFAULT '', double_optin SMALLINT NOT NULL DEFAULT 0,
            welcome_mail_html TEXT DEFAULT '', welcome_mail_drag TEXT DEFAULT '',
            confirm_mail_html TEXT DEFAULT '', confirm_mail_drag TEXT DEFAULT '',
            success_url TEXT DEFAULT '', confirm_url TEXT DEFAULT '', already_url TEXT DEFAULT '',
            subscribe_form TEXT DEFAULT '', confirm_subject TEXT DEFAULT '',
            welcome_subject TEXT DEFAULT '', send_welcome_email SMALLINT NOT NULL DEFAULT 0,
            unsubscribe_mail_html TEXT DEFAULT '', unsubscribe_mail_drag TEXT DEFAULT '',
            unsubscribe_subject TEXT DEFAULT 'You''re unsubscribed',
            unsubscribe_redirect_url TEXT DEFAULT '',
            send_unsubscribe_email SMALLINT NOT NULL DEFAULT 0,
            UNIQUE(name))",
        "CREATE TABLE bm_contacts (
            id SERIAL PRIMARY KEY, email VARCHAR(320) NOT NULL, group_id INTEGER,
            active INTEGER DEFAULT 1, task_id INTEGER DEFAULT 0,
            create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            status INTEGER DEFAULT 0, attribs JSONB DEFAULT '{}'::jsonb,
            last_active_at INTEGER DEFAULT 0,
            FOREIGN KEY (group_id) REFERENCES bm_contact_groups(id) ON DELETE SET NULL,
            UNIQUE(group_id, email))",
        "CREATE TABLE bm_contact_tags (
            id SERIAL PRIMARY KEY, contact_id INTEGER NOT NULL, tag_id INTEGER NOT NULL,
            create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            UNIQUE(contact_id, tag_id))",
        "CREATE TABLE email_templates (
            id SERIAL PRIMARY KEY, temp_name VARCHAR(255), chat_id VARCHAR(255),
            add_type SMALLINT NOT NULL DEFAULT 0, content TEXT NOT NULL DEFAULT '',
            render TEXT NOT NULL DEFAULT '',
            create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            UNIQUE(temp_name))",
        // Only the columns Rust reads so far.
        "CREATE TABLE email_tasks (id SERIAL PRIMARY KEY, group_id INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE mailstat_message_ids (postfix_message_id TEXT PRIMARY KEY,
            log_time_millis BIGINT NOT NULL DEFAULT 0,
            log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
            message_id TEXT NOT NULL DEFAULT '')",
        "CREATE TABLE recipient_info (id SERIAL PRIMARY KEY, task_id INTEGER NOT NULL,
            recipient VARCHAR(320) NOT NULL, message_id TEXT NOT NULL)",
        "CREATE TABLE mailstat_send_mails (postfix_message_id TEXT PRIMARY KEY,
            log_time_millis BIGINT NOT NULL DEFAULT 0,
            log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
            status TEXT NOT NULL DEFAULT '', recipient TEXT NOT NULL DEFAULT '',
            mail_provider TEXT NOT NULL DEFAULT '', delay REAL NOT NULL DEFAULT 0,
            delays TEXT NOT NULL DEFAULT '', dsn TEXT NOT NULL DEFAULT '',
            relay TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '')",
        "CREATE TABLE mailstat_senders (postfix_message_id TEXT PRIMARY KEY,
            log_time_millis BIGINT NOT NULL DEFAULT 0,
            log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
            size INTEGER NOT NULL DEFAULT 0, sender TEXT NOT NULL DEFAULT '')",
        "CREATE TABLE mailstat_deferred_mails (id SERIAL PRIMARY KEY,
            postfix_message_id TEXT NOT NULL DEFAULT '', log_time_millis BIGINT NOT NULL DEFAULT 0,
            log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
            delay REAL NOT NULL DEFAULT 0, delays TEXT NOT NULL DEFAULT '',
            dsn TEXT NOT NULL DEFAULT '', relay TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '')",
        "CREATE TABLE mailstat_opened (id SERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL DEFAULT 0,
            log_time_millis BIGINT NOT NULL DEFAULT 0,
            log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
            recipient TEXT NOT NULL DEFAULT '', postfix_message_id TEXT NOT NULL DEFAULT '',
            message_id TEXT NOT NULL DEFAULT '')",
        "CREATE TABLE mailstat_clicked (id SERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL DEFAULT 0,
            log_time_millis BIGINT NOT NULL DEFAULT 0,
            log_time INTEGER GENERATED ALWAYS AS (log_time_millis / 1000) STORED,
            recipient TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '',
            postfix_message_id TEXT NOT NULL DEFAULT '', message_id TEXT NOT NULL DEFAULT '')",
        "CREATE TABLE bm_operation_logs (
            id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL DEFAULT 0, type VARCHAR(64) NOT NULL,
            log TEXT NOT NULL, ip VARCHAR(64) NOT NULL, info TEXT NOT NULL,
            addtime INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()))",
        "CREATE TABLE bm_tags (
            id SERIAL PRIMARY KEY, group_id INTEGER NOT NULL, name VARCHAR(100) NOT NULL,
            create_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()),
            UNIQUE(group_id, name))",
        "CREATE TABLE bm_options (name VARCHAR(255) NOT NULL PRIMARY KEY, value TEXT NOT NULL)",
        "CREATE TABLE bm_console_ip_whitelist (
            id SERIAL PRIMARY KEY, ip varchar(45) NOT NULL, ip_type smallint NOT NULL DEFAULT 1,
            create_time int NOT NULL default 0, UNIQUE (ip))",
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
    let response = app.clone().oneshot(req).await.expect("infallible");
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
