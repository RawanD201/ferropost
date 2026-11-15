//! End-to-end test of the HTTP layer against real PostgreSQL and Redis and a
//! fake Go upstream.
//!
//! Runs only when `BM_TEST_DATABASE_URL` and `BM_TEST_REDIS_URL` are set
//! (see `core-rs/README.md`). The database is reset on every run.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bm_api::access_log::AccessLog;
use bm_api::{AppState, ConnInfo};
use bm_common::{Config, EnvFile};
use bm_store::Store;
use fred::prelude::{ClientLike, KeysInterface};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET_DB: &str = "dbpass";
const SECRET_REDIS: &str = "redispass";
const CLIENT: &str = "203.0.113.9:40000";

struct Harness {
    store: Store,
    upstream: String,
    root: tempfile::TempDir,
}

impl Harness {
    async fn start() -> Option<Self> {
        let (Ok(db), Ok(redis)) = (
            std::env::var("BM_TEST_DATABASE_URL"),
            std::env::var("BM_TEST_REDIS_URL"),
        ) else {
            eprintln!("skipping e2e: BM_TEST_DATABASE_URL / BM_TEST_REDIS_URL not set");
            return None;
        };

        let upstream = spawn_fake_go().await;
        let root = tempfile::tempdir().expect("tempdir");
        let config = config(root.path(), &upstream, &db, &redis, &[]);
        let store = Store::connect(&config).await.expect("connect");
        reset_schema(&store).await;
        Some(Self {
            store,
            upstream,
            root,
        })
    }

    /// A fresh app (fresh caches) with extra `.env` values.
    fn app(&self, env: &[(&str, &str)]) -> Router {
        let db = std::env::var("BM_TEST_DATABASE_URL").expect("db url");
        let redis = std::env::var("BM_TEST_REDIS_URL").expect("redis url");
        let config = config(self.root.path(), &self.upstream, &db, &redis, env);
        let state = AppState::with_access_log(config, self.store.clone(), AccessLog::disabled())
            .expect("state");
        bm_api::app(state)
    }
}

fn config(root: &Path, upstream: &str, db: &str, redis: &str, extra: &[(&str, &str)]) -> Config {
    let mut env: HashMap<String, String> = HashMap::from([
        ("DBPASS".into(), SECRET_DB.into()),
        ("REDISPASS".into(), SECRET_REDIS.into()),
    ]);
    env.extend(extra.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    let vars: HashMap<&str, String> = HashMap::from([
        ("BM_DATABASE_URL", db.to_owned()),
        ("BM_REDIS_URL", redis.to_owned()),
        ("BM_GO_UPSTREAM", upstream.to_owned()),
        ("BM_SERVER_IP", "198.51.100.1".to_owned()),
    ]);
    Config::from_sources(root.to_path_buf(), Arc::new(EnvFile::from_map(env)), |k| {
        vars.get(k).cloned()
    })
    .expect("config")
}

/// Echoes what Go would receive, so the test can inspect forwarded headers.
async fn spawn_fake_go() -> String {
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

async fn reset_schema(store: &Store) {
    let statements = [
        "DROP TABLE IF EXISTS role_permission, account_role, permission, role, account,
             bm_tags, bm_contact_groups, bm_options, bm_console_ip_whitelist CASCADE",
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
            update_time INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()))",
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
    let _: () = store.redis.flushall(false).await.expect("flush redis");
}

fn token(account_id: i64, subject: &str, jti: &str) -> String {
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

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn call(app: &Router, uri: &str, headers: &[(&str, &str)], tls: bool) -> Reply {
    let mut builder = Request::builder()
        .uri(uri)
        .header("host", "console.example.com");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let mut req = builder.body(Body::empty()).expect("request");
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

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn end_to_end() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-1"));

    // --- authentication -------------------------------------------------
    let r = call(&app, "/api/tags/list", &[], false).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body,
        json!({"success": false, "code": 401, "msg": "no authorization", "data": null})
    );

    let refresh = bearer(&token(1, "refresh_token", "r-1"));
    let r = call(
        &app,
        "/api/tags/list",
        &[("authorization", &refresh)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 401, "refresh tokens are not access tokens");

    // --- tags/list as admin ---------------------------------------------
    let r = call(&app, "/api/tags/list", &[("authorization", &admin)], false).await;
    assert_eq!(r.body["success"], true);
    assert_eq!(r.body["code"], 0);
    assert_eq!(r.body["msg"], "Get tag list successfully");
    assert_eq!(r.body["data"]["total"], 4);
    let names: Vec<&str> = r.body["data"]["list"]
        .as_array()
        .expect("list")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        ["50% off", "50 off", "vip", "orphan"],
        "create_time DESC"
    );
    assert_eq!(r.body["data"]["list"][3]["group_name"], "Unknown");
    assert_eq!(r.body["data"]["list"][0]["group_name"], "Customers");

    // Keyword is matched literally: "%" is not a wildcard.
    let r = call(
        &app,
        "/api/tags/list?keyword=50%25",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 1);
    assert_eq!(r.body["data"]["list"][0]["name"], "50% off");

    let r = call(
        &app,
        "/api/tags/list?group_id=1&page=2&page_size=1",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 2);
    assert_eq!(r.body["data"]["list"][0]["name"], "vip");

    let r = call(
        &app,
        "/api/tags/list?group_id=&keyword=",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 4, "empty params mean no filter");

    let r = call(
        &app,
        "/api/tags/list?group_id=-1",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 412);

    let r = call(&app, "/api/tags/all", &[("authorization", &admin)], false).await;
    assert_eq!(r.body["data"]["total"], 4);

    // --- RBAC -----------------------------------------------------------
    let viewer = bearer(&token(2, "access_token", "viewer-1"));
    let r = call(&app, "/api/tags/list", &[("authorization", &viewer)], false).await;
    assert_eq!(r.body["code"], 0, "viewer has tags:read");
    let r = call(&app, "/api/tags/all", &[("authorization", &viewer)], false).await;
    assert_eq!(r.body["code"], 403, "tags/all needs action 'all'");

    let nobody = bearer(&token(3, "access_token", "nobody-1"));
    let r = call(&app, "/api/tags/list", &[("authorization", &nobody)], false).await;
    assert_eq!(
        r.body,
        json!({"success": false, "code": 403, "msg": "Insufficient permissions", "data": null})
    );

    // --- revocation -----------------------------------------------------
    let _: () = h
        .store
        .redis
        .set("JWT_BLACK_LIST:viewer-1", 0, None, None, false)
        .await
        .expect("revoke");
    let r = call(&app, "/api/tags/list", &[("authorization", &viewer)], false).await;
    assert_eq!(r.body["code"], 401, "revoked token");

    // --- i18n -----------------------------------------------------------
    let lang_dir = h.root.path().join("languages/zh");
    std::fs::create_dir_all(&lang_dir).expect("mkdir");
    std::fs::write(
        lang_dir.join("server.json"),
        json!({ md5_hex("Get tag list successfully"): "获取标签列表成功" }).to_string(),
    )
    .expect("write pack");
    let r = call(
        &h.app(&[]),
        "/api/tags/list?lang=zh-CN",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "获取标签列表成功");

    // --- proxy to Go ----------------------------------------------------
    let r = call(
        &app,
        "/api/domains/list?page=1",
        &[
            ("authorization", &admin),
            ("x-forwarded-for", "127.0.0.1"),
            ("proxy-client-ip", "127.0.0.1"),
        ],
        true,
    )
    .await;
    assert_eq!(r.body["go"], true);
    assert_eq!(r.body["uri"], "/api/domains/list?page=1");
    assert_eq!(
        r.body["x_forwarded_for"], "203.0.113.9",
        "spoofed XFF replaced"
    );
    assert_eq!(r.body["x_real_ip"], "203.0.113.9");
    assert_eq!(r.body["proxy_client_ip"], "");
    assert_eq!(r.body["x_forwarded_proto"], "https");
    assert_eq!(r.body["host"], "console.example.com");
    assert_eq!(
        r.headers[header::SET_COOKIE],
        "billion_mail=sess; Path=/; HttpOnly; Secure"
    );

    // --- safe entrance --------------------------------------------------
    let gated = h.app(&[("SafePath", "/s3cret")]);
    let r = call(
        &gated,
        "/api/tags/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(
        r.body,
        json!({"success": false, "code": 404, "msg": "access denied", "data": null})
    );
    let r = call(&gated, "/", &[], false).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = call(&gated, "/pmta/open/abc", &[], false).await;
    assert_eq!(r.body["go"], true, "tracking links stay public");
    let r = call(&gated, "/api/unsubscribe", &[], false).await;
    assert_eq!(r.body["go"], true, "unsubscribe stays public");

    let api_token = bearer(&token(1, "api_token", "api-1"));
    let r = call(
        &gated,
        "/api/tags/list",
        &[("authorization", &api_token)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "API tokens skip the entrance");

    let r = call(&gated, "/s3cret", &[], true).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.headers[header::LOCATION], "/");
    let set_cookie = r.headers[header::SET_COOKIE].to_str().expect("cookie");
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("Secure"));
    let cookie = set_cookie.split(';').next().expect("pair").to_owned();
    let r = call(
        &gated,
        "/api/tags/list",
        &[("authorization", &admin), ("cookie", &cookie)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "entrance cookie opens the console");

    // --- IP whitelist ---------------------------------------------------
    let listed = h.app(&[("IP_WHITELIST_ENABLE", "true")]);
    let r = call(
        &listed,
        "/api/tags/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.body, "IP not allowed");
    let r = call(&listed, "/api/unsubscribe", &[], false).await;
    assert_eq!(r.body["go"], true, "public paths bypass the whitelist");

    sqlx::query("INSERT INTO bm_console_ip_whitelist (ip) VALUES ('203.0.113.0/24')")
        .execute(&h.store.pg)
        .await
        .expect("insert");
    let listed = h.app(&[("IP_WHITELIST_ENABLE", "true")]);
    let r = call(
        &listed,
        "/api/tags/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "CIDR entry allows the client");

    // --- base path ------------------------------------------------------
    let based = h.app(&[("WEB_BASE_PATH", "/billionmail")]);
    let r = call(
        &based,
        "/billionmail/api/tags/all",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0);
    let r = call(&based, "/billionmail/api/domains/list", &[], false).await;
    assert_eq!(
        r.body["uri"], "/api/domains/list",
        "Go receives the stripped path"
    );

    // --- Go unavailable -------------------------------------------------
    let config = {
        let db = std::env::var("BM_TEST_DATABASE_URL").expect("db");
        let redis = std::env::var("BM_TEST_REDIS_URL").expect("redis");
        config(h.root.path(), "http://127.0.0.1:9", &db, &redis, &[])
    };
    let down = bm_api::app(
        AppState::with_access_log(config, h.store.clone(), AccessLog::disabled()).expect("state"),
    );
    let r = call(
        &down,
        "/api/domains/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 503);
    let r = call(&down, "/dashboard", &[], false).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
}

fn md5_hex(input: &str) -> String {
    use md5::{Digest, Md5};
    hex::encode(Md5::digest(input.as_bytes()))
}
