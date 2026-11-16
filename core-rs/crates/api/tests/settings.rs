//! Settings: the system config without secrets, `.env` keys (the admin
//! login applied to its account, host-only keys refused), the IP whitelist
//! and its lock-out guard, the console certificate, API token revocation,
//! the reverse-proxy check, the alert mailbox with its test mail, the
//! Docker routes with Docker switched off, and the safe entrance going live.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use common::*;
use serde_json::{Value, json};

async fn config(app: &Router, auth: &str) -> Value {
    let r = call(
        app,
        "/api/settings/get_system_config",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    r.body["data"].clone()
}

async fn set_key(app: &Router, auth: &str, key: &str, value: Value) -> Value {
    post(
        app,
        "/api/settings/set_system_config_key",
        auth,
        json!({"key": key, "value": value}),
    )
    .await
    .body
}

fn cert(cn: &str) -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec![cn.to_owned()]).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    (cert.pem(), key.serialize_pem())
}

/// A stand-in console behind a reverse proxy: `/api/languages/get` answers
/// code 0, the same path under `/bad` answers code 5.
async fn proxy_target() -> String {
    let app = Router::new()
        .route(
            "/api/languages/get",
            get(|| async { axum::Json(json!({"code": 0})) }),
        )
        .route(
            "/bad/api/languages/get",
            get(|| async { axum::Json(json!({"code": 5})) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

async fn audit_text(h: &Harness) -> String {
    sqlx::query_scalar("SELECT COALESCE(string_agg(log, ' | '), '') FROM bm_operation_logs")
        .fetch_one(&h.store.pg)
        .await
        .expect("logs")
}

#[tokio::test]
async fn settings() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let ssl_dir = h.root.path().join("ssl");
    let ssl = ssl_dir.display().to_string();
    let old_token = token(1, "api_token", "api-old");
    for sql in [
        "INSERT INTO permission (permission_id, permission_name, module, action, resource) VALUES
            (10, 'settings:get', 'settings', 'get_system_config', 'settings'),
            (11, 'settings:key', 'settings', 'set_system_config_key', 'settings'),
            (12, 'settings:token', 'settings', 'regenerate_api_token', 'settings')",
        "INSERT INTO role_permission (role_id, permission_id) VALUES (2, 10), (2, 11), (2, 12)",
    ] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    sqlx::query("INSERT INTO bm_options (name, value) VALUES ('API_TOKEN', $1)")
        .bind(&old_token)
        .execute(pg)
        .await
        .expect("token");
    let app = h.app(&[
        ("ADMIN_USERNAME", "admin"),
        ("ADMIN_PASSWORD", "Old-pass1"),
        ("DBNAME", "billionmail"),
        ("HTTPS_PORT", "443"),
        ("TZ", "UTC"),
        ("FERROPOST_SSL_DIR", &ssl),
    ]);
    let admin = bearer(&token(1, "access_token", "admin-settings"));
    let auth = admin.as_str();
    let viewer = bearer(&token(2, "access_token", "viewer-settings"));

    // --- Reading ----------------------------------------------------------------
    let r = call(
        &app,
        "/api/settings/get_version",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(
        (
            r.body["data"]["version"].clone(),
            r.body["data"]["can_update"].clone()
        ),
        (json!("0.1"), json!(false))
    );
    let c = config(&app, auth).await;
    assert_eq!(c["admin_username"], "admin");
    for secret in ["admin_password", "db_pass", "redis_pass"] {
        assert_eq!(c[secret], "", "{secret} is never sent");
    }
    assert_eq!(c["db_name"], "billionmail");
    assert_eq!(
        (c["ssl"]["status"].clone(), c["ssl"]["privateKey"].clone()),
        (json!(false), json!(""))
    );
    assert_eq!(c["api_doc_swagger"]["api_token"], old_token.as_str());
    assert_eq!(c["blacklist_config"]["auto_scan_enabled"], true);
    assert_eq!(
        c["blacklist_config"]["alert_settings"]["recipient_list"],
        json!([])
    );
    assert!(
        c["manage_ports"]["command_https"]
            .as_str()
            .is_some_and(|cmd| cmd.ends_with("| bash bm.sh change-port")),
        "{}",
        c["manage_ports"]
    );
    assert_eq!(c["manage_ports"]["https"], 443);
    assert_eq!(c["mail_ports"]["smtp"], 0, "unset ports stay 0, as in Go");
    let r = call(
        &app,
        "/api/settings/get_timezone_list",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert!(r.body["data"].is_object(), "{}", r.body);

    // The API token is for admins only.
    let c = config(&app, &viewer).await;
    assert_eq!(c["api_doc_swagger"]["api_token"], "");
    assert_eq!(
        set_key(&app, &viewer, "admin_password", json!("Viewer-pw1")).await["code"],
        403
    );
    let r = post(
        &app,
        "/api/settings/regenerate_api_token",
        &viewer,
        json!({}),
    )
    .await;
    assert_eq!(r.body["code"], 403);

    // --- `.env` keys --------------------------------------------------------------
    let r = set_key(&app, auth, "https", json!("8443")).await;
    assert!(
        r["msg"].as_str().is_some_and(|m| m.contains("bm.sh")),
        "ports only change with bm.sh: {r}"
    );
    assert_eq!(
        set_key(&app, auth, "nope", json!("x")).await["msg"],
        "Invalid configuration item or value not changed"
    );
    let r = set_key(&app, auth, "admin_password", json!("pass word")).await;
    assert_eq!(
        (r["code"].clone(), r["msg"].clone()),
        (
            json!(412),
            json!("Parameter validation failed: configuration value contains illegal characters")
        ),
        "a space would run the rest as a command under `source .env`"
    );
    let r = set_key(&app, auth, "admin_password", json!("New-pass1")).await;
    assert_eq!(r["code"], 0, "{r}");
    let hash: String = sqlx::query_scalar("SELECT password FROM account WHERE account_id = 1")
        .fetch_one(pg)
        .await
        .expect("hash");
    assert!(
        pwhash::bcrypt::verify("New-pass1", &hash),
        "applied to the account at once"
    );
    assert_eq!(
        set_key(&app, auth, "admin_password", json!("New-pass1")).await["msg"],
        "Invalid configuration item or value not changed"
    );
    assert_eq!(
        set_key(&app, auth, "admin_username", json!("viewer")).await["code"],
        409
    );
    assert_eq!(
        set_key(&app, auth, "admin_username", json!("chief_1")).await["code"],
        0
    );
    let name: String = sqlx::query_scalar("SELECT username FROM account WHERE account_id = 1")
        .fetch_one(pg)
        .await
        .expect("name");
    assert_eq!(name, "chief_1");
    assert_eq!(
        set_key(&app, auth, "retention_days", json!(30)).await["code"],
        0
    );
    assert_eq!(
        set_key(
            &app,
            auth,
            "billionmail_hostname",
            json!("Mail.Example.TEST")
        )
        .await["code"],
        0
    );
    let c = config(&app, auth).await;
    assert_eq!(
        (
            c["admin_username"].clone(),
            c["retention_days"].clone(),
            c["billionmail_hostname"].clone()
        ),
        (json!("chief_1"), json!(30), json!("mail.example.test"))
    );
    let logs = audit_text(&h).await;
    assert!(logs.contains("ADMIN_PASSWORD changed to ******"), "{logs}");
    assert!(!logs.contains("New-pass1"), "no password in the audit log");

    // --- IP whitelist ---------------------------------------------------------------
    assert_eq!(
        set_key(&app, auth, "ip_whitelist_enable", json!("true")).await["msg"],
        "IP whitelist list is empty. Whitelist function cannot be enabled"
    );
    let add = |ip: &'static str| {
        let app = app.clone();
        async move {
            post(
                &app,
                "/api/settings/add_ip_whitelist",
                auth,
                json!({"ip": ip}),
            )
            .await
            .body
        }
    };
    assert_eq!(add("nope").await["msg"], "Invalid IP address: nope");
    assert_eq!(add("198.51.100.7").await["code"], 0);
    assert_eq!(add("198.51.100.7").await["code"], 409);
    let r = set_key(&app, auth, "ip_whitelist_enable", json!("true")).await;
    assert!(
        r["msg"]
            .as_str()
            .is_some_and(|m| m.contains("block your own address 203.0.113.9")),
        "the caller would be locked out: {r}"
    );
    assert_eq!(add("203.0.113.5/24").await["code"], 0);
    assert_eq!(
        set_key(&app, auth, "ip_whitelist_enable", json!(true)).await["code"],
        0
    );
    let c = config(&app, auth).await;
    assert_eq!(
        c["ip_whitelist_enable"], true,
        "and the console still answers"
    );
    let list = c["ip_whitelist"].as_array().expect("list").clone();
    let range = list
        .iter()
        .find(|e| e["ip"] == "203.0.113.0/24")
        .expect("stored canonical");
    let r = post(
        &app,
        "/api/settings/delete_ip_whitelist",
        auth,
        json!({"id": range["id"]}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.contains("block your own address"))
    );
    let r = post(
        &app,
        "/api/settings/set_ip_whitelist",
        auth,
        json!({"ip_list": ["203.0.113.9", "bad"]}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    let r = post(
        &app,
        "/api/settings/set_ip_whitelist",
        auth,
        json!({"ip_list": []}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    let c = config(&app, auth).await;
    assert_eq!(
        (c["ip_whitelist"].clone(), c["ip_whitelist_enable"].clone()),
        (json!([]), json!(false)),
        "an empty list switches the whitelist off"
    );

    // --- Console certificate --------------------------------------------------------
    let (cert_pem, key_pem) = cert("console.example.test");
    let (_, other_key) = cert("other.example.test");
    let ssl_set = |cert: String, key: String| {
        let app = app.clone();
        async move {
            post(
                &app,
                "/api/settings/set_ssl_config",
                auth,
                json!({"certPem": cert, "privateKey": key}),
            )
            .await
            .body
        }
    };
    let r = ssl_set(cert_pem.clone(), other_key).await;
    assert!(
        r["msg"]
            .as_str()
            .is_some_and(|m| m.contains("does not belong")),
        "{r}"
    );
    let r = ssl_set("junk".into(), key_pem.clone()).await;
    assert_eq!(r["code"], 412);
    assert_eq!(ssl_set(cert_pem.clone(), key_pem.clone()).await["code"], 0);
    let mode = std::fs::metadata(ssl_dir.join("key.pem"))
        .expect("key")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let c = config(&app, auth).await;
    assert_eq!(
        (
            c["ssl"]["status"].clone(),
            c["ssl"]["subject_common_name"].clone(),
            c["ssl"]["privateKey"].clone()
        ),
        (json!(true), json!("console.example.test"), json!(""))
    );
    assert_eq!(
        ssl_set(cert_pem.clone(), String::new()).await["code"],
        0,
        "an empty key keeps the stored one"
    );
    assert_eq!(
        ssl_set(String::new(), String::new()).await["msg"],
        "Certificate deleted successfully"
    );
    assert!(!ssl_dir.join("cert.pem").exists() && !ssl_dir.join("key.pem").exists());
    assert!(!audit_text(&h).await.contains("PRIVATE KEY"));

    // --- API token ------------------------------------------------------------------
    let r = post(&app, "/api/settings/regenerate_api_token", auth, json!({})).await;
    let fresh = r.body["data"]["api_token"]
        .as_str()
        .expect("token")
        .to_owned();
    for (token, code) in [(&old_token, 401), (&fresh, 0)] {
        let r = call(
            &app,
            "/api/tags/list?page=1&page_size=10",
            &[("authorization", &bearer(token))],
            false,
        )
        .await;
        assert_eq!(r.body["code"], code, "{}", r.body);
    }

    // --- Reverse proxy --------------------------------------------------------------
    let proxy = |domain: String| {
        let app = app.clone();
        async move {
            post(
                &app,
                "/api/settings/set_reverse_proxy_domain",
                auth,
                json!({"domain": domain}),
            )
            .await
            .body
        }
    };
    assert_eq!(proxy("ftp://x.test".into()).await["code"], 412);
    let r = proxy("http://127.0.0.1:9".into()).await;
    assert!(
        r["msg"]
            .as_str()
            .is_some_and(|m| m.starts_with("Failed to connect to reverse proxy domain")),
        "{r}"
    );
    let target = proxy_target().await;
    assert_eq!(
        proxy(format!("{target}/bad/")).await["msg"],
        "Reverse proxy domain test failed: response code is 5, expected 0"
    );
    assert_eq!(proxy(format!("{target}/")).await["code"], 0);
    let c = config(&app, auth).await;
    assert_eq!(
        (
            c["reverse_proxy_domain"]["reverse_proxy"].clone(),
            c["reverse_proxy_domain"]["current_url"].clone()
        ),
        (json!(target), json!(target)),
        "links use it at once"
    );
    let r = post(
        &app,
        "/api/settings/delete_reverse_proxy_domain",
        auth,
        json!({}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    assert_eq!(
        config(&app, auth).await["reverse_proxy_domain"]["reverse_proxy"],
        ""
    );

    // --- Switches ---------------------------------------------------------------------
    let r = post(
        &app,
        "/api/settings/set_api_doc_swagger",
        auth,
        json!({"api_doc_enabled": true}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.ends_with("service restarted"))
    );
    let r = post(
        &app,
        "/api/settings/set_api_doc_swagger",
        auth,
        json!({"api_doc_enabled": true}),
    )
    .await;
    assert_eq!(r.body["msg"], "No configuration changes needed");
    let r = post(
        &app,
        "/api/settings/set_blacklist_auto_scan",
        auth,
        json!({}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    for (path, value) in [
        ("/api/settings/set_blacklist_auto_scan", false),
        ("/api/settings/set_blacklist_alert", true),
    ] {
        let r = post(&app, path, auth, json!({"enabled": value})).await;
        assert_eq!(r.body["code"], 0, "{path}");
    }
    let c = config(&app, auth).await;
    assert_eq!(
        (
            c["api_doc_swagger"]["api_doc_enabled"].clone(),
            c["blacklist_config"]["auto_scan_enabled"].clone(),
            c["blacklist_config"]["alert_enabled"].clone()
        ),
        (json!(true), json!(false), json!(true))
    );

    // --- Alert mailbox ----------------------------------------------------------------
    let alert = |password: &str, server: &str, recipients: Value| {
        let app = app.clone();
        let body = json!({
            "name": "Alerts", "sender_email": "alerts@x.test", "smtp_password": password,
            "smtp_server": server, "smtp_port": h.smtp.port, "recipient_list": recipients,
        });
        async move {
            post(
                &app,
                "/api/settings/set_blacklist_alert_settings",
                auth,
                body,
            )
            .await
            .body
        }
    };
    assert_eq!(
        alert("pw", "127.0.0.1", json!(["nope"])).await["msg"],
        "Parameter validation failed: invalid recipient email format: nope"
    );
    let r = alert("pw", "127.0.0.1", json!(["ops@x.test", "sec@x.test"])).await;
    assert_eq!(
        r["msg"], "Alert settings saved successfully and test email sent",
        "{r}"
    );
    let mut mails = Vec::new();
    for _ in 0..50 {
        mails = h.smtp.mails();
        if mails.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(mails.len(), 2);
    assert!(
        mails
            .iter()
            .all(|m| m.login == "alerts@x.test" && m.password == "pw")
    );
    let subject = mail_parser::MessageParser::default()
        .parse(&mails[0].data)
        .and_then(|p| p.subject().map(str::to_owned));
    assert_eq!(subject.as_deref(), Some("Blacklist Alert Test - Ferropost"));
    let file = h.core_dir().join("data/blacklist_alert_settings.json");
    assert_eq!(
        std::fs::metadata(&file).expect("file").permissions().mode() & 0o777,
        0o600
    );
    let c = config(&app, auth).await;
    assert_eq!(
        (
            c["blacklist_config"]["alert_settings"]["smtp_password"].clone(),
            c["blacklist_config"]["alert_settings"]["sender_email"].clone()
        ),
        (json!(""), json!("alerts@x.test"))
    );
    // The console sends back the empty password: the stored one is kept, but
    // only for the same server.
    assert_eq!(
        alert("", "127.0.0.1", json!(["ops@x.test"])).await["code"],
        0
    );
    assert_eq!(
        h.smtp.mails().last().map(|m| m.password.clone()).as_deref(),
        Some("pw")
    );
    assert_eq!(
        alert("", "localhost", json!(["ops@x.test"])).await["msg"],
        "Parameter validation failed: SMTP password is required"
    );

    // --- Docker and files ---------------------------------------------------------------
    let r = call(
        &app,
        "/api/docker_api/list",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.contains("Docker is disabled")),
        "{}",
        r.body
    );
    let r = post(&app, "/api/docker_api/restart", auth, json!({})).await;
    assert_eq!(r.body["msg"], "container_id is required");
    let r = call(
        &app,
        "/api/docker_api/list",
        &[("authorization", &viewer)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 403, "admins only");
    let r = call(
        &app,
        "/api/file/read?file_path=/etc/passwd",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 501);

    // --- The safe entrance applies at once -------------------------------------------
    assert_eq!(
        set_key(&app, auth, "safe_path", json!("a/b")).await["code"],
        412
    );
    assert_eq!(
        set_key(&app, auth, "safe_path", json!("/Entry-9")).await["code"],
        0
    );
    let r = call(
        &app,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "access denied", "{}", r.body);
}
