//! SMTP relays: the start-up migration and sync, create/edit/delete with
//! the Postfix and rspamd files they produce, passwords never sent back,
//! a toggle that keeps the login, connection tests against the harness's
//! SMTP sink, and the SPF advice.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use common::*;
use serde_json::{Value, json};

fn read(path: &PathBuf) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

async fn list(app: &axum::Router, auth: &str) -> Vec<Value> {
    let r = call(app, "/api/relay/list", &[("authorization", auth)], false).await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    r.body["data"]["list"].as_array().expect("list").clone()
}

#[tokio::test]
async fn relays() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let postfix = h.root.path().join("conf/postfix");
    let local_d = h.root.path().join("conf/rspamd/local.d");
    std::fs::create_dir_all(&postfix).expect("postfix dir");
    std::fs::create_dir_all(&local_d).expect("rspamd dir");
    std::fs::write(
        postfix.join("main.cf"),
        "myhostname = x\nsender_dependent_default_transport_maps = hash:/etc/postfix/old\n",
    )
    .expect("main.cf");
    std::fs::write(postfix.join("master.cf"), "smtp inet n - n - - smtpd\n").expect("master.cf");
    for (domain, at) in [("example.test", 1), ("other.test", 2)] {
        sqlx::query("INSERT INTO domain (domain, create_time, active) VALUES ($1, $2, 1)")
            .bind(domain)
            .bind(at)
            .execute(pg)
            .await
            .expect("domain");
    }
    let env = [("DBUSER", "billionmail"), ("DBNAME", "billionmail")];

    // --- Start-up: Go's one-off migration, then a sync ------------------------------
    let mut with_job = env.to_vec();
    with_job.push(("FERROPOST_RUST_JOBS", "relay"));
    let job_state = h.state(&with_job);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let jobs = ferropost_api::relay::spawn(&job_state, stopped);
    let marker = h.core_dir().join("data/SMTP_relay_sync_config_mark2.pl");
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(marker.exists(), "first sync ran");
    let _ = stop.send(true);
    for job in jobs {
        let _ = job.await;
    }
    assert!(
        read(&postfix.join("main.cf")).contains(
            "# sender_dependent_default_transport_maps = hash:/etc/postfix/old # Migrated"
        ),
        "hand-written transport maps commented out"
    );
    assert_eq!(
        read(&postfix.join("conf/sasl_passwd")),
        "# No active relay configurations\n"
    );
    assert!(read(&postfix.join("master.cf")).contains("# No active relay configurations"));
    assert!(
        read(&postfix.join("sql/pgsql_sender_relay_maps.cf")).starts_with("user = billionmail\n")
    );

    // --- Create --------------------------------------------------------------------
    let app = h.app(&env);
    let admin = bearer(&token(1, "access_token", "admin-relay"));
    let auth = admin.as_str();
    let port = h.smtp.port;
    let relay = |extra: Value| {
        let mut body = json!({
            "rtype": "custom", "smtp_name": "SES Tokyo", "sender_domains": ["example.test"],
            "relay_host": "127.0.0.1", "relay_port": port, "auth_user": "AKIA",
            "auth_password": "pw:1", "host": "amazonses.com", "active": 1,
            "auth_method": "", "skip_tls_verify": "", "helo_name": "mail.example.test",
        });
        for (k, v) in extra.as_object().expect("object") {
            body[k] = v.clone();
        }
        body
    };
    let r = call(
        &app,
        "/api/relay/get_unbound_domains",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(
        r.body["data"],
        json!([{"domain": "example.test", "is_bound": false}, {"domain": "other.test", "is_bound": false}])
    );
    for (extra, msg) in [
        (
            json!({"helo_name": "mail.x.test\n  -o content_filter=evil"}),
            "helo_name must be a host name or IP address",
        ),
        (
            json!({"sender_domains": ["nope.test"]}),
            "The domain nope.test is not one of your domains",
        ),
        (
            json!({"auth_password": ""}),
            "Both auth_user and auth_password must be provided when using authentication",
        ),
        (
            json!({"auth_password": "pw\nx"}),
            "auth_user or auth_password contains characters Postfix cannot store",
        ),
    ] {
        let r = post(&app, "/api/relay/add", auth, relay(extra)).await;
        assert_eq!(r.body["msg"], msg);
    }
    let r = post(&app, "/api/relay/add", auth, relay(json!({}))).await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    assert_eq!(
        r.body["spf_record"],
        json!({"type": "TXT", "host": "example.test",
               "value": "v=spf1 +a +mx +ip4:198.51.100.1 include:amazonses.com -all"})
    );
    let r = post(
        &app,
        "/api/relay/add",
        auth,
        relay(json!({"smtp_name": "Other"})),
    )
    .await;
    assert_eq!(r.body["code"], 409, "a domain has one relay");

    let sasl = postfix.join("conf/sasl_passwd");
    assert_eq!(read(&sasl), format!("[127.0.0.1]:{port} AKIA:pw:1\n"));
    assert_eq!(
        std::fs::metadata(&sasl).expect("sasl").permissions().mode() & 0o777,
        0o600,
        "relay passwords readable by root only"
    );
    let master = read(&postfix.join("master.cf"));
    assert!(
        master.contains(
            "smtp_Custom_SES_Tokyo unix - - n - - smtp\n  -o smtp_helo_name=mail.example.test\n"
        ),
        "{master}"
    );
    assert!(read(&postfix.join("main.cf")).contains(ferropost_domain::relay::MAIN_BEGIN));
    let transport: (String, String) = sqlx::query_as(
        "SELECT domain, smtp_name FROM bm_domain_smtp_transport WHERE atype = 'relay'",
    )
    .fetch_one(pg)
    .await
    .expect("transport");
    assert_eq!(
        transport,
        ("@example.test".into(), "smtp_Custom_SES_Tokyo".into())
    );
    let (id, stored): (i64, String) =
        sqlx::query_as("SELECT id, auth_password FROM bm_relay_config")
            .fetch_one(pg)
            .await
            .expect("relay");
    let key: String =
        sqlx::query_scalar("SELECT value FROM bm_options WHERE name = 'relay_encryption_key'")
            .fetch_one(pg)
            .await
            .expect("key");
    let key = ferropost_domain::relay::password_key(&key).expect("valid key");
    assert_eq!(
        ferropost_domain::relay::decrypt_password(&key, &stored).as_deref(),
        Some("pw:1"),
        "stored encrypted, in Go's format"
    );
    let dkim = read(&local_d.join("dkim_signing.conf"));
    assert!(
        dkim.contains("#other.test_DKIM_BEGIN") && !dkim.contains("example.test"),
        "the relay provider signs example.test"
    );

    // --- List and status ---------------------------------------------------------------
    let mut item = Value::Null;
    for _ in 0..100 {
        item = list(&app, auth).await[0].clone();
        if item["smtp_status"]["status"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        item["smtp_status"],
        json!({"status": true, "msg": "Connection normal"}),
        "checked against the sink: {item}"
    );
    assert_eq!(item["auth_password"], "", "never sent back");
    assert_eq!(item["sender_domains"], json!(["example.test"]));
    assert_eq!(
        (
            item["check_spf"].clone(),
            item["spf_records"][0]["check"].clone()
        ),
        (json!(1), json!(1)),
        "example.test publishes no SPF record"
    );

    // --- Connection tests ----------------------------------------------------------------
    let test = |body: Value| {
        let app = app.clone();
        async move {
            post(&app, "/api/relay/test_connection", auth, body)
                .await
                .body
        }
    };
    let r = test(json!({"relay_host": "127.0.0.1", "relay_port": port, "auth_user": "AKIA", "auth_password": ""})).await;
    assert_eq!(r["msg"], "The SMTP connection test was successful", "{r}");
    assert_eq!(
        (
            r["data"]["tls_status"].clone(),
            r["data"]["auth_status"].clone(),
            r["data"]["supported_auth"].clone()
        ),
        (
            json!("None"),
            json!("Authentication succeeded."),
            json!("PLAIN, LOGIN")
        ),
        "the stored password was used"
    );
    let r = test(json!({"relay_host": "localhost", "relay_port": port, "auth_user": "AKIA"})).await;
    assert_eq!(
        r["msg"], "Password is required when username is provided.",
        "the stored password only goes to its own server"
    );
    let r = test(json!({"relay_host": "127.0.0.1", "relay_port": 9})).await;
    assert!(
        r["msg"]
            .as_str()
            .is_some_and(|m| m.starts_with("SMTP connection failed:")),
        "{r}"
    );

    // --- Edits ---------------------------------------------------------------------------
    // The console's on/off switch sends only these two fields.
    let r = post(
        &app,
        "/api/relay/edit",
        auth,
        json!({"id": id, "active": 0}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let login: (String, String, i32) =
        sqlx::query_as("SELECT auth_user, auth_password, active::int FROM bm_relay_config")
            .fetch_one(pg)
            .await
            .expect("login");
    assert_eq!(
        (login.0.as_str(), login.1 == stored, login.2),
        ("AKIA", true, 0),
        "Go wiped the login here"
    );
    assert_eq!(read(&sasl), "# No active relay configurations\n");
    assert!(!read(&postfix.join("main.cf")).contains(ferropost_domain::relay::MAIN_BEGIN));
    assert!(read(&local_d.join("dkim_signing.conf")).contains("#example.test_DKIM_BEGIN"));
    assert_eq!(
        list(&app, auth).await[0]["smtp_status"]["msg"],
        "Relay is disabled"
    );

    let r = post(
        &app,
        "/api/relay/edit",
        auth,
        json!({"id": id, "active": 1, "auth_user": "AKIA", "auth_password": "", "relay_port": port,
               "sender_domains": ["example.test", "other.test"], "skip_tls_verify": ""}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    assert_eq!(
        read(&sasl),
        format!("[127.0.0.1]:{port} AKIA:pw:1\n"),
        "an empty password keeps the stored one"
    );
    let routes: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bm_domain_smtp_transport WHERE atype = 'relay'")
            .fetch_one(pg)
            .await
            .expect("routes");
    assert_eq!(routes, 2);

    let r = post(
        &app,
        "/api/relay/edit",
        auth,
        json!({"id": id, "auth_user": ""}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    let login: (String, String, String) =
        sqlx::query_as("SELECT auth_user, auth_password, auth_method FROM bm_relay_config")
            .fetch_one(pg)
            .await
            .expect("login");
    assert_eq!(login, (String::new(), String::new(), "NONE".to_owned()));
    assert_eq!(
        read(&sasl),
        "# No relay configurations require authentication\n"
    );
    let r = post(
        &app,
        "/api/relay/edit",
        auth,
        json!({"id": 999, "active": 1}),
    )
    .await;
    assert_eq!(r.body["code"], 404);

    // --- Delete ----------------------------------------------------------------------------
    let r = post(&app, "/api/relay/delete", auth, json!({"id": id})).await;
    assert_eq!(r.body["msg"], "Relay configuration deleted successfully");
    let r = post(&app, "/api/relay/delete", auth, json!({"id": id})).await;
    assert_eq!(r.body["code"], 404);
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM bm_relay_domain_mapping) + (SELECT COUNT(*) FROM bm_domain_smtp_transport)",
    )
    .fetch_one(pg)
    .await
    .expect("left");
    assert_eq!(left, 0);
    let logs: String =
        sqlx::query_scalar("SELECT COALESCE(string_agg(log, ' | '), '') FROM bm_operation_logs")
            .fetch_one(pg)
            .await
            .expect("logs");
    assert!(logs.contains("Created relay configuration: SES Tokyo for domains: example.test"));
    assert!(!logs.contains("pw:1"), "no password in the audit log");
}
