//! Domains: creating one (system mailboxes, catch-all, DKIM keys, rspamd's
//! signing configuration, the server's host name), listing them (records,
//! certificate without its key, default flag), updating only what is
//! given, the brand flag, the default domain, dedicated addresses,
//! refreshing records, and deleting a domain with what belongs to it.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};

async fn list(app: &axum::Router, auth: &str, query: &str) -> Value {
    let r = call(
        app,
        &format!("/api/domains/list?{query}"),
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    r.body["data"].clone()
}

async fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..200 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn domains() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let local_d = h.root.path().join("conf/rspamd/local.d");
    std::fs::create_dir_all(&local_d).expect("rspamd dir");
    let signing = local_d.join("dkim_signing.conf");
    let state = h.state(&[("BILLIONMAIL_HOSTNAME", "mail.example.com")]);
    let app = ferropost_api::app(state.clone());
    let admin = bearer(&token(1, "access_token", "admin-domains"));
    let auth = admin.as_str();

    // --- Validation: nothing is written -------------------------------------------
    for body in [
        json!({}),
        json!({"domain": "not a domain"}),
        json!({"domain": "localhost"}),
        json!({"domain": "ex.test", "hostname": "bad host"}),
        json!({"domain": "ex.test", "email": "nobody"}),
        json!({"domain": "ex.test", "mailboxes": -1}),
        json!({"domain": "ex.test", "mailboxes": 0}),
        json!({"domain": "ex.test", "outbound_ip": "300.1.1.1"}),
        json!({"domain": "ex.test", "urls": ["javascript:alert(1)"]}),
        json!({"domain": "ex.test", "hasbrandinfo": 2}),
    ] {
        let r = post(&app, "/api/domains/create", auth, body.clone()).await;
        assert_eq!(r.body["code"], 412, "{body}: {}", r.body);
    }
    // A dedicated address is checked first: no half-made domain (Go
    // created the domain, then failed).
    let r = post(
        &app,
        "/api/domains/create",
        auth,
        json!({"domain": "ex.test", "outbound_ip": "203.0.113.7"}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.starts_with("Failed to add dedicated IP")),
        "{}",
        r.body
    );
    let none: i64 = sqlx::query_scalar("SELECT count(*) FROM domain")
        .fetch_one(pg)
        .await
        .expect("count");
    assert_eq!(none, 0);

    // --- Create -------------------------------------------------------------------
    let r = post(
        &app,
        "/api/domains/create",
        auth,
        json!({"domain": "Ex.Test", "quota": 5_368_709_120_i64, "mailboxes": 20,
               "email": "Owner@Elsewhere.test", "urls": ["https://", "https://ex.test"],
               "hasbrandinfo": 1, "outbound_ip": "", "hostname": ""}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    assert_eq!(r.body["msg"], "Domain added successfully");
    let row: (String, String, i32, i64, Vec<String>, i16, i16) = sqlx::query_as(
        "SELECT domain, a_record, mailboxes, quota, urls, hasbrandinfo, active FROM domain",
    )
    .fetch_one(pg)
    .await
    .expect("row");
    assert_eq!(
        row,
        (
            "ex.test".to_owned(),
            "mail.ex.test".to_owned(),
            20,
            5_368_709_120,
            vec!["https://ex.test".to_owned()],
            1,
            1
        )
    );
    let mailboxes: Vec<String> =
        sqlx::query_scalar("SELECT username FROM mailbox WHERE domain = 'ex.test' ORDER BY 1")
            .fetch_all(pg)
            .await
            .expect("mailboxes");
    assert_eq!(
        mailboxes,
        [
            "abuse@ex.test",
            "admin@ex.test",
            "noreply@ex.test",
            "postmaster@ex.test",
            "support@ex.test"
        ]
    );
    let catchall: (String, i16) =
        sqlx::query_as("SELECT goto, active FROM alias WHERE address = '@ex.test'")
            .fetch_one(pg)
            .await
            .expect("catch-all");
    assert_eq!(catchall, ("owner@elsewhere.test".to_owned(), 1));
    let keys = h.root.path().join("rspamd-data/dkim/ex.test");
    for file in [
        "default.private",
        "default.pub",
        "short.private",
        "short.pub",
    ] {
        assert!(keys.join(file).exists(), "{file}");
    }
    wait_for("rspamd's signing configuration", || {
        std::fs::read_to_string(&signing).is_ok_and(|c| c.contains("#ex.test_DKIM_BEGIN"))
    })
    .await;
    assert_eq!(
        state.config.env.get("BILLIONMAIL_HOSTNAME").as_deref(),
        Some("mail.ex.test"),
        "the first domain names the server, as in Go"
    );

    let r = post(
        &app,
        "/api/domains/create",
        auth,
        json!({"domain": "EX.TEST"}),
    )
    .await;
    assert_eq!(r.body["code"], 409, "{}", r.body);
    let r = post(
        &app,
        "/api/domains/create",
        auth,
        json!({"domain": "other.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    assert_eq!(
        state.config.env.get("BILLIONMAIL_HOSTNAME").as_deref(),
        Some("mail.ex.test"),
        "only while none is set"
    );

    // --- List -----------------------------------------------------------------------
    let page = list(&app, auth, "page=1&page_size=10&keyword=ex.").await;
    assert_eq!(page["total"], 1, "{page}");
    let d = &page["list"][0];
    assert_eq!(d["domain"], "ex.test");
    assert_eq!(d["email"], "owner@elsewhere.test");
    assert_eq!(d["default"], 0);
    assert_eq!(d["mailboxes"], 20);
    assert_eq!(d["hasbrandinfo"], 1);
    assert_eq!(d["urls"], json!(["https://ex.test"]));
    assert_eq!(d["multi_ip_domains"], Value::Null);
    assert_eq!(d["cert_info"]["key_pem"], "", "never the private key");
    assert_eq!(d["black_check_result"]["tested"], 0);
    assert!(
        d["black_check_log"]
            .as_str()
            .is_some_and(|p| p.ends_with("/data/mail.ex.test_blcheck.txt")),
        "{d}"
    );
    let dns = &d["dns_records"];
    assert_eq!(
        dns["mx"],
        json!({"type": "MX", "host": "@", "value": "mail.ex.test", "valid": false})
    );
    assert_eq!(dns["a"]["value"], "198.51.100.1");
    assert_eq!(dns["spf"]["value"], "v=spf1 +a +mx +ip4:198.51.100.1 -all");
    assert_eq!(
        dns["dmarc"]["value"],
        "v=DMARC1;p=quarantine;rua=mailto:admin@ex.test"
    );
    assert_eq!(dns["ptr"]["host"], "198.51.100.1");
    assert!(
        dns["dkim"]["value"]
            .as_str()
            .is_some_and(|v| v.starts_with("v=DKIM1; k=rsa; p=MIIBIjAN")),
        "{dns}"
    );
    assert!(
        dns["dkim_short"]["value"]
            .as_str()
            .is_some_and(|v| v.starts_with("v=DKIM1; k=rsa; p=MIGfMA0")),
        "{dns}"
    );
    assert_eq!(list(&app, auth, "keyword=nothing").await["total"], 0);
    assert_eq!(list(&app, auth, "").await["total"], 2);

    // --- Default domain ---------------------------------------------------------------
    let r = post(
        &app,
        "/api/domains/set_default_domain",
        auth,
        json!({"domain": "ex.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let r = post(
        &app,
        "/api/domains/set_default_domain",
        auth,
        json!({"domain": "gone.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 404, "{}", r.body);
    let r = call(&app, "/api/domains/all", &[("authorization", auth)], false).await;
    let all = r.body["data"].as_array().expect("all").clone();
    let defaults: Vec<(&str, i64)> = all
        .iter()
        .map(|d| {
            (
                d["domain"].as_str().unwrap_or_default(),
                d["default"].as_i64().unwrap_or(-1),
            )
        })
        .collect();
    assert_eq!(
        defaults,
        [("ex.test", 1), ("other.test", 0)],
        "Go never marked it here"
    );

    // --- Update: only what is given -----------------------------------------------------
    let r = post(
        &app,
        "/api/domains/update",
        auth,
        json!({"domain": "ex.test", "hostname": "MX.ex.test", "email": "", "quota": 0}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let row: (String, i64, i16, i16, Vec<String>) = sqlx::query_as(
        "SELECT a_record, quota, hasbrandinfo, active, urls FROM domain WHERE domain = 'ex.test'",
    )
    .fetch_one(pg)
    .await
    .expect("row");
    assert_eq!(
        row,
        (
            "mx.ex.test".to_owned(),
            5_368_709_120,
            1,
            1,
            vec!["https://ex.test".to_owned()]
        ),
        "Go cleared the brand flag and re-enabled the domain on every edit"
    );
    let active: i16 = sqlx::query_scalar("SELECT active FROM alias WHERE address = '@ex.test'")
        .fetch_one(pg)
        .await
        .expect("alias");
    assert_eq!(active, 0, "an empty address turns the catch-all off");
    let r = post(
        &app,
        "/api/domains/update",
        auth,
        json!({"domain": "gone.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 404, "{}", r.body);
    let r = post(
        &app,
        "/api/domains/update",
        auth,
        json!({"domain": "other.test", "active": 0}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let r = post(
        &app,
        "/api/domains/set_default_domain",
        auth,
        json!({"domain": "other.test"}),
    )
    .await;
    assert_eq!(
        r.body["code"], 404,
        "a disabled domain cannot be the default: {}",
        r.body
    );
    let r = post(
        &app,
        "/api/domains/update",
        auth,
        json!({"domain": "ex.test", "outbound_ip": "203.0.113.7", "mailboxes": 30}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.starts_with("Failed to add dedicated IP")),
        "{}",
        r.body
    );
    let mailboxes: i32 =
        sqlx::query_scalar("SELECT mailboxes FROM domain WHERE domain = 'ex.test'")
            .fetch_one(pg)
            .await
            .expect("mailboxes");
    assert_eq!(mailboxes, 20, "a failed check changes nothing");

    let r = post(
        &app,
        "/api/domains/update_brandinfo",
        auth,
        json!({"domain": "ex.test", "hasbrandinfo": 0}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let flag: i16 = sqlx::query_scalar("SELECT hasbrandinfo FROM domain WHERE domain = 'ex.test'")
        .fetch_one(pg)
        .await
        .expect("flag");
    assert_eq!(flag, 0);

    // --- Dedicated addresses -------------------------------------------------------------
    ferropost_api::multi_ip::add_config(&state, "ex.test", "203.0.113.7".parse().expect("ip"))
        .await
        .expect("dedicated");
    ferropost_api::multi_ip::add_config(&state, "other.test", "203.0.113.8".parse().expect("ip"))
        .await
        .expect("dedicated");
    let nets: Vec<(String, String, String)> =
        sqlx::query_as("SELECT domain, subnet, postfix_ip FROM bm_multi_ip_domain ORDER BY id")
            .fetch_all(pg)
            .await
            .expect("nets");
    assert_eq!(
        nets,
        [
            (
                "ex.test".to_owned(),
                "172.66.2.0/24".to_owned(),
                "172.66.2.100".to_owned()
            ),
            (
                "other.test".to_owned(),
                "172.66.3.0/24".to_owned(),
                "172.66.3.100".to_owned()
            ),
        ]
    );
    let r = post(
        &app,
        "/api/domains/fresh_dns_records",
        auth,
        json!({"domain": "ex.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let dns = &r.body["data"];
    assert_eq!(dns["mx"]["value"], "mx.ex.test");
    assert_eq!(dns["a"]["value"], "203.0.113.7");
    assert_eq!(dns["ptr"]["host"], "203.0.113.7");
    assert_eq!(
        dns["spf"]["value"],
        "v=spf1 +a +mx +ip4:198.51.100.1 +ip4:203.0.113.7 -all"
    );
    let r = post(
        &app,
        "/api/domains/fresh_dns_records",
        auth,
        json!({"domain": "gone.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 404, "{}", r.body);
    let page = list(&app, auth, "keyword=ex.test").await;
    assert_eq!(
        page["list"][0]["multi_ip_domains"]["outbound_ip"],
        "203.0.113.7"
    );

    // Absent keeps it (the console's form never filled it in, so Go
    // removed it on every edit); empty removes it.
    let r = post(
        &app,
        "/api/domains/update",
        auth,
        json!({"domain": "other.test", "mailboxes": 5}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let r = post(
        &app,
        "/api/domains/update",
        auth,
        json!({"domain": "other.test", "outbound_ip": ""}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    let left: Vec<String> = sqlx::query_scalar("SELECT domain FROM bm_multi_ip_domain ORDER BY id")
        .fetch_all(pg)
        .await
        .expect("left");
    assert_eq!(left, ["ex.test"]);

    // --- Delete: with what belongs to the domain ----------------------------------------
    sqlx::query(
        "INSERT INTO bm_bcc (type, address, goto, domain, create_time, update_time, active)
         VALUES ('sender', 'admin@ex.test', 'archive@other.test', 'ex.test', 1, 1, 1)",
    )
    .execute(pg)
    .await
    .expect("bcc");
    let r = post(
        &app,
        "/api/domains/delete",
        auth,
        json!({"domain": "EX.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    for (table, column) in [
        ("domain", "domain"),
        ("mailbox", "domain"),
        ("alias", "domain"),
        ("bm_bcc", "domain"),
        ("bm_multi_ip_domain", "domain"),
    ] {
        let left: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {table} WHERE {column} = 'ex.test'"
        ))
        .fetch_one(pg)
        .await
        .expect("count");
        assert_eq!(left, 0, "{table}");
    }
    let default: Option<String> =
        sqlx::query_scalar("SELECT value FROM bm_options WHERE name = 'default_sender_domain'")
            .fetch_optional(pg)
            .await
            .expect("option");
    assert_eq!(default, None);
    let others: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mailbox WHERE domain = 'other.test'")
            .fetch_one(pg)
            .await
            .expect("others");
    assert_eq!(others, 5);
    wait_for("rspamd to stop signing for the domain", || {
        std::fs::read_to_string(&signing).is_ok_and(|c| {
            !c.contains("#ex.test_DKIM_BEGIN") && c.contains("#other.test_DKIM_BEGIN")
        })
    })
    .await;
    assert!(
        keys.join("default.private").exists(),
        "keys stay, so the published records still match if the domain comes back"
    );
    let r = post(
        &app,
        "/api/domains/delete",
        auth,
        json!({"domain": "ex.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 404, "{}", r.body);
}
