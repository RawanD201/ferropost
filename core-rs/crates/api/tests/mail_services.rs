//! Mail services: the start-up repair of `main.cf`, the configuration
//! editor, BCC rules and their Postfix maps, mail forwarding, and the
//! Postfix queue routes (with Postfix itself switched off).

mod common;

use std::path::{Path, PathBuf};

use common::*;
use serde_json::{Value, json};

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

async fn get(app: &axum::Router, auth: &str, uri: &str) -> Value {
    call(app, uri, &[("authorization", auth)], false).await.body
}

async fn send_json(app: &axum::Router, auth: &str, uri: &str, body: Value) -> Value {
    post(app, uri, auth, body).await.body
}

#[tokio::test]
async fn mail_services() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let conf: PathBuf = h.root.path().join("conf");
    for dir in ["postfix", "dovecot", "rspamd"] {
        std::fs::create_dir_all(conf.join(dir)).expect("conf dir");
    }
    let main = conf.join("postfix/main.cf");
    std::fs::write(
        &main,
        "compatibility_level = 3.6\nmyhostname = mail.example.com\n\nqueue_run_delay = 100s\n",
    )
    .expect("main.cf");
    std::fs::write(conf.join("dovecot/dovecot.conf"), "protocols = imap\n").expect("dovecot");
    std::fs::write(conf.join("rspamd/rspamd.conf"), ".include x\n").expect("rspamd");
    sqlx::query("INSERT INTO domain (domain, create_time, active) VALUES ('example.test', 1, 1)")
        .execute(pg)
        .await
        .expect("domain");

    // --- Start-up repair -----------------------------------------------------------
    let state = h.state(&[]);
    assert!(
        ferropost_api::postfix::fix_main_config(&state)
            .await
            .expect("repair")
    );
    let repaired = read(&main);
    assert!(
        repaired.contains("mail_name = PostBillionMail\n"),
        "{repaired}"
    );
    assert!(
        repaired.contains("myhostname = mail.example.test\n"),
        "the mail host name, not the bare domain: {repaired}"
    );
    assert!(read(&conf.join("postfix/conf/header_checks")).contains("REPLACE Received:"));
    assert!(
        !ferropost_api::postfix::fix_main_config(&state)
            .await
            .expect("again"),
        "nothing left to repair"
    );

    // --- Configuration editor ------------------------------------------------------
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-mail-services"));
    let auth = admin.as_str();
    let r = send_json(
        &app,
        auth,
        "/api/services/get_config",
        json!({"service_type": "/billionmail-postfix-billionmail-1"}),
    )
    .await;
    assert_eq!(r["data"]["content"], repaired.as_str(), "{r}");
    assert_eq!(r["data"]["only_read"], false);
    assert!(
        r["data"]["config_path"]
            .as_str()
            .is_some_and(|p| p.ends_with("conf/postfix/main.cf") && !p.contains(".."))
    );
    let r = send_json(
        &app,
        auth,
        "/api/services/get_config",
        json!({"service_type": "core"}),
    )
    .await;
    assert_eq!(
        (r["code"].clone(), r["msg"].clone()),
        (json!(412), json!("Invalid service type"))
    );
    let r = send_json(
        &app,
        auth,
        "/api/services/save_config",
        json!({"service_type": "rspamd", "content": "options {}\n"}),
    )
    .await;
    assert_eq!(
        r["msg"], "The configuration file was saved successfully",
        "{r}"
    );
    assert_eq!(read(&conf.join("rspamd/rspamd.conf")), "options {}\n");
    let backups = std::fs::read_dir(conf.join("rspamd"))
        .expect("ls")
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("rspamd.conf.bak.")
        })
        .count();
    assert_eq!(backups, 1);
    let r = send_json(
        &app,
        auth,
        "/api/services/save_config",
        json!({"service_type": "rspamd", "content": "a\u{0}b"}),
    )
    .await;
    assert_eq!(r["code"], 412);
    std::fs::remove_file(conf.join("dovecot/dovecot.conf")).expect("remove");
    let r = send_json(
        &app,
        auth,
        "/api/services/get_config",
        json!({"service_type": "dovecot"}),
    )
    .await;
    assert_eq!(r["code"], 404);
    let viewer = bearer(&token(2, "access_token", "viewer-mail-services"));
    let r = send_json(
        &app,
        &viewer,
        "/api/services/get_config",
        json!({"service_type": "postfix"}),
    )
    .await;
    assert_eq!(r["code"], 403, "admins only");

    // --- BCC -----------------------------------------------------------------------
    let sender_bcc = conf.join("postfix/conf/sender_bcc");
    let recipient_bcc = conf.join("postfix/conf/recipient_bcc");
    let r = send_json(
        &app,
        auth,
        "/api/mail_bcc/add",
        json!({"type": "sender", "address": "@Example.test", "goto": "Archive@x.test", "active": 1}),
    )
    .await;
    assert_eq!(r["msg"], "add bcc rule success", "{r}");
    assert_eq!(read(&sender_bcc), "@example.test archive@x.test\n");
    assert_eq!(read(&recipient_bcc), "");
    assert!(read(&main).contains("sender_bcc_maps = hash:/etc/postfix/conf/sender_bcc\n"));
    let r = send_json(
        &app,
        auth,
        "/api/mail_bcc/add",
        json!({"type": "sender", "address": "example.test", "goto": "other@x.test"}),
    )
    .await;
    assert_eq!(r["code"], 409, "Postfix copies to one address per key");
    for (body, why) in [
        (
            json!({"type": "sender", "address": "a@example.test", "goto": "nope"}),
            "goto",
        ),
        (
            json!({"type": "sender", "address": "a b@example.test", "goto": "c@x.test"}),
            "address",
        ),
        (
            json!({"type": "sender", "address": "example.test\nevil x", "goto": "c@x.test"}),
            "address",
        ),
        (
            json!({"type": "other", "address": "a@example.test", "goto": "c@x.test"}),
            "type",
        ),
    ] {
        let r = send_json(&app, auth, "/api/mail_bcc/add", body).await;
        assert_eq!(r["code"], 412, "{why}: {r}");
    }
    let r = send_json(
        &app,
        auth,
        "/api/mail_bcc/add",
        json!({"type": "recipient", "address": "boss@example.test", "goto": "copy@x.test", "active": 1}),
    )
    .await;
    assert_eq!(r["code"], 0);
    assert_eq!(read(&recipient_bcc), "boss@example.test copy@x.test\n");
    let r = get(
        &app,
        auth,
        "/api/mail_bcc/list?page=1&page_size=10&keyword=boss",
    )
    .await;
    assert_eq!(r["data"]["total"], 1, "the console's keyword: {r}");
    let r = get(
        &app,
        auth,
        "/api/mail_bcc/list?type=recipient&keyword=archive",
    )
    .await;
    assert_eq!(r["data"]["total"], 0, "search narrows the type filter");
    let r = get(&app, auth, "/api/mail_bcc/list?page=2&page_size=1").await;
    assert_eq!(
        (
            r["data"]["total"].clone(),
            r["data"]["list"][0]["address"].clone()
        ),
        (json!(2), json!("example.test")),
        "page 2 is page 2"
    );
    let sender_id = r["data"]["list"][0]["id"].clone();
    let r = send_json(
        &app,
        auth,
        "/api/mail_bcc/edit",
        json!({"id": sender_id, "active": 0}),
    )
    .await;
    assert_eq!(r["msg"], "bcc rule disabled");
    assert_eq!(read(&sender_bcc), "");
    let r = send_json(
        &app,
        auth,
        "/api/mail_bcc/edit",
        json!({"id": sender_id, "type": "sender", "address": "example.test", "goto": "new@x.test", "active": 1}),
    )
    .await;
    assert_eq!(r["msg"], "modify bcc rule success");
    assert_eq!(read(&sender_bcc), "@example.test new@x.test\n");
    let r = send_json(&app, auth, "/api/mail_bcc/delete", json!({"id": sender_id})).await;
    assert_eq!(r["msg"], "delete bcc rule success");
    let r = send_json(&app, auth, "/api/mail_bcc/delete", json!({"id": sender_id})).await;
    assert_eq!(r["code"], 404);
    assert_eq!(read(&sender_bcc), "");

    // --- Forwarding ----------------------------------------------------------------------
    let r = send_json(
        &app,
        auth,
        "/api/mail_forward/add",
        json!({"address": "Info@example.test", "goto": "a@x.test\nB@y.test", "active": 1, "domain": "example.test"}),
    )
    .await;
    assert_eq!(r["msg"], "add mail forward success", "{r}");
    let forward: (String, String, i32) = sqlx::query_as(
        "SELECT goto, domain, active::int FROM alias WHERE address = 'info@example.test'",
    )
    .fetch_one(pg)
    .await
    .expect("alias");
    assert_eq!(
        forward,
        ("a@x.test,b@y.test".into(), "example.test".into(), 1)
    );
    for (body, code) in [
        (
            json!({"address": "info@example.test", "goto": "c@x.test"}),
            409,
        ),
        (json!({"address": "x@nope.test", "goto": "c@x.test"}), 400),
        (
            json!({"address": "y@example.test", "goto": "c@x.test\nnope"}),
            412,
        ),
        (
            json!({"address": "not-an-address", "goto": "c@x.test"}),
            412,
        ),
    ] {
        let r = send_json(&app, auth, "/api/mail_forward/add", body.clone()).await;
        assert_eq!(r["code"], code, "{body}: {r}");
    }
    let r = send_json(
        &app,
        auth,
        "/api/mail_forward/add",
        json!({"address": "@example.test", "goto": "catchall@x.test"}),
    )
    .await;
    assert_eq!(r["code"], 0, "a domain's catch-all");
    let r = get(
        &app,
        auth,
        "/api/mail_forward/list?page=1&page_size=10&keyword=info",
    )
    .await;
    assert_eq!(r["data"]["total"], 1, "{r}");
    // The console's switch sends the stored list back.
    let r = send_json(
        &app,
        auth,
        "/api/mail_forward/edit",
        json!({"address": "info@example.test", "goto": "a@x.test,b@y.test", "active": 0}),
    )
    .await;
    assert_eq!(r["msg"], "modify mail forward success");
    let state_of = || async {
        sqlx::query_as::<_, (String, i32)>(
            "SELECT goto, active::int FROM alias WHERE address = 'info@example.test'",
        )
        .fetch_one(pg)
        .await
        .expect("alias")
    };
    assert_eq!(state_of().await, ("a@x.test,b@y.test".into(), 0));
    let r = send_json(
        &app,
        auth,
        "/api/mail_forward/edit",
        json!({"address": "info@example.test", "active": 1}),
    )
    .await;
    assert_eq!(r["code"], 0);
    let r = send_json(
        &app,
        auth,
        "/api/mail_forward/edit",
        json!({"address": "info@example.test", "goto": "c@z.test"}),
    )
    .await;
    assert_eq!(r["code"], 0);
    assert_eq!(
        state_of().await,
        ("c@z.test".into(), 1),
        "a targets-only edit keeps it on (Go switched it off)"
    );
    let r = send_json(
        &app,
        auth,
        "/api/mail_forward/delete",
        json!({"address": "info@example.test"}),
    )
    .await;
    assert_eq!(r["msg"], "delete mail forward success");
    let r = send_json(
        &app,
        auth,
        "/api/mail_forward/delete",
        json!({"address": "info@example.test"}),
    )
    .await;
    assert_eq!(r["code"], 404);

    // --- Postfix queue ---------------------------------------------------------------------
    let r = get(&app, auth, "/api/postfix_queue/list").await;
    assert_eq!(r["data"], json!({"total": 0, "list": []}), "{r}");
    let r = get(&app, auth, "/api/postfix_queue/list?domain=x';reboot;'").await;
    assert_eq!(r["code"], 412, "no shell for the domain filter");
    let r = get(&app, auth, "/api/postfix_queue/queue_info?queue_id=ALL").await;
    assert_eq!(r["code"], 412);
    let r = get(&app, auth, "/api/postfix_queue/queue_info?queue_id=").await;
    assert_eq!(r["msg"], "queue_id required");
    for (ids, msg) in [
        (json!(["ALL"]), "invalid queue ID: ALL"),
        (json!([]), "No queue IDs provided"),
    ] {
        let r = send_json(
            &app,
            auth,
            "/api/postfix_queue/delete_by_id",
            json!({"queue_ids": ids}),
        )
        .await;
        assert_eq!(r["msg"], msg);
    }
    let r = send_json(
        &app,
        auth,
        "/api/postfix_queue/delete_by_id",
        json!({"queue_ids": ["4AB12C"]}),
    )
    .await;
    assert_eq!(r["msg"], "delete postfix queue mails success");
    let r = send_json(
        &app,
        auth,
        "/api/postfix_queue/flush",
        json!({"domain": "example.test"}),
    )
    .await;
    assert_eq!(r["msg"], "no deferred mail found for sender domain");
    let r = send_json(&app, auth, "/api/postfix_queue/flush", json!({})).await;
    assert_eq!(r["msg"], "flush all postfix queue success");

    let r = get(&app, auth, "/api/postfix_queue/get_config").await;
    assert_eq!(
        (
            r["data"]["queue_run_delay"].clone(),
            r["data"]["bounce_queue_lifetime"].clone()
        ),
        (json!("100s"), json!("5d"))
    );
    let r = send_json(
        &app,
        auth,
        "/api/postfix_queue/set_config",
        json!({"key": "queue_run_delay", "value": "5d\ncontent_filter = evil:x"}),
    )
    .await;
    assert_eq!(r["code"], 412, "no new main.cf lines");
    let r = send_json(
        &app,
        auth,
        "/api/postfix_queue/set_config",
        json!({"key": "myhostname", "value": "x"}),
    )
    .await;
    assert_eq!(r["msg"], "config key not allowed to modify: myhostname");
    let r = send_json(
        &app,
        auth,
        "/api/postfix_queue/set_all_config",
        json!({"queue_run_delay": "60s", "trigger_timeout": "5s", "minimal_backoff_time": ""}),
    )
    .await;
    assert_eq!(r["msg"], "set postfix configs success", "{r}");
    let main_cf = read(&main);
    assert_eq!(main_cf.matches("queue_run_delay").count(), 1);
    assert!(
        main_cf.contains("queue_run_delay = 60s\n") && main_cf.contains("trigger_timeout = 5s\n")
    );
    assert!(!main_cf.contains("content_filter"));
    let r = get(&app, auth, "/api/postfix_queue/get_config").await;
    assert_eq!(r["data"]["queue_run_delay"], "60s");
}
