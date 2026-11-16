//! Abnormal recipients (routes, group scan, the bounce job), the console
//! language, and the hosted `/subscription/form` page.

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;

async fn scalar(h: &Harness, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&h.store.pg)
        .await
        .expect(sql)
}

#[tokio::test]
async fn abnormal_recipients_languages_and_form() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-abnormal"));
    let auth = admin.as_str();
    let now = chrono::Utc::now().timestamp();

    // --- Abnormal recipients --------------------------------------------------
    sqlx::query("INSERT INTO abnormal_recipient (recipient, count, description, add_type) VALUES ('seen@x.test', 1, 'once', 2)")
        .execute(pg)
        .await
        .expect("seed");
    let r = post(
        &app,
        "/api/abnormal_recipient/add",
        auth,
        json!({"recipient": "nope"}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    for address in ["seen@x.test", "new@x.test"] {
        let r = post(
            &app,
            "/api/abnormal_recipient/add",
            auth,
            json!({"recipient": address}),
        )
        .await;
        assert_eq!(
            r.body["msg"],
            "The exception recipient was added successfully"
        );
    }
    // A manual block always reaches the blocking count (Go left 'seen' at 1).
    assert_eq!(
        scalar(
            &h,
            "SELECT count::bigint FROM abnormal_recipient WHERE recipient = 'seen@x.test'"
        )
        .await,
        3
    );
    let r = call(
        &app,
        "/api/abnormal_recipient/list?page=1&page_size=10&add_type=1",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 2, "{}", r.body);

    // The bounce job counts each address that bounced since its last pass.
    for (id, recipient, offset) in [
        ("B1", "bounce@x.test", -60),
        ("B2", "bounce@x.test", -30),
        ("B3", "seen@x.test", -10),
        ("B4", "old@x.test", -7200),
    ] {
        sqlx::query("INSERT INTO mailstat_send_mails (postfix_message_id, log_time_millis, status, recipient, description)
                     VALUES ($1, $2, 'bounced', $3, $4)")
            .bind(id)
            .bind((now + offset) * 1000)
            .bind(recipient)
            .bind(format!("550 user unknown {id} {}", "x".repeat(300)))
            .execute(pg)
            .await
            .expect("bounce");
    }
    let counted = ferropost_jobs::abnormal::pass(pg, now).await.expect("pass");
    assert_eq!(
        counted, 2,
        "bounce@ and seen@, not the one from two hours ago"
    );
    let (count, description): (i32, String) = sqlx::query_as(
        "SELECT count, description FROM abnormal_recipient WHERE recipient = 'bounce@x.test'",
    )
    .fetch_one(pg)
    .await
    .expect("bounce row");
    assert_eq!(count, 1);
    assert!(
        description.starts_with("Automatic statistics - 550 user unknown B2"),
        "latest reason: {description}"
    );
    assert_eq!(description.chars().count(), 255, "fits VARCHAR(255)");
    assert_eq!(
        scalar(
            &h,
            "SELECT count::bigint FROM abnormal_recipient WHERE recipient = 'seen@x.test'"
        )
        .await,
        4
    );
    // The next pass starts where this one ended.
    assert_eq!(
        ferropost_jobs::abnormal::pass(pg, now + 1)
            .await
            .expect("again"),
        0
    );
    // Switched off, it does nothing.
    let r = post(
        &app,
        "/api/abnormal_recipient/set_check_switch",
        auth,
        json!({"oper": 0}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    let r = call(
        &app,
        "/api/abnormal_recipient/check_switch",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"], 0);
    assert!(!ferropost_jobs::abnormal::enabled(pg).await.expect("switch"));

    // Group scan: the reserved `.invalid` domain cannot receive mail; a
    // failed lookup (no resolver) would be left alone rather than acted on.
    sqlx::query("INSERT INTO bm_contacts (email, group_id, active, status) VALUES ('a@nowhere.invalid', 1, 1, 1)")
        .execute(pg)
        .await
        .expect("contact");
    let r = post(
        &app,
        "/api/abnormal_recipient/check_group",
        auth,
        json!({"group_id": 99, "oper": 1}),
    )
    .await;
    assert_eq!(r.body["msg"], "The group does not exist.");
    let r = post(
        &app,
        "/api/abnormal_recipient/check_group",
        auth,
        json!({"group_id": 1, "oper": 2}),
    )
    .await;
    assert_eq!(
        r.body["msg"],
        "The process is currently running in the background. Please check the log."
    );
    let mut log = String::new();
    for _ in 0..100 {
        let r = post(
            &app,
            "/api/abnormal_recipient/get_scan_log",
            auth,
            json!({}),
        )
        .await;
        log = r.body["data"].as_str().unwrap_or_default().to_owned();
        if log.contains("Check finished") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        log.contains("Group[Customers] start checking...") && log.contains("Tested: 1"),
        "{log}"
    );
    let blocked = scalar(
        &h,
        "SELECT COUNT(*) FROM abnormal_recipient WHERE recipient = 'a@nowhere.invalid'",
    )
    .await;
    if log.contains("x  the domain does not exist") {
        assert_eq!(blocked, 1, "blocked after the scan: {log}");
    } else {
        assert!(log.contains("(left as is)"), "{log}");
        assert_eq!(blocked, 0, "a failed lookup is not acted on");
    }

    let r = post(
        &app,
        "/api/abnormal_recipient/delete",
        auth,
        json!({"id": 999}),
    )
    .await;
    assert_eq!(r.body["code"], 404);
    let r = post(
        &app,
        "/api/abnormal_recipient/clear_abnormal",
        auth,
        json!({}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    assert_eq!(
        scalar(&h, "SELECT COUNT(*) FROM abnormal_recipient").await,
        0
    );

    // --- Language -----------------------------------------------------------------
    std::fs::create_dir_all(h.core_dir().join("languages")).expect("languages");
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../core/languages/settings.json"),
        h.core_dir().join("languages/settings.json"),
    )
    .expect("settings");
    let r = call(&app, "/api/languages/get", &[], false).await;
    assert_eq!(
        r.body["data"]["available_languages"][0]["name"], "en",
        "public: {}",
        r.body
    );
    // Go let anyone switch the console language.
    let r = post(&app, "/api/languages/set", "", json!({"language": "ja"})).await;
    assert_eq!(r.body["code"], 401);
    let viewer = bearer(&token(2, "access_token", "viewer-lang"));
    let r = post(
        &app,
        "/api/languages/set",
        &viewer,
        json!({"language": "xx"}),
    )
    .await;
    assert_eq!(r.body["msg"], "Invalid language code: xx");
    let r = post(
        &app,
        "/api/languages/set",
        &viewer,
        json!({"language": "ja"}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "any role may switch: {}", r.body);
    let r = call(&app, "/api/languages/get", &[], false).await;
    assert_eq!(r.body["data"]["current_language"], "ja");

    // --- The hosted subscription form -------------------------------------------------
    copy_templates(&h);
    sqlx::query("UPDATE bm_contact_groups SET name = '<b>Leads</b>', double_optin = 1, token = 'tok-leads' WHERE id = 2")
        .execute(pg)
        .await
        .expect("group");
    for sql in [
        "INSERT INTO domain (domain, create_time, active) VALUES ('example.test', 100, 1)",
        "INSERT INTO bm_options (name, value) VALUES ('ferropost_token_secret', 'test-secret')",
    ] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    let r = call(&app, "/subscription/form", &[], false).await;
    let html = r.body.as_str().expect("html").to_owned();
    assert!(
        html.contains("&lt;b&gt;Leads&lt;/b&gt;") && !html.contains("<b>Leads</b>"),
        "group names escaped"
    );
    let token = html
        .split("name=\"token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("token")
        .to_owned();
    let r = post_form(
        &app,
        "/subscription/form",
        &[
            ("email", "v@x.test"),
            ("group_ids", "1"),
            ("token", "1.bad"),
        ],
    )
    .await;
    assert_eq!(
        (r.status.as_u16(), r.body.as_str()),
        (400, Some("CSRF token not valid"))
    );
    let r = post_form(
        &app,
        "/subscription/form",
        &[
            ("email", "v@x.test"),
            ("name", "<i>Vee</i>"),
            ("group_ids", "1"),
            ("group_ids", "2"),
            ("token", &token),
        ],
    )
    .await;
    assert!(
        r.body.as_str().expect("success page").contains("v@x.test"),
        "{:?}",
        r.body
    );
    // Group 1 subscribes directly; group 2 is double opt-in: pending, with
    // its confirmation mail (Go made both active and mailed "confirmed").
    let state = |g: i32| {
        let pg = pg.clone();
        async move {
            sqlx::query_as::<_, (i32, i32)>(
                "SELECT active, status FROM bm_contacts WHERE email = 'v@x.test' AND group_id = $1",
            )
            .bind(g)
            .fetch_one(&pg)
            .await
            .expect("membership")
        }
    };
    assert_eq!(state(1).await, (1, 1));
    assert_eq!(state(2).await, (1, 0));
    let mut subjects = Vec::new();
    for _ in 0..50 {
        subjects = h
            .smtp
            .mails()
            .iter()
            .filter_map(|m| {
                mail_parser::MessageParser::default()
                    .parse(&m.data)
                    .and_then(|p| p.subject().map(str::to_owned))
            })
            .collect::<Vec<_>>();
        if !subjects.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(subjects, ["Confirm Your Subscription"]);
}

fn copy_templates(h: &Harness) {
    let from = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../core/template");
    let to = h.core_dir().join("template");
    fn copy(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir_all(to).expect("mkdir");
        for entry in std::fs::read_dir(from).expect("read").flatten() {
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).expect("copy");
            }
        }
    }
    copy(&from, &to);
}
