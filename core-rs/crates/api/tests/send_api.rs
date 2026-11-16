//! The send API end to end: managing keys, queueing through `send` and
//! `batch_send` with their error codes, and the sender delivering the
//! queue to the harness's SMTP sink.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};

const HOST: &str = "https://news.example.test";
const SENDER: &str = "news@example.test";

async fn api_post(app: &axum::Router, uri: &str, key: &str, body: Value) -> Reply {
    send(app, "POST", uri, &[("x-api-key", key)], Some(body), false).await
}

async fn scalar(h: &Harness, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&h.store.pg)
        .await
        .expect(sql)
}

fn mail_to(h: &Harness, to: &str) -> Vec<mail_parser::Message<'static>> {
    h.smtp
        .mails()
        .into_iter()
        .filter(|m| m.to.iter().any(|t| t == to))
        .map(|m| {
            mail_parser::MessageParser::default()
                .parse(&m.data)
                .expect("mime")
                .into_owned()
        })
        .collect()
}

#[tokio::test]
async fn send_api() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let (hash, encoded) = ferropost_sender::smtp::mailbox_credentials("pw").expect("credentials");
    for sql in [
        "INSERT INTO domain (domain, create_time, active) VALUES ('example.test', 100, 1)",
        "INSERT INTO bm_options (name, value) VALUES
            ('reverse_proxy_domain', 'https://news.example.test'),
            ('ferropost_token_secret', 'test-secret'), ('unsubscribe_jwt_secret', 'go-secret')",
        r#"INSERT INTO email_templates (id, temp_name, content) VALUES (1, 'Order',
            '<html><body><p>Hi {{.API.first}} {{.Subscriber.Email}}</p><a href="https://shop.example/x">x</a></body></html>')"#,
        "INSERT INTO bm_contacts (email, group_id, active, status) VALUES ('gone@x.test', 1, 0, 1)",
    ] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    for user in [SENDER, "sales@example.test"] {
        sqlx::query(
            "INSERT INTO mailbox (username, password, password_encode, full_name, maildir, local_part, domain)
             VALUES ($1, $2, $3, '', '', split_part($1, '@', 1), 'example.test')",
        )
        .bind(user)
        .bind(&hash)
        .bind(&encoded)
        .execute(pg)
        .await
        .expect("mailbox");
    }
    sync_sequences(&h.store).await;
    let state = h.state(&[("FERROPOST_RUST_JOBS", "api_mail")]);
    let app = ferropost_api::app(state.clone());
    let admin = bearer(&token(1, "access_token", "admin-api"));
    let auth = admin.as_str();

    // --- Keys ------------------------------------------------------------------
    let base = json!({
        "api_name": "Shop", "template_id": 1, "subject": "Order {{.API.order}}", "addresser": SENDER,
        "full_name": "Shop", "unsubscribe": 1, "active": 1, "track_open": 1, "track_click": 1,
        "ip_whitelist": [" 203.0.113.9 ", "bad", "203.0.113.9"],
    });
    let with = |patch: Value| {
        let mut body = base.clone();
        for (k, v) in patch.as_object().expect("object") {
            body[k] = v.clone();
        }
        body
    };
    let r = post(
        &app,
        "/api/batch_mail/api/create",
        auth,
        with(json!({"template_id": 999})),
    )
    .await;
    assert_eq!(r.body["msg"], "Email template does not exist");
    let r = post(
        &app,
        "/api/batch_mail/api/create",
        auth,
        with(json!({"addresser": ""})),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    for patch in [
        json!({}),
        json!({"api_name": "Group API", "group_id": 1, "ip_whitelist": []}),
        json!({"api_name": "Locked", "ip_whitelist": ["198.51.100.77"]}),
    ] {
        let r = post(&app, "/api/batch_mail/api/create", auth, with(patch)).await;
        assert_eq!(r.body["msg"], "Create API successfully", "{}", r.body);
    }
    let r = call(
        &app,
        "/api/batch_mail/api/list?page=1&page_size=10&active=-1",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 3, "{}", r.body);
    let list = r.body["data"]["list"].as_array().expect("list").clone();
    let find = |name: &str| {
        list.iter()
            .find(|a| a["api_name"] == name)
            .expect(name)
            .clone()
    };
    let (shop, group_api, locked) = (find("Shop"), find("Group API"), find("Locked"));
    assert_eq!(shop["ip_whitelist"], json!(["203.0.113.9"]));
    assert_eq!(
        shop["server_addresser"],
        format!("{HOST}/api/batch_mail/api/send")
    );
    assert_eq!(shop["api_key"].as_str().map(str::len), Some(64));
    let shop_key = shop["api_key"].as_str().expect("key").to_owned();
    let group_key = group_api["api_key"].as_str().expect("key").to_owned();
    let shop_id = shop["id"].as_i64().expect("id");

    // --- Queueing ----------------------------------------------------------------
    let url = "/api/batch_mail/api/send";
    for (key, body, code, msg) in [
        (
            "",
            json!({"recipient": "r1@x.test"}),
            1001,
            "API key is invalid",
        ),
        (
            "wrong",
            json!({"recipient": "r1@x.test"}),
            1001,
            "API key is invalid",
        ),
        (
            locked["api_key"].as_str().expect("key"),
            json!({"recipient": "r1@x.test"}),
            1002,
            "IP not allowed",
        ),
        (
            &shop_key,
            json!({"recipient": "nope"}),
            1003,
            "Invalid recipient",
        ),
        (
            &shop_key,
            json!({"recipient": "r1@x.test", "addresser": "admin@other.test"}),
            1005,
            "The addresser must be on the API's sending domain",
        ),
        (
            &shop_key,
            json!({"recipient": "r1@x.test", "addresser": "ghost@example.test"}),
            1005,
            "Failed to create email sender: password not found for ghost@example.test",
        ),
        (
            &group_key,
            json!({"recipient": "gone@x.test"}),
            1003,
            "Failed to process recipient: the recipient has unsubscribed from the current group and cannot send",
        ),
    ] {
        let r = api_post(&app, url, key, body.clone()).await;
        assert_eq!(
            (r.body["code"].clone(), r.body["msg"].clone()),
            (json!(code), json!(msg)),
            "{body}"
        );
    }
    let r = api_post(
        &app,
        url,
        &shop_key,
        json!({"recipient": "r1@x.test", "attribs": {"first": "Ray", "order": 42}}),
    )
    .await;
    assert_eq!(r.body["msg"], "Email sent successfully", "{}", r.body);
    let r = api_post(
        &app,
        url,
        &shop_key,
        json!({"recipient": "r3@x.test", "addresser": "sales@example.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 0, "same-domain sender: {}", r.body);
    // Without its own group the API files recipients in api_group_<id>.
    assert_eq!(
        scalar(
            &h,
            &format!(
                "SELECT COUNT(*) FROM bm_contacts c JOIN bm_contact_groups g ON g.id = c.group_id
                              WHERE g.name = 'api_group_{shop_id}' AND c.active = 1"
            )
        )
        .await,
        2
    );

    let batch = "/api/batch_mail/api/batch_send";
    for (body, msg) in [
        (json!({"recipients": []}), "Recipients cannot be empty"),
        (json!({"recipients": ["bad", " "]}), "No valid recipients"),
        (
            json!({"recipients": ["gone@x.test"]}),
            "No valid recipients to insert",
        ),
    ] {
        let r = api_post(&app, batch, &group_key, body).await;
        assert_eq!(
            (r.body["code"].clone(), r.body["msg"].clone()),
            (json!(1003), json!(msg))
        );
    }
    let r = api_post(
        &app,
        batch,
        &group_key,
        json!({"recipients": ["r2@x.test", "gone@x.test", "bad", "r2@x.test"]}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "Batch email send request accepted, 1 emails queued",
        "{}",
        r.body
    );

    // --- Sending -----------------------------------------------------------------
    // r3's row was claimed by a sender that then stopped.
    sqlx::query("UPDATE api_mail_logs SET status = 1 WHERE recipient = 'r3@x.test'")
        .execute(pg)
        .await
        .expect("claim");
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let jobs = ferropost_api::api_mail::spawn(&state, stop_rx);
    assert_eq!(jobs.len(), 1);
    let mut settled = false;
    for _ in 0..100 {
        if scalar(&h, "SELECT COUNT(*) FROM api_mail_logs WHERE status <> 2").await == 0 {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(settled, "queue not sent");
    // Queued while running: sent without waiting for a poll.
    let r = api_post(&app, url, &shop_key, json!({"recipient": "r4@x.test"})).await;
    assert_eq!(r.body["code"], 0);
    for _ in 0..30 {
        if !mail_to(&h, "r4@x.test").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(mail_to(&h, "r4@x.test").len(), 1, "woken by the queue");
    let _ = stop.send(true);
    for job in jobs {
        job.await.expect("job");
    }

    let ray = mail_to(&h, "r1@x.test");
    assert_eq!(ray.len(), 1);
    let ray = &ray[0];
    assert_eq!(ray.subject(), Some("Order 42"));
    let html = ray.body_html(0).expect("html").into_owned();
    assert!(html.contains("Hi Ray r1@x.test"), "{html}");
    assert!(
        html.contains(&format!("{HOST}/unsubscribe_new.html?jwt=")),
        "group unsubscribe: {html}"
    );
    let token = html
        .split(&format!("{HOST}/pmta/"))
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("tracked link");
    let (event, _) =
        ferropost_domain::tracking::decode(token, &state.tracking_key).expect("signed");
    assert_eq!(event.campaign_id, 1_000_000_000 + shop_id);
    let stored: String =
        sqlx::query_scalar("SELECT message_id FROM api_mail_logs WHERE recipient = 'r1@x.test'")
            .fetch_one(pg)
            .await
            .expect("message id");
    assert_eq!(ray.message_id(), Some(stored.as_str()));
    let raw = h
        .smtp
        .mails()
        .into_iter()
        .find(|m| m.to == ["r1@x.test"])
        .map(|m| String::from_utf8_lossy(&m.data).into_owned())
        .expect("raw mail");
    assert!(raw.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
    let logins: Vec<(String, Vec<String>)> = h
        .smtp
        .mails()
        .iter()
        .map(|m| (m.login.clone(), m.to.clone()))
        .collect();
    assert!(
        logins.contains(&(
            "sales@example.test".to_owned(),
            vec!["r3@x.test".to_owned()]
        )),
        "{logins:?}"
    );
    assert_eq!(mail_to(&h, "r2@x.test").len(), 1);
    assert!(mail_to(&h, "gone@x.test").is_empty());

    // --- Stats -------------------------------------------------------------------
    let now = chrono::Utc::now().timestamp() * 1000;
    for sql in [
        format!(
            "INSERT INTO mailstat_message_ids (postfix_message_id, log_time_millis, message_id) VALUES ('P1', {now}, '{stored}')"
        ),
        format!(
            "INSERT INTO mailstat_send_mails (postfix_message_id, log_time_millis, status, dsn) VALUES ('P1', {now}, 'sent', '2.0.0')"
        ),
        format!(
            "INSERT INTO mailstat_opened (campaign_id, postfix_message_id, log_time_millis) VALUES ({}, 'P1', {now})",
            1_000_000_000 + shop_id
        ),
    ] {
        sqlx::query(&sql).execute(pg).await.expect("stats");
    }
    let r = call(
        &app,
        "/api/batch_mail/api/list?page=1&page_size=10&keyword=Shop",
        &[("authorization", auth)],
        false,
    )
    .await;
    let row = &r.body["data"]["list"][0];
    // r1, r3 and r4 were sent; one delivery and one open logged so far.
    assert_eq!(
        (
            row["send_count"].clone(),
            row["success_count"].clone(),
            row["delivery_rate"].clone(),
            row["open_rate"].clone()
        ),
        (json!(3), json!(1), json!(33.33), json!(33.33)),
        "{row}"
    );
    let r = call(
        &app,
        "/api/batch_mail/api/overview_stats",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total_send"], 4, "{}", r.body);

    // --- Legacy unsubscribe links from Go's API mail -----------------------------
    let legacy = ferropost_sender::tokens::issue_unsubscribe(
        &ferropost_sender::tokens::TokenKeys {
            current: "go-secret".into(),
            legacy: Vec::new(),
        },
        ferropost_sender::tokens::UnsubscribeClaims {
            email: "r1@x.test".into(),
            template_id: 1,
            task_id: shop_id,
            group_id: 0,
        },
        chrono::Utc::now().timestamp(),
    );
    let r = post(
        &app,
        "/api/unsubscribe/user_group",
        "",
        json!({"jwt": legacy}),
    )
    .await;
    assert_eq!(
        r.body["code"], 0,
        "accepted on the strength of the API delivery: {}",
        r.body
    );

    // --- Key changes ---------------------------------------------------------------
    let r = post(
        &app,
        "/api/batch_mail/api/update",
        auth,
        json!({"id": shop_id, "api_name": "Shop 2", "reset_key": true}),
    )
    .await;
    assert_eq!(r.body["msg"], "Update API successfully", "{}", r.body);
    let r = api_post(&app, url, &shop_key, json!({"recipient": "r1@x.test"})).await;
    assert_eq!(r.body["code"], 1001, "the old key no longer works");
    let updated: (String, i16, i16, String) = sqlx::query_as(
        "SELECT api_key, track_open, unsubscribe, subject FROM api_templates WHERE id = $1",
    )
    .bind(shop_id as i32)
    .fetch_one(pg)
    .await
    .expect("updated");
    assert_ne!(updated.0, shop_key);
    assert_eq!(
        (updated.1, updated.2, updated.3.as_str()),
        (1, 1, "Order {{.API.order}}"),
        "unchanged settings kept"
    );
    assert_eq!(
        scalar(
            &h,
            &format!("SELECT COUNT(*) FROM api_ip_whitelist WHERE api_id = {shop_id}")
        )
        .await,
        1
    );
    sqlx::query(
        "UPDATE api_templates SET expire_time = 60, last_key_update_time = $2 WHERE id = $1",
    )
    .bind(shop_id as i32)
    .bind((chrono::Utc::now().timestamp() - 120) as i32)
    .execute(pg)
    .await
    .expect("expire");
    let r = api_post(&app, url, &updated.0, json!({"recipient": "r1@x.test"})).await;
    assert_eq!(r.body["code"], 1001, "expired key");

    let r = post(
        &app,
        "/api/batch_mail/api/delete",
        auth,
        json!({"id": group_api["id"]}),
    )
    .await;
    assert_eq!(r.body["msg"], "Delete API successfully");
    assert_eq!(
        scalar(
            &h,
            &format!(
                "SELECT COUNT(*) FROM api_mail_logs WHERE api_id = {}",
                group_api["id"]
            )
        )
        .await,
        0
    );
    let r = post(
        &app,
        "/api/batch_mail/api/delete",
        auth,
        json!({"id": group_api["id"]}),
    )
    .await;
    assert_eq!(r.body["msg"], "API does not exist");
}
