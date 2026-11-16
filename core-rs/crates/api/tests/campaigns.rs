//! Campaigns end to end: the routes, the sender submitting over SMTP to the
//! harness's sink, the queue surviving a restart, warmup limits, stats and
//! one-click unsubscribe.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};

const HOST: &str = "https://news.example.test";
const SENDER: &str = "news@example.test";

struct Mail {
    to: Vec<String>,
    login: String,
    password: String,
    subject: String,
    html: String,
    from_name: String,
    message_id: String,
    list_unsubscribe: String,
    list_unsubscribe_post: String,
}

fn decode(m: &SinkMail) -> Mail {
    let msg = mail_parser::MessageParser::default()
        .parse(&m.data)
        .expect("mime");
    // Header block, unfolded (RFC 5322 2.2.3).
    let text = String::from_utf8_lossy(&m.data);
    let head = text
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .replace("\r\n ", " ")
        .replace("\r\n\t", " ");
    let raw = |name: &str| {
        head.split("\r\n")
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.split_whitespace().collect::<String>())
            })
            .unwrap_or_default()
    };
    Mail {
        to: m.to.clone(),
        login: m.login.clone(),
        password: m.password.clone(),
        subject: msg.subject().unwrap_or_default().to_owned(),
        html: msg.body_html(0).unwrap_or_default().into_owned(),
        from_name: msg
            .from()
            .and_then(|a| a.first())
            .and_then(|a| a.name())
            .unwrap_or_default()
            .to_owned(),
        message_id: msg.message_id().unwrap_or_default().to_owned(),
        list_unsubscribe: raw("List-Unsubscribe"),
        list_unsubscribe_post: raw("List-Unsubscribe-Post"),
    }
}

fn mails_to(h: &Harness, to: &str) -> Vec<Mail> {
    h.smtp
        .mails()
        .iter()
        .filter(|m| m.to.iter().any(|t| t == to))
        .map(decode)
        .collect()
}

async fn task(app: &axum::Router, auth: &str, id: i64) -> Value {
    let r = call(
        app,
        &format!("/api/batch_mail/task/find?id={id}"),
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);
    r.body["data"].clone()
}

async fn scalar(h: &Harness, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&h.store.pg)
        .await
        .expect(sql)
}

#[tokio::test]
async fn campaigns() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let (hash, encoded) = ferropost_sender::smtp::mailbox_credentials("pw").expect("credentials");
    let now = chrono::Utc::now().timestamp();
    for sql in [
        "INSERT INTO domain (domain, create_time, active) VALUES ('example.test', 100, 1)",
        "INSERT INTO bm_options (name, value) VALUES
            ('reverse_proxy_domain', 'https://news.example.test'),
            ('ferropost_token_secret', 'test-secret')",
        r#"INSERT INTO email_templates (id, temp_name, content) VALUES (1, 'News',
            '<html><body><p>Hello {{.Subscriber.name}}</p><a href="https://shop.example/sale">Sale</a></body></html>')"#,
        r#"INSERT INTO bm_contacts (id, email, group_id, active, status, attribs) VALUES
            (1, 'a@x.test', 1, 1, 1, '{"name": "Ann"}'), (2, 'b@x.test', 1, 1, 1, '{}'),
            (3, 'c@x.test', 1, 1, 0, '{}'), (4, 'd@x.test', 1, 0, 1, '{}'),
            (5, 'bounce@x.test', 1, 1, 1, '{}'), (6, 'not-an-email', 1, 1, 1, '{}')"#,
        "INSERT INTO bm_contact_tags (contact_id, tag_id) VALUES (1, 1)",
        "INSERT INTO abnormal_recipient (recipient, count, description) VALUES ('bounce@x.test', 3, 'bounces')",
    ] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    sqlx::query(
        "INSERT INTO mailbox (username, password, password_encode, full_name, maildir, local_part, domain)
         VALUES ($1, $2, $3, 'News', 'news@example.test/', 'news', 'example.test')",
    )
    .bind(SENDER)
    .bind(&hash)
    .bind(&encoded)
    .execute(pg)
    .await
    .expect("mailbox");
    sync_sequences(&h.store).await;

    let state = h.state(&[("FERROPOST_RUST_JOBS", "campaigns")]);
    let app = ferropost_api::app(state.clone());
    let admin = bearer(&token(1, "access_token", "admin-campaigns"));
    let auth = admin.as_str();

    // Without the job the routes stay with Go.
    let r = call(
        &h.app(&[]),
        "/api/batch_mail/task/list?page=1&page_size=10",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["go"], true, "{}", r.body);

    // --- Creating ------------------------------------------------------------
    let base = json!({
        "addresser": SENDER, "subject": "News for {{.Subscriber.Email}}", "full_name": "Acme News",
        "template_id": 1, "group_id": 1, "start_time": now as f64 + 0.5, "threads": 2,
        "tag_ids": [], "tag_logic": "AND", "remark": "r", "unsubscribe": 1, "warmup": 0,
    });
    let with = |patch: Value| {
        let mut body = base.clone();
        for (k, v) in patch.as_object().expect("object") {
            body[k] = v.clone();
        }
        body
    };
    for (patch, code, msg) in [
        (json!({"group_id": 0}), 400, "Must select a contact group"),
        (json!({"template_id": 999}), 400, "Template not found"),
        (json!({"group_id": 2}), 400, "No contacts found in group 2"),
        (
            json!({"tag_ids": [3], "tag_logic": "OR"}),
            400,
            "No contacts found matching the tag filter criteria",
        ),
        (
            json!({"tag_logic": "XOR"}),
            412,
            "The tag_logic value `XOR` is not in acceptable range: AND,OR,NOT",
        ),
        (json!({"subject": ""}), 412, "The subject field is required"),
    ] {
        let r = post(
            &app,
            "/api/batch_mail/task/create",
            auth,
            with(patch.clone()),
        )
        .await;
        assert_eq!(
            (r.body["code"].clone(), r.body["msg"].clone()),
            (json!(code), json!(msg)),
            "{patch}"
        );
    }

    // Tagged VIPs only: just Ann.
    let r = post(
        &app,
        "/api/batch_mail/task/create",
        auth,
        with(json!({"tag_ids": [1], "tag_logic": "OR"})),
    )
    .await;
    assert_eq!(r.body["msg"], "Task created successfully", "{}", r.body);
    let first = r.body["data"]["id"].as_i64().expect("id");
    let t = task(&app, auth, first).await;
    assert_eq!(
        (
            t["recipient_count"].clone(),
            t["tag_ids"].clone(),
            t["tag_logic"].clone(),
            t["start_time"].clone()
        ),
        (json!(1), json!([1]), json!("OR"), json!(now))
    );
    // Dropping the filter before it starts rebuilds the recipients; fields
    // not sent keep their value (Go reset `unsubscribe` to 0).
    let r = post(
        &app,
        "/api/batch_mail/task/update",
        auth,
        json!({"task_id": first, "tag_ids": []}),
    )
    .await;
    assert_eq!(r.body["msg"], "Task update successful", "{}", r.body);
    let t = task(&app, auth, first).await;
    assert_eq!(
        (
            t["recipient_count"].clone(),
            t["tag_ids"].clone(),
            t["unsubscribe"].clone()
        ),
        (json!(2), json!([]), json!(1))
    );
    let recipients: Vec<String> =
        sqlx::query_scalar("SELECT recipient FROM recipient_info WHERE task_id = $1 ORDER BY id")
            .bind(first as i32)
            .fetch_all(pg)
            .await
            .expect("recipients");
    assert_eq!(
        recipients,
        ["a@x.test", "b@x.test"],
        "pending, unsubscribed, bouncing and invalid addresses are left out"
    );

    // A warmup campaign, and one that will "crash" mid-send.
    let r = post(
        &app,
        "/api/batch_mail/task/create",
        auth,
        with(json!({"warmup": 1, "subject": "Warm"})),
    )
    .await;
    let warm = r.body["data"]["id"].as_i64().expect("id");
    assert_eq!(
        scalar(
            &h,
            &format!("SELECT COUNT(*) FROM bm_campaign_warmup WHERE task_id = {warm}")
        )
        .await,
        1
    );
    // A sender without a mailbox, and one scheduled for later.
    let r = post(
        &app,
        "/api/batch_mail/task/create",
        auth,
        with(json!({"addresser": "ghost@example.test"})),
    )
    .await;
    let ghost = r.body["data"]["id"].as_i64().expect("id");
    let r = post(
        &app,
        "/api/batch_mail/task/create",
        auth,
        with(json!({"start_time": now + 3600})),
    )
    .await;
    let later = r.body["data"]["id"].as_i64().expect("id");

    // --- The list ------------------------------------------------------------
    let r = call(
        &app,
        "/api/batch_mail/task/list?page=1&page_size=10&keyword=Warm",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 1, "{}", r.body);
    let row = &r.body["data"]["list"][0];
    assert_eq!(
        (
            row["group_name"].clone(),
            row["template_name"].clone(),
            row["progress"].clone(),
            row["unsent_count"].clone()
        ),
        (json!("Customers"), json!("News"), json!(0), json!(2))
    );
    // Two recipients at 88 an hour (eight groups of min(29, 280 / 24)).
    assert_eq!(row["estimated_time_with_warmup"], 81);
    let r = call(
        &app,
        "/api/batch_mail/task/list?page=1&page_size=10&status=2",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 0);

    // --- Pause, resume, speed, update rules ----------------------------------
    let r = post(
        &app,
        "/api/batch_mail/task/pause",
        auth,
        json!({"task_id": later}),
    )
    .await;
    assert_eq!(r.body["msg"], "Cannot pause task because it is not started");
    let r = post(
        &app,
        "/api/batch_mail/task/resume",
        auth,
        json!({"task_id": later}),
    )
    .await;
    assert_eq!(
        r.body["msg"],
        "Cannot resume task because it is not started"
    );
    let r = post(
        &app,
        "/api/batch_mail/task/speed",
        auth,
        json!({"task_id": later, "threads": 7}),
    )
    .await;
    assert_eq!(
        r.body["data"],
        json!({"task_id": later, "threads": 7, "emails_per_minute": 8400}),
        "{}",
        r.body
    );
    for (threads, msg) in [
        (0, "Threads must be greater than zero"),
        (101, "Threads cannot exceed 100"),
    ] {
        let r = post(
            &app,
            "/api/batch_mail/task/speed",
            auth,
            json!({"task_id": later, "threads": threads}),
        )
        .await;
        assert_eq!(r.body["msg"], msg);
    }
    sqlx::query("UPDATE email_tasks SET task_process = 1 WHERE id = $1")
        .bind(later as i32)
        .execute(pg)
        .await
        .expect("running");
    let r = post(
        &app,
        "/api/batch_mail/task/update",
        auth,
        json!({"task_id": later, "remark": "x"}),
    )
    .await;
    assert_eq!(
        r.body["msg"],
        "The task is currently running. Please pause the task first."
    );
    let r = post(
        &app,
        "/api/batch_mail/task/pause",
        auth,
        json!({"task_id": later}),
    )
    .await;
    assert_eq!(r.body["msg"], "Task paused successfully");
    let t = task(&app, auth, later).await;
    assert_eq!(
        (
            t["pause"].clone(),
            t["task_process"].clone(),
            t["threads"].clone()
        ),
        (json!(1), json!(3), json!(7))
    );
    let r = post(
        &app,
        "/api/batch_mail/task/delete",
        auth,
        json!({"id": later}),
    )
    .await;
    assert_eq!(r.body["msg"], "Task deleted successfully");
    assert_eq!(
        scalar(
            &h,
            &format!("SELECT COUNT(*) FROM recipient_info WHERE task_id = {later}")
        )
        .await,
        0
    );
    let r = call(
        &app,
        &format!("/api/batch_mail/task/find?id={later}"),
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 404);

    // --- Test mail -----------------------------------------------------------
    let r = post(&app, "/api/batch_mail/task/send_test", auth, json!({
        "addresser": SENDER, "subject": "Test {{.Subscriber.Email}}", "recipient": "t@x.test", "template_id": 1})).await;
    assert_eq!(r.body["msg"], "send email successfully", "{}", r.body);
    let test = mails_to(&h, "t@x.test");
    assert_eq!(
        test[0].subject, "Test t@x.test",
        "rendered even for a non-contact (Go sent raw tags)"
    );
    assert!(
        test[0]
            .html
            .contains(&format!("{HOST}/unsubscribe.html?jwt=")),
        "{}",
        test[0].html
    );
    let r = post(&app, "/api/batch_mail/task/send_test", auth, json!({
        "addresser": "ghost@example.test", "subject": "x", "recipient": "t@x.test", "template_id": 1})).await;
    assert_eq!(
        r.body["msg"],
        "create email sender failed: : password not found for ghost@example.test"
    );

    // --- Sending -------------------------------------------------------------
    // The warmup campaign's claims were left behind by a "crash".
    sqlx::query("UPDATE recipient_info SET is_sent = 2 WHERE task_id = $1")
        .bind(warm as i32)
        .execute(pg)
        .await
        .expect("claims");
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let jobs = ferropost_api::campaigns::spawn(&state, stop_rx);
    assert_eq!(jobs.len(), 2);
    let mut done = false;
    for _ in 0..200 {
        let states: Vec<(i32, i16, i16)> =
            sqlx::query_as("SELECT id, task_process, pause FROM email_tasks ORDER BY id")
                .fetch_all(pg)
                .await
                .expect("states");
        let of = |id: i64| {
            states
                .iter()
                .find(|s| i64::from(s.0) == id)
                .map(|s| (s.1, s.2))
        };
        if of(first) == Some((2, 0)) && of(warm) == Some((2, 0)) && of(ghost) == Some((3, 1)) {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "campaigns did not finish");
    let _ = stop.send(true);
    for job in jobs {
        job.await.expect("job");
    }
    assert_eq!(
        scalar(
            &h,
            &format!(
                "SELECT COUNT(*) FROM recipient_info WHERE is_sent <> 1 AND task_id <> {ghost}"
            )
        )
        .await,
        0
    );
    assert_eq!(
        scalar(
            &h,
            &format!("SELECT COUNT(*) FROM recipient_info WHERE task_id = {ghost} AND is_sent = 0")
        )
        .await,
        2,
        "nothing was claimed for good"
    );

    // Each recipient got the first campaign once, personalised and tracked.
    let ann: Vec<Mail> = mails_to(&h, "a@x.test")
        .into_iter()
        .filter(|m| m.subject == "News for a@x.test")
        .collect();
    assert_eq!(ann.len(), 1);
    let ann = &ann[0];
    assert_eq!(
        (
            ann.login.as_str(),
            ann.password.as_str(),
            ann.from_name.as_str()
        ),
        (SENDER, "pw", "Acme News")
    );
    assert!(ann.html.contains("Hello Ann"), "{}", ann.html);
    assert!(
        !ann.html.contains(r#"href="https://shop.example/sale""#),
        "click tracked: {}",
        ann.html
    );
    assert_eq!(
        ann.html.matches(&format!("{HOST}/pmta/v2.")).count(),
        2,
        "link and pixel"
    );
    assert!(
        ann.html
            .contains(&format!("{HOST}/unsubscribe_new.html?jwt="))
    );
    assert!(
        ann.list_unsubscribe
            .starts_with(&format!("<{HOST}/api/unsubscribe/one_click?jwt=")),
        "{}",
        ann.list_unsubscribe
    );
    assert_eq!(ann.list_unsubscribe_post, "List-Unsubscribe=One-Click");
    assert_eq!(ann.to, ["a@x.test"]);
    let stored: String = sqlx::query_scalar(
        "SELECT message_id FROM recipient_info WHERE task_id = $1 AND recipient = 'a@x.test'",
    )
    .bind(first as i32)
    .fetch_one(pg)
    .await
    .expect("message id");
    assert_eq!(stored, ann.message_id);
    assert_eq!(
        mails_to(&h, "b@x.test").len(),
        2,
        "first and warmup campaigns"
    );
    // Warmup limits counted under the recipient's provider group.
    let redis_count: Option<String> = {
        use fred::prelude::KeysInterface;
        h.store
            .redis
            .get("warmup:vw:d:198.51.100.1:other")
            .await
            .expect("redis")
    };
    assert_eq!(redis_count.as_deref(), Some("2"));

    // --- Stats from the mail log ---------------------------------------------
    let bob_id: String = sqlx::query_scalar(
        "SELECT message_id FROM recipient_info WHERE task_id = $1 AND recipient = 'b@x.test'",
    )
    .bind(first as i32)
    .fetch_one(pg)
    .await
    .expect("message id");
    let at = now * 1000;
    for (pmid, mid, recipient, status, dsn) in [
        ("P1", ann.message_id.as_str(), "a@x.test", "sent", "2.0.0"),
        ("P2", bob_id.as_str(), "b@x.test", "bounced", "5.1.1"),
    ] {
        sqlx::query("INSERT INTO mailstat_message_ids (postfix_message_id, log_time_millis, message_id) VALUES ($1, $2, $3)")
            .bind(pmid).bind(at).bind(mid).execute(pg).await.expect("mid");
        sqlx::query("INSERT INTO mailstat_senders (postfix_message_id, log_time_millis, sender) VALUES ($1, $2, $3)")
            .bind(pmid).bind(at).bind(SENDER).execute(pg).await.expect("sender");
        sqlx::query("INSERT INTO mailstat_send_mails (postfix_message_id, log_time_millis, status, recipient, mail_provider, dsn)
                     VALUES ($1, $2, $3, $4, 'other', $5)")
            .bind(pmid).bind(at).bind(status).bind(recipient).bind(dsn).execute(pg).await.expect("delivery");
    }
    let refreshed = ferropost_store::campaigns::refresh_stats(pg, now + 1)
        .await
        .expect("refresh");
    assert!(refreshed >= 3, "{refreshed}");
    let r = call(
        &app,
        "/api/batch_mail/task/list?page=1&page_size=10",
        &[("authorization", auth)],
        false,
    )
    .await;
    let row = r.body["data"]["list"]
        .as_array()
        .expect("list")
        .iter()
        .find(|t| t["id"] == first)
        .expect("row")
        .clone();
    assert_eq!(
        [
            &row["sendsCount"],
            &row["deliveredCount"],
            &row["bouncedCount"],
            &row["progress"],
            &row["success_count"],
            &row["error_count"],
            &row["unsent_count"]
        ],
        [
            &json!(2),
            &json!(1),
            &json!(1),
            &json!(100),
            &json!(1),
            &json!(1),
            &json!(0)
        ],
        "{row}"
    );
    for (status, total) in [(1, 1), (0, 1), (-1, 2)] {
        let r = call(
            &app,
            &format!("/api/batch_mail/tracking/logs?task_id={first}&status={status}&domain=x.test"),
            &[("authorization", auth)],
            false,
        )
        .await;
        assert_eq!(
            r.body["data"]["total"], total,
            "status {status}: {}",
            r.body
        );
    }
    let r = call(
        &app,
        &format!("/api/batch_mail/tracking/mail_provider?task_id={first}&status=-1"),
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"], json!([{"domain": "x.test", "count": 2}]));
    let r = call(
        &app,
        &format!(
            "/api/batch_mail/task/stat_chart?task_id={first}&start_time={}&end_time={}",
            now - 3600,
            now + 60
        ),
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["dashboard"]["sends"], 2, "{}", r.body);
    let r = call(
        &app,
        &format!("/api/batch_mail/task/send_count?task_id={first}"),
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total_sent"], 2, "{}", r.body);
    let r = call(
        &app,
        &format!(
            "/api/batch_mail/task/overview?start_time={}&end_time={}",
            now - 3600,
            now + 60
        ),
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(
        (
            r.body["data"]["sends"].clone(),
            r.body["data"]["delivered"].clone()
        ),
        (json!(2), json!(1)),
        "{}",
        r.body
    );

    // --- One-click unsubscribe ------------------------------------------------
    let url = ann.list_unsubscribe.trim_matches(['<', '>']).to_owned();
    let path = url.strip_prefix(HOST).expect("host");
    let r = call(&app, path, &[], false).await;
    assert_eq!(r.status, 302);
    assert!(
        r.headers["location"]
            .to_str()
            .expect("location")
            .starts_with("/unsubscribe_new.html?jwt=")
    );
    assert_eq!(
        scalar(
            &h,
            "SELECT active::bigint FROM bm_contacts WHERE email = 'a@x.test' AND group_id = 1"
        )
        .await,
        1,
        "GET does not unsubscribe"
    );
    let r = send(&app, "POST", path, &[], None, false).await;
    assert_eq!(
        r.body["msg"], "You have been successfully unsubscribed",
        "{}",
        r.body
    );
    assert_eq!(
        scalar(
            &h,
            "SELECT active::bigint FROM bm_contacts WHERE email = 'a@x.test' AND group_id = 1"
        )
        .await,
        0
    );
    assert_eq!(
        scalar(
            &h,
            &format!("SELECT COUNT(*) FROM unsubscribe_records WHERE task_id = {first}")
        )
        .await,
        1
    );
}
