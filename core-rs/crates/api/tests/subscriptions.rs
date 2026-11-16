//! Subscribe and unsubscribe flows end to end, including the mail they
//! send (submitted over SMTP to the harness's in-process sink).

mod common;

use std::path::Path;
use std::time::Duration;

use common::*;
use ferropost_sender::tokens::{
    SubscribeClaims, TokenKeys, UnsubscribeClaims, issue_subscribe, issue_unsubscribe,
};
use serde_json::{Value, json};

const HOST: &str = "https://news.example.test";

fn keys(secret: &str) -> TokenKeys {
    TokenKeys {
        current: secret.to_owned(),
        legacy: Vec::new(),
    }
}

fn unsubscribe_token(secret: &str, email: &str, task_id: i64, group_id: i64) -> String {
    issue_unsubscribe(
        &keys(secret),
        UnsubscribeClaims {
            email: email.to_owned(),
            template_id: 3,
            task_id,
            group_id,
        },
        chrono::Utc::now().timestamp(),
    )
}

fn location(reply: &Reply) -> String {
    assert_eq!(reply.status, 302, "{:?}", reply.body);
    reply
        .headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy");
        }
    }
}

/// A decoded message from the SMTP sink.
#[derive(Debug)]
struct Received {
    login: String,
    envelope_from: String,
    from: String,
    html: String,
    text: String,
}

fn decode(mail: &SinkMail) -> Option<(String, Received)> {
    let message = mail_parser::MessageParser::default().parse(&mail.data)?;
    let from = message
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .unwrap_or_default()
        .to_owned();
    Some((
        message.subject().unwrap_or_default().to_owned(),
        Received {
            login: mail.login.clone(),
            envelope_from: mail.from.clone(),
            from,
            html: message.body_html(0).unwrap_or_default().into_owned(),
            text: message.body_text(0).unwrap_or_default().into_owned(),
        },
    ))
}

/// Mail to `to` with `subject`, waiting until there are `count` (mail is
/// sent in the background).
async fn wait_for(h: &Harness, to: &str, subject: &str, count: usize) -> Vec<Received> {
    for _ in 0..100 {
        let found: Vec<Received> = h
            .smtp
            .mails()
            .iter()
            .filter(|m| m.to.iter().any(|t| t == to))
            .filter_map(decode)
            .filter(|(s, _)| s == subject)
            .map(|(_, r)| r)
            .collect();
        if found.len() >= count {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("fewer than {count} mail(s) {subject:?} to {to} after 10s");
}

/// A link in a mail body starting with `prefix`, up to the closing quote.
fn link(html: &str, prefix: &str) -> String {
    let start = html
        .find(prefix)
        .unwrap_or_else(|| panic!("{prefix} in {html}"));
    let rest = &html[start..];
    rest[..rest.find(['"', '\'', '<', ' ']).unwrap_or(rest.len())].replace("&amp;", "&")
}

async fn contact(h: &Harness, email: &str, group: i32) -> Option<(i32, i32, Value)> {
    sqlx::query_as(
        "SELECT active, status, attribs FROM bm_contacts WHERE email = $1 AND group_id = $2",
    )
    .bind(email)
    .bind(group)
    .fetch_optional(&h.store.pg)
    .await
    .expect("contact")
}

#[tokio::test]
async fn subscribe_and_unsubscribe_flows() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    for sql in [
        "UPDATE bm_contact_groups SET token = 'tok-customers', send_welcome_email = 1 WHERE id = 1",
        "UPDATE bm_contact_groups SET token = 'tok-leads', double_optin = 1, send_welcome_email = 1,
            send_unsubscribe_email = 1, unsubscribe_redirect_url = 'https://example.test/bye'
          WHERE id = 2",
        "INSERT INTO domain (domain, create_time, active) VALUES ('example.test', 100, 1),
            ('inactive.test', 50, 0)",
        "INSERT INTO bm_options (name, value) VALUES
            ('reverse_proxy_domain', 'https://news.example.test/'),
            ('ferropost_token_secret', 'test-secret'), ('unsubscribe_jwt_secret', 'go-secret')",
        "INSERT INTO email_tasks (id, group_id, addresser) VALUES (7, 2, 'news@example.test')",
        "INSERT INTO recipient_info (task_id, recipient, message_id) VALUES (7, 'old@x.test', 'm1')",
    ] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    sync_sequences(&h.store).await;
    copy_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../core/template"),
        &h.core_dir().join("template"),
    );
    let app = h.app(&[]);

    // --- Subscribe form ------------------------------------------------
    for uri in [
        "/api/subscribe/submit",
        "/api/subscribe/submit?token=",
        "/api/subscribe/submit?token=nope",
    ] {
        let r = post_form(&app, uri, &[("email", "ann@x.test")]).await;
        assert_eq!(location(&r), "/invalid.html", "{uri}");
    }
    // Go stored any text as an address.
    let r = post_form(
        &app,
        "/api/subscribe/submit?token=tok-customers",
        &[("email", "not an address")],
    )
    .await;
    assert_eq!(location(&r), "/invalid.html");

    // Single opt-in, posted as the embedded form does.
    let r = post_form(
        &app,
        "/api/subscribe/submit?token=tok-customers",
        &[
            ("email", "ann@x.test"),
            ("name", "Ann"),
            ("attribs", r#"{"name":"Ann","company":"Acme"}"#),
        ],
    )
    .await;
    assert_eq!(location(&r), format!("{HOST}/subscribe_success.html"));
    assert_eq!(
        contact(&h, "ann@x.test", 1).await,
        Some((1, 1, json!({"name": "Ann", "company": "Acme"})))
    );
    let r = send(
        &app,
        "POST",
        "/api/subscribe/submit",
        &[],
        Some(json!({"email": "ann@x.test", "token": "tok-customers"})),
        false,
    )
    .await;
    assert_eq!(location(&r), format!("{HOST}/already_subscribed.html"));

    // Double opt-in: pending until confirmed; a second submission merges
    // attributes but does not mail again.
    let r = post_form(
        &app,
        "/api/subscribe/submit?token=tok-leads",
        &[("email", "bob@x.test"), ("attribs", r#"{"name":"Bob"}"#)],
    )
    .await;
    assert_eq!(location(&r), format!("{HOST}/subscribe_confirm.html"));
    let r = send(
        &app,
        "POST",
        "/api/subscribe/submit?token=tok-leads",
        &[],
        Some(json!({"email": "bob@x.test", "attribs": {"city": "Oslo"}})),
        false,
    )
    .await;
    assert_eq!(location(&r), format!("{HOST}/subscribe_confirm.html"));
    assert_eq!(
        contact(&h, "bob@x.test", 2).await,
        Some((1, 0, json!({"name": "Bob", "city": "Oslo"})))
    );

    let mails = wait_for(&h, "bob@x.test", "Confirm Your Subscription", 1).await;
    let confirmation = &mails[0];
    assert_eq!(confirmation.from, "noreply@example.test");
    assert_eq!(confirmation.envelope_from, "noreply@example.test");
    assert_eq!(confirmation.login, "noreply@example.test");
    assert!(!confirmation.text.is_empty(), "plain-text part");
    assert!(!confirmation.html.contains("{{"), "{}", confirmation.html);
    let confirm_url = link(
        &confirmation.html,
        &format!("{HOST}/api/subscribe/confirm?token="),
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        wait_for(&h, "bob@x.test", "Confirm Your Subscription", 1)
            .await
            .len(),
        1,
        "the second submission must not mail again"
    );
    let confirm_path = confirm_url.strip_prefix(HOST).expect("same host");
    let r = call(&app, confirm_path, &[], false).await;
    assert_eq!(location(&r), format!("{HOST}/subscribe_success.html"));
    assert_eq!(
        contact(&h, "bob@x.test", 2).await.map(|c| (c.0, c.1)),
        Some((1, 1))
    );
    let r = call(&app, confirm_path, &[], false).await;
    assert_eq!(location(&r), format!("{HOST}/already_subscribed.html"));

    // Confirmation needs a valid token for an address that asked.
    let r = call(&app, "/api/subscribe/confirm?token=garbage", &[], false).await;
    assert_eq!(location(&r), "/invalid.html");
    let stranger = issue_subscribe(
        &keys("test-secret"),
        SubscribeClaims {
            email: "eve@x.test".into(),
            group_token: "tok-leads".into(),
        },
        chrono::Utc::now().timestamp(),
    );
    let r = call(
        &app,
        &format!("/api/subscribe/confirm?token={stranger}"),
        &[],
        false,
    )
    .await;
    assert_eq!(location(&r), "/invalid.html");
    assert_eq!(contact(&h, "eve@x.test", 2).await, None);

    wait_for(&h, "ann@x.test", "Welcome Aboard!", 1).await;
    wait_for(&h, "bob@x.test", "Welcome Aboard!", 1).await;

    // --- Unsubscribe page ----------------------------------------------
    sqlx::query(
        "INSERT INTO bm_contacts (email, group_id, active, status) VALUES ('ann@x.test', 2, 1, 1)",
    )
    .execute(pg)
    .await
    .expect("ann in leads");
    let ann = unsubscribe_token("test-secret", "ann@x.test", 0, 1);

    // Go listed anyone's groups for a bare address.
    let r = post(
        &app,
        "/api/unsubscribe/user_group",
        "",
        json!({"email": "ann@x.test"}),
    )
    .await;
    assert_eq!(r.body["code"], 400, "{}", r.body);
    let r = post(
        &app,
        "/api/unsubscribe/user_group",
        "",
        json!({"email": "other@x.test", "jwt": ann}),
    )
    .await;
    assert_eq!(r.body["code"], 400, "{}", r.body);
    let groups = |r: &Reply| -> Vec<String> {
        r.body["data"]
            .as_array()
            .expect("groups")
            .iter()
            .map(|g| g["name"].as_str().expect("name").to_owned())
            .collect()
    };
    let r = post(
        &app,
        "/api/unsubscribe/user_group",
        "",
        json!({"email": "ann@x.test", "jwt": ann}),
    )
    .await;
    assert_eq!(groups(&r), ["Customers", "Leads"], "{}", r.body);

    for body in [
        json!({"jwt": ann, "group_id": []}),
        json!({"jwt": "garbage", "group_id": [1]}),
        json!({"group_id": [1]}),
    ] {
        let r = post(&app, "/api/unsubscribe", "", body.clone()).await;
        assert_eq!(r.body["success"], false, "{body}: {}", r.body);
    }
    let r = post(
        &app,
        "/api/unsubscribe",
        "",
        json!({"jwt": ann, "group_id": [1]}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "You have been successfully unsubscribed",
        "{}",
        r.body
    );
    assert_eq!(contact(&h, "ann@x.test", 1).await.map(|c| c.0), Some(0));
    let record: (i32, i32, i32) = sqlx::query_as(
        "SELECT group_id, template_id, task_id FROM unsubscribe_records WHERE email = 'ann@x.test'",
    )
    .fetch_one(pg)
    .await
    .expect("record");
    assert_eq!(record, (1, 3, 0));
    let r = post(&app, "/api/unsubscribe/user_group", "", json!({"jwt": ann})).await;
    assert_eq!(groups(&r), ["Leads"]);

    // --- One-click unsubscribe with the group's notice -------------------
    let bob = unsubscribe_token("test-secret", "bob@x.test", 7, 2);
    let r = post(&app, "/api/unsubscribe_new", "", json!({"jwt": bob})).await;
    assert_eq!(
        r.body["data"],
        json!({"email": "bob@x.test", "group_name": "Leads", "redirect_url": "https://example.test/bye"}),
        "{}",
        r.body
    );
    assert_eq!(contact(&h, "bob@x.test", 2).await.map(|c| c.0), Some(0));
    let notice = wait_for(&h, "bob@x.test", "You're unsubscribed", 1).await;
    let resubscribe = link(
        &notice[0].html,
        &format!("{HOST}/api/subscribe/confirm?token="),
    );
    let r = call(
        &app,
        resubscribe.strip_prefix(HOST).expect("host"),
        &[],
        false,
    )
    .await;
    assert_eq!(location(&r), format!("{HOST}/subscribe_success.html"));
    assert_eq!(contact(&h, "bob@x.test", 2).await.map(|c| c.0), Some(1));
    wait_for(&h, "bob@x.test", "Welcome Aboard!", 2).await;

    // --- Links Go signed ---------------------------------------------
    // Forgeable, so only accepted with evidence the address got the mail.
    let forged = unsubscribe_token("go-secret", "stranger@x.test", 0, 2);
    let r = post(
        &app,
        "/api/unsubscribe/user_group",
        "",
        json!({"jwt": forged}),
    )
    .await;
    assert_eq!(r.body["code"], 400, "{}", r.body);
    let forged = unsubscribe_token("go-secret", "stranger@x.test", 7, 2);
    let r = post(&app, "/api/unsubscribe_new", "", json!({"jwt": forged})).await;
    assert_eq!(r.body["code"], 400, "{}", r.body);
    let delivered = unsubscribe_token("go-secret", "old@x.test", 7, 2);
    let r = post(&app, "/api/unsubscribe_new", "", json!({"jwt": delivered})).await;
    assert_eq!(r.body["success"], true, "{}", r.body);
    let member = unsubscribe_token("go-secret", "ann@x.test", 0, 2);
    let r = post(
        &app,
        "/api/unsubscribe/user_group",
        "",
        json!({"jwt": member}),
    )
    .await;
    assert_eq!(groups(&r), ["Leads"], "{}", r.body);

    // --- Group subscription settings ----------------------------------
    let admin = bearer(&token(1, "access_token", "admin-subs"));
    let r = call(
        &app,
        "/api/contact/group/info?group_id=1",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(
        r.body["msg"], "Group info retrieved successfully",
        "{}",
        r.body
    );
    let d = &r.body["data"];
    assert_eq!(d["success_url"], format!("{HOST}/subscribe_success.html"));
    assert_eq!(d["confirm_url"], format!("{HOST}/subscribe_confirm.html"));
    assert_eq!(d["already_url"], format!("{HOST}/already_subscribed.html"));
    assert_eq!(
        d["unsubscribe_redirect_url"],
        format!("{HOST}/unsubscribe_success.html")
    );
    assert_eq!(
        d["subscribe_link"],
        format!("{HOST}/subscribe_form.html?token=tok-customers")
    );
    assert_eq!(d["sender"], "noreply@example.test");
    assert_eq!(d["welcome_subject"], "Welcome Aboard!");
    assert_eq!(d["confirm_subject"], "Confirm Your Subscription");
    assert!(
        d["subscribe_form"].as_str().is_some_and(
            |f| f.contains(&format!("{HOST}/api/subscribe/submit?token=tok-customers"))
        ),
        "{d}"
    );
    let templates = h.core_dir().join("template");
    for (kind, file) in [
        ("welcome", "default_welcome_email/welcome_email"),
        ("confirm", "default_confirm_email/confirm_email"),
        ("unsubscribe", "default_unsubscribe_email/unsubscribe_email"),
    ] {
        let read = |ext: &str| {
            std::fs::read_to_string(templates.join(format!("{file}.{ext}"))).expect("template")
        };
        assert_eq!(d[format!("{kind}_mail_html")], read("html"), "{kind}");
        assert_eq!(d[format!("{kind}_mail_drag")], read("txt"), "{kind}");
    }
    assert!(
        d["confirm_mail_html"]
            .as_str()
            .is_some_and(|h| h.contains("{{ ConfirmURL . }}"))
    );
    let r = call(
        &app,
        "/api/contact/group/info?group_id=2",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(
        r.body["data"]["unsubscribe_redirect_url"],
        "https://example.test/bye"
    );
    let r = call(
        &app,
        "/api/contact/group/info?group_id=99",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 404, "{}", r.body);
    let r = call(&app, "/api/contact/group/info?group_id=1", &[], false).await;
    assert_eq!(r.body["code"], 401, "{}", r.body);

    // --- The noreply mailbox, created on first mail ----------------------
    let (hash, encoded, maildir) = sqlx::query_as::<_, (String, String, String)>(
        "SELECT password, password_encode, maildir FROM mailbox WHERE username = 'noreply@example.test'",
    )
    .fetch_one(pg)
    .await
    .expect("noreply mailbox");
    assert!(hash.starts_with("$1$"), "{hash}");
    let password = ferropost_sender::smtp::decode_mailbox_password(&encoded).expect("decode");
    assert!(pwhash::md5_crypt::verify(&password, &hash));
    assert_eq!(maildir, "noreply@example.test/");
    // Every message logged in as the mailbox, with its stored password.
    for mail in h.smtp.mails() {
        assert_eq!(
            (mail.login.as_str(), mail.password.as_str()),
            ("noreply@example.test", password.as_str())
        );
    }
    assert_eq!(
        std::fs::read_to_string(
            h.root
                .path()
                .join("vmail-data/example.test/noreply/maildirsize")
        )
        .expect("maildirsize"),
        "0S\n0 0\n"
    );
}
