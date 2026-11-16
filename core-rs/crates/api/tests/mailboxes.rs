//! Mailboxes end to end: the routes, the files Dovecot reads, and the
//! upkeep jobs (usage, quota alerts, the one-time quota plugin setup).

mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};

const SECRET: &str = "Sup3rSecret!";

async fn scalar_text(h: &Harness, sql: &str) -> String {
    sqlx::query_scalar(sql)
        .fetch_one(&h.store.pg)
        .await
        .expect(sql)
}

async fn scalar(h: &Harness, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&h.store.pg)
        .await
        .expect(sql)
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every file under `dir`, concatenated.
fn all_text(dir: &std::path::Path) -> String {
    let mut out = String::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.push_str(&all_text(&path));
            } else {
                out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    out
}

#[tokio::test]
async fn mailboxes() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    for sql in [
        "INSERT INTO domain (domain, create_time, active, quota) VALUES ('example.test', 100, 1, 1000)",
        "INSERT INTO bm_options (name, value) VALUES ('ferropost_token_secret', 'test-secret')",
    ] {
        sqlx::query(sql).execute(pg).await.expect(sql);
    }
    let state = h.state(&[]);
    let app = ferropost_api::app(state.clone());
    let admin = bearer(&token(1, "access_token", "admin-mailboxes"));
    let auth = admin.as_str();
    let vmail = h.root.path().join("vmail-data");

    // --- Creating ----------------------------------------------------------
    let base = json!({"domain": "example.test", "local_part": "Ann", "password": SECRET, "full_name": "Ann"});
    let with = |patch: Value| {
        let mut body = base.clone();
        for (k, v) in patch.as_object().expect("object") {
            body[k] = v.clone();
        }
        body
    };
    for (patch, code, msg) in [
        (
            json!({"domain": "bad domain"}),
            412,
            "The domain value `bad domain` is not a valid domain format",
        ),
        (json!({"domain": "unknown.test"}), 400, "Domain not found"),
        (
            json!({"password": "short"}),
            412,
            "The password length must be equal or greater than 8",
        ),
        (
            json!({"local_part": "a b"}),
            412,
            "The local_part value `a b` is not a valid mailbox name",
        ),
    ] {
        let r = post(&app, "/api/mailbox/create", auth, with(patch.clone())).await;
        assert_eq!(
            (r.body["code"].clone(), r.body["msg"].clone()),
            (json!(code), json!(msg)),
            "{patch}"
        );
    }
    let r = post(
        &app,
        "/api/mailbox/create",
        auth,
        with(json!({"isAdmin": 1})),
    )
    .await;
    assert_eq!(r.body["msg"], "Mailbox added successfully", "{}", r.body);
    let r = post(&app, "/api/mailbox/create", auth, base.clone()).await;
    assert_eq!(
        (r.body["code"].clone(), r.body["msg"].clone()),
        (json!(409), json!("mailbox ann@example.test already exists"))
    );

    let hash = scalar_text(
        &h,
        "SELECT password FROM mailbox WHERE username = 'ann@example.test'",
    )
    .await;
    let crypt = hash
        .strip_prefix("{SHA512-CRYPT}")
        .expect("SHA512-CRYPT for Dovecot");
    assert!(pwhash::sha512_crypt::verify(SECRET, crypt));
    assert_eq!(
        read(&vmail.join("example.test/ann/maildirsize")),
        "5242880S\n0 0\n"
    );

    // --- Reading ------------------------------------------------------------
    let r = call(
        &app,
        "/api/mailbox/list?domain=example.test&page=1&page_size=10",
        &[("authorization", auth)],
        false,
    )
    .await;
    let row = &r.body["data"]["list"][0];
    assert_eq!(
        (
            row["username"].clone(),
            row["password"].clone(),
            row["password_encode"].clone(),
            row["mx"].clone(),
            row["is_admin"].clone()
        ),
        (
            json!("ann@example.test"),
            json!(SECRET),
            json!(""),
            json!("mail.example.test"),
            json!(1)
        ),
        "{row}"
    );
    let r = call(
        &app,
        "/api/mailbox/all?domain=example.test",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(
        (
            r.body["data"][0]["password"].clone(),
            r.body["data"][0]["password_encode"].clone()
        ),
        (json!(""), json!(""))
    );
    let r = call(
        &app,
        "/api/mailbox/all_email",
        &[("authorization", auth)],
        false,
    )
    .await;
    assert_eq!(r.body["data"], json!(["ann@example.test"]));

    // --- Updating -------------------------------------------------------------
    let r = post(
        &app,
        "/api/mailbox/update",
        auth,
        json!({"domain": "example.test", "local_part": "ann", "quota": 2000}),
    )
    .await;
    assert_eq!(r.body["msg"], "Mailbox updated successfully", "{}", r.body);
    assert_eq!(
        read(&vmail.join("example.test/ann/maildirsize")),
        "2000S\n0 0\n"
    );
    let kept: (i16, i16, String) = sqlx::query_as(
        "SELECT is_admin, active, password FROM mailbox WHERE username = 'ann@example.test'",
    )
    .fetch_one(pg)
    .await
    .expect("kept");
    assert_eq!(
        (kept.0, kept.1, kept.2.as_str()),
        (1, 1, hash.as_str()),
        "fields not sent are kept (Go reset them)"
    );
    let r = post(
        &app,
        "/api/mailbox/update",
        auth,
        json!({"domain": "example.test", "local_part": "ann", "password": "An0therSecret"}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    assert_ne!(
        scalar_text(
            &h,
            "SELECT password FROM mailbox WHERE username = 'ann@example.test'"
        )
        .await,
        hash
    );
    let r = post(
        &app,
        "/api/mailbox/update",
        auth,
        json!({"domain": "example.test", "local_part": "ghost"}),
    )
    .await;
    assert_eq!(r.body["code"], 404);

    // --- Batch, export, import, delete -----------------------------------------------
    let r = post(
        &app,
        "/api/mailbox/batch_create",
        auth,
        json!({"domain": "example.test", "count": 1}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    let r = post(
        &app,
        "/api/mailbox/batch_create",
        auth,
        json!({"domain": "example.test", "count": 3, "prefix": "bad prefix"}),
    )
    .await;
    assert_eq!(
        r.body["msg"],
        "Prefixes can contain only letters, numbers, underscores, and hyphens"
    );
    let r = post(
        &app,
        "/api/mailbox/batch_create",
        auth,
        json!({"domain": "example.test", "count": 3, "prefix": "team"}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "3 email accounts were successfully created",
        "{}",
        r.body
    );
    let team: Vec<String> = serde_json::from_value(r.body["data"].clone()).expect("names");
    assert!(
        team.iter()
            .all(|t| t.starts_with("team") && t.ends_with("@example.test")),
        "{team:?}"
    );

    let r = send(
        &app,
        "POST",
        "/api/mailbox/export",
        &[("authorization", auth)],
        Some(json!({"domain": "example.test", "file_type": "csv"})),
        false,
    )
    .await;
    assert_eq!(
        r.headers["content-disposition"],
        "attachment; filename=mailboxes.csv"
    );
    let csv = r.body.as_str().expect("csv text").to_owned();
    assert!(csv.starts_with("username,full_name,is_admin,quota,quota_active,local_part,domain,active,password,password_encode\n"));
    assert_eq!(csv.lines().count(), 5, "{csv}");

    let r = post(
        &app,
        "/api/mailbox/import",
        auth,
        json!({"file_type": "txt", "file_data": "new@example.test\nother@unknown.test\n"}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "The import is complete, but 1 email addresses failed to be imported",
        "{}",
        r.body
    );
    let (quota, encoded): (i64, String) = sqlx::query_as(
        "SELECT quota, password_encode FROM mailbox WHERE username = 'new@example.test'",
    )
    .fetch_one(pg)
    .await
    .expect("imported");
    let password = ferropost_sender::smtp::decode_mailbox_password(&encoded).expect("decode");
    assert!(
        password != "123456" && password.len() == 16,
        "a random password, not Go's 123456"
    );
    assert_eq!(quota, 5_242_880, "Go defaulted to 1000 bytes");
    // A file exported from another server keeps hashes and passwords.
    let moved = csv
        .replacen("ann@example.test", "moved@example.test", 1)
        .replacen(",ann,", ",moved,", 1);
    let r = post(
        &app,
        "/api/mailbox/import",
        auth,
        json!({"file_type": "csv", "file_data": moved}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "The import is complete, but 3 email addresses failed to be imported",
        "{}",
        r.body
    );
    assert_eq!(
        scalar_text(
            &h,
            "SELECT password_encode FROM mailbox WHERE username = 'moved@example.test'"
        )
        .await,
        scalar_text(
            &h,
            "SELECT password_encode FROM mailbox WHERE username = 'ann@example.test'"
        )
        .await
    );

    let r = post(&app, "/api/mailbox/delete", auth, json!({"emails": []})).await;
    assert_eq!(r.body["msg"], "Email addresses cannot be empty");
    let r = post(
        &app,
        "/api/mailbox/delete",
        auth,
        json!({"emails": ["moved@example.test", "new@example.test", "none@example.test"]}),
    )
    .await;
    assert_eq!(r.body["msg"], "Successfully deleted 2 mailbox(es)");

    // The audit log never holds a password.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let logs = all_text(&h.root.path().join("logs"))
        + &scalar_text(
            &h,
            "SELECT COALESCE(string_agg(log || info, ' '), '') FROM bm_operation_logs",
        )
        .await;
    assert!(logs.contains("Add email address :ann@example.test successfully"));
    for secret in [SECRET, "An0therSecret", &password] {
        assert!(!logs.contains(secret), "audit log leaks a password");
    }

    // --- Jobs -----------------------------------------------------------------
    // Usage from maildirsize, and the domain total.
    std::fs::write(
        vmail.join("example.test/ann/maildirsize"),
        "2000S\n1950 4\n",
    )
    .expect("usage");
    ferropost_api::mailbox_jobs::refresh_usage(&state)
        .await
        .expect("usage pass");
    assert_eq!(
        scalar(
            &h,
            "SELECT used_quota FROM mailbox WHERE username = 'ann@example.test'"
        )
        .await,
        1950
    );
    assert_eq!(
        scalar(
            &h,
            "SELECT current_usage FROM domain WHERE domain = 'example.test'"
        )
        .await,
        1950
    );

    // 97.5% of the mailbox quota and over the domain's: one alert each, once.
    ferropost_api::mailbox_jobs::send_quota_alerts(&state)
        .await
        .expect("alerts");
    ferropost_api::mailbox_jobs::send_quota_alerts(&state)
        .await
        .expect("alerts again");
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
        if subjects.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    subjects.sort();
    assert_eq!(
        subjects,
        [
            "[Quota 95% Alert] ann@example.test usage 97.5%",
            "[Quota EXCEEDED] example.test 195.0%"
        ],
        "the domain alert went to its administrator, ann"
    );

    // Lower-casing addresses written with capitals.
    sqlx::query(
        "INSERT INTO mailbox (username, password, password_encode, full_name, maildir, local_part, domain)
         VALUES ('Bob@Example.test', '', '', '', 'Bob@Example.test/', 'Bob', 'Example.test')",
    )
    .execute(pg)
    .await
    .expect("upper");

    // The one-time Dovecot quota setup, on a copy of the shipped files.
    let conf = h.root.path().join("conf/dovecot");
    std::fs::create_dir_all(conf.join("conf.d")).expect("conf");
    let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../conf/dovecot");
    for file in [
        "dovecot.conf",
        "conf.d/20-pop3.conf",
        "conf.d/90-quota.conf",
    ] {
        std::fs::copy(shipped.join(file), conf.join(file)).expect(file);
    }
    std::fs::remove_file(vmail.join("example.test/ann/maildirsize")).expect("rm");
    ferropost_api::mailbox_jobs::init_quota_plugin(&state)
        .await
        .expect("quota plugin");
    assert!(read(&conf.join("dovecot.conf")).contains("mail_plugins = quota"));
    assert!(read(&conf.join("conf.d/20-pop3.conf")).contains("  mail_plugins = $mail_plugins"));
    assert!(read(&conf.join("conf.d/90-quota.conf")).ends_with("plugin {\n  quota = maildir\n}\n"));
    assert!(read(&conf.join("conf.d/dovecot-sql.conf.ext")).starts_with("driver = pgsql\n"));
    assert_eq!(
        read(&vmail.join("example.test/ann/maildirsize")),
        "2000S\n0 0\n"
    );
    assert!(h.core_dir().join("data/quota_init_done.mark").exists());
    // Done once: a second run leaves the files alone.
    std::fs::write(conf.join("dovecot.conf"), "edited").expect("edit");
    ferropost_api::mailbox_jobs::init_quota_plugin(&state)
        .await
        .expect("second run");
    assert_eq!(read(&conf.join("dovecot.conf")), "edited");

    let changed = ferropost_store::mailboxes::normalise_case(pg)
        .await
        .expect("normalise");
    assert_eq!(changed, 1);
    assert_eq!(scalar(&h, "SELECT COUNT(*) FROM mailbox WHERE username = 'bob@example.test' AND domain = 'example.test'").await, 1);
}
