//! Blocklist checks: a check's log and stored result (on a test list, not
//! the public ones), the log route serving check logs only, and the alert
//! mail through the harness's SMTP sink.

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;

#[tokio::test]
async fn blocklist() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let state = h.state(&[]);
    let app = ferropost_api::app(state.clone());
    let admin = bearer(&token(1, "access_token", "admin-blocklist"));
    let auth = admin.as_str();

    // A check on a list that cannot exist: every answer is "not listed" or
    // "no answer", and the counts add up.
    let result = ferropost_api::blocklist::check_on(
        &state,
        "mail.example.test",
        "203.0.113.9".parse().expect("ip"),
        &["nothing.invalid"],
    )
    .await
    .expect("check");
    assert_eq!(result.tested, 1);
    assert_eq!(result.passed + result.invalid + result.blacklisted, 1);
    let stored = ferropost_api::blocklist::result_for(&state, "mail.example.test")
        .await
        .expect("stored");
    assert_eq!(stored, result);
    let path = ferropost_api::blocklist::log_path(&state, "mail.example.test");
    let r = call(
        &app,
        &format!("/api/domain_blocklist/logs?path={}", urlencode(&path)),
        &[("authorization", auth)],
        false,
    )
    .await;
    let log = r.body["data"].as_str().unwrap_or_default().to_owned();
    assert!(
        log.contains("Start checking")
            && log.contains("Results for mail.example.test")
            && log.contains("Check finished"),
        "{}",
        r.body
    );

    // Only check logs are served (Go returned any file).
    let env_file = h.core_dir().join("../.env");
    for path in [
        "/etc/passwd".to_owned(),
        env_file.display().to_string(),
        "/etc/mail.example.test_blcheck.txt".to_owned(),
    ] {
        let r = call(
            &app,
            &format!("/api/domain_blocklist/logs?path={}", urlencode(&path)),
            &[("authorization", auth)],
            false,
        )
        .await;
        assert_eq!(r.body["code"], 412, "{path}: {}", r.body);
    }

    let r = post(
        &app,
        "/api/domain_blocklist/check",
        auth,
        json!({"a_record": "bad host"}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    let r = post(
        &app,
        "/api/domain_blocklist/check",
        auth,
        json!({"a_record": "mail.nowhere.invalid"}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.starts_with("resolve failed")),
        "{}",
        r.body
    );

    // A listing mails the alert recipients when alerts are on.
    sqlx::query("INSERT INTO bm_options (name, value) VALUES ('blacklist_alert_enabled', 'true')")
        .execute(&h.store.pg)
        .await
        .expect("switch");
    std::fs::create_dir_all(h.core_dir().join("data")).expect("data");
    std::fs::write(
        h.core_dir().join("data/blacklist_alert_settings.json"),
        json!({"name": "Alerts", "sender_email": "alerts@x.test", "smtp_password": "pw",
               "smtp_server": "127.0.0.1", "smtp_port": h.smtp.port,
               "recipient_list": ["ops@x.test"]})
        .to_string(),
    )
    .expect("settings");
    let listed = ferropost_domain::blocklist::CheckResult {
        domain: "mail.example.test".into(),
        ip: "203.0.113.9".into(),
        tested: 1,
        blacklisted: 1,
        black_list: vec![ferropost_domain::blocklist::Listing {
            blacklist: "zen.spamhaus.org".into(),
            response: "127.0.0.2".into(),
            time: 0,
        }],
        ..Default::default()
    };
    ferropost_api::blocklist::alert(&state, &listed)
        .await
        .expect("alert");
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
            .collect();
        if !subjects.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(subjects, ["⚠️ Blacklist Alert - mail.example.test"]);
}
