//! Dedicated sending IPs with Docker switched off: applying fails cleanly
//! (status `failed`, Postfix's files untouched), nothing to apply needs no
//! Docker, the DNS test's checks, and SNAT rules only started when needed.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn multi_ip() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let postfix = h.root.path().join("conf/postfix");
    std::fs::create_dir_all(&postfix).expect("postfix");
    std::fs::write(postfix.join("main.cf"), "myhostname = x\n").expect("main.cf");
    std::fs::write(postfix.join("master.cf"), "smtp inet n - n - - smtpd\n").expect("master.cf");
    sqlx::query("INSERT INTO domain (domain, create_time, active) VALUES ('example.test', 1, 1)")
        .execute(pg)
        .await
        .expect("domain");
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-multi-ip"));
    let auth = admin.as_str();

    // Nothing to apply: no Docker needed, the host commands are shown.
    let r = post(&app, "/api/multi_ip_domain/apply", auth, json!({})).await;
    assert_eq!(
        r.body["msg"], "Configuration applied successfully",
        "{}",
        r.body
    );
    assert!(
        r.body["data"]["command"]
            .as_str()
            .is_some_and(|c| c.ends_with("&& bash bm.sh multi_ip"))
    );

    // With a configuration and no Docker, the apply fails and says so.
    sqlx::query(
        "INSERT INTO bm_multi_ip_domain (domain, outbound_ip, network_name, subnet, postfix_ip,
             aliases, smtp_server_name, status)
         VALUES ('example.test', '203.0.113.7', 'billionmail-net-1', '172.66.2.0/24',
                 '172.66.2.100', 'aliases-example-test', 'smtp_bind_ip_1', 'pending')",
    )
    .execute(pg)
    .await
    .expect("config");
    let r = post(&app, "/api/multi_ip_domain/apply", auth, json!({})).await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.starts_with("Failed to apply configuration:")
                && m.contains("Docker is disabled")),
        "{}",
        r.body
    );
    let status: String = sqlx::query_scalar("SELECT status FROM bm_multi_ip_domain")
        .fetch_one(pg)
        .await
        .expect("status");
    assert_eq!(status, "failed");
    assert_eq!(
        std::fs::read_to_string(postfix.join("master.cf")).expect("master.cf"),
        "smtp inet n - n - - smtpd\n",
        "untouched"
    );

    // The DNS test.
    for (body, msg) in [
        (
            json!({"domain": "example.test", "outbound_ip": "nope"}),
            "invalid IP address format",
        ),
        (
            json!({"domain": "bad domain", "outbound_ip": "1.2.3.4"}),
            "invalid domain format",
        ),
    ] {
        let r = post(&app, "/api/multi_ip_domain/test", auth, body).await;
        assert_eq!(r.body["msg"], msg);
    }
    let r = post(
        &app,
        "/api/multi_ip_domain/test",
        auth,
        json!({"domain": "example.test", "outbound_ip": "203.0.113.7"}),
    )
    .await;
    assert!(
        r.body["msg"].as_str().is_some_and(|m| m.starts_with(
            "Test configuration failed: failed to query A record for domain 'example.test'"
        )),
        "{}",
        r.body
    );

    // SNAT rules: with configurations a helper is needed (and Docker is off).
    let state = h.state(&[]);
    assert!(
        ferropost_api::multi_ip::reapply_rules(&state)
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM bm_multi_ip_domain")
        .execute(pg)
        .await
        .expect("delete");
    assert_eq!(
        ferropost_api::multi_ip::reapply_rules(&state)
            .await
            .expect("none"),
        0,
        "nothing installed, nothing to remove: no helper started"
    );
}
