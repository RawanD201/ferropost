//! Signing in and out: login with its failure lock and captcha, refresh
//! rotation, logout ending the whole session, disabled accounts, aaPanel SSO.

mod common;

use common::*;
use fred::prelude::KeysInterface;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

const PASSWORD: &str = "Corr3ct-horse";

async fn captcha(app: &axum::Router, h: &Harness) -> (String, String) {
    let r = call(app, "/api/get_validate_code", &[], false).await;
    let id = r.body["data"]["validateCodeId"]
        .as_str()
        .expect("id")
        .to_owned();
    assert!(
        r.body["data"]["validateCodeBase64"]
            .as_str()
            .is_some_and(|i| i.starts_with("data:image/svg+xml;base64,"))
    );
    let answer: Option<String> = h
        .store
        .redis
        .get(format!("ferropost:captcha:{id}"))
        .await
        .expect("redis");
    (id, answer.expect("answer stored"))
}

async fn login(app: &axum::Router, body: Value) -> Reply {
    send(app, "POST", "/api/login", &[], Some(body), false).await
}

fn sso_headers(secret: &str, ts: i64, nonce: &str, user: &str) -> Vec<(String, String)> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("key");
    mac.update(format!("{ts}\n{nonce}\n{user}").as_bytes());
    vec![
        ("x-aapanel-timestamp".into(), ts.to_string()),
        ("x-aapanel-nonce".into(), nonce.into()),
        (
            "x-aapanel-signature".into(),
            format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
        ),
    ]
}

#[tokio::test]
async fn sign_in_flows() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let hash = pwhash::bcrypt::hash(PASSWORD).expect("bcrypt");
    sqlx::query("UPDATE account SET password = $1")
        .bind(&hash)
        .execute(pg)
        .await
        .expect("passwords");
    sqlx::query("INSERT INTO account (account_id, username, password, email, status) VALUES (4, 'off', $1, 'o@x.test', 0)")
        .bind(&hash)
        .execute(pg)
        .await
        .expect("disabled");
    let app = h.app(&[]);

    // --- Failures, captcha, lock -------------------------------------------------
    let r = login(&app, json!({"username": "admin", "password": "wrong"})).await;
    assert_eq!(r.body["msg"], "Invalid username or password");
    let r = call(&app, "/api/get_validate_code", &[], false).await;
    assert_eq!(
        (
            r.body["data"]["mustValidateCode"].clone(),
            r.body["data"]["loginRetries"].clone()
        ),
        (json!(true), json!(1))
    );
    let r = login(&app, json!({"username": "admin", "password": PASSWORD})).await;
    assert_eq!(r.body["msg"], "Validation code ID and code cannot be empty");
    let (id, _) = captcha(&app, &h).await;
    let r = login(&app, json!({"username": "admin", "password": PASSWORD, "validate_code_id": id, "validate_code": "zzzz"})).await;
    assert_eq!(r.body["msg"], "Invalid validation code");
    let (id, answer) = captcha(&app, &h).await;
    // Unknown users and disabled accounts fail like a wrong password.
    for user in ["nobody-here", "off"] {
        let (id, answer) = captcha(&app, &h).await;
        let r = login(&app, json!({"username": user, "password": PASSWORD, "validate_code_id": id, "validate_code": answer})).await;
        assert_eq!(r.body["msg"], "Invalid username or password", "{user}");
    }
    let r = login(&app, json!({"username": "admin", "password": PASSWORD, "validate_code_id": id, "validate_code": answer.to_uppercase()})).await;
    assert_eq!(r.body["msg"], "Login successful", "{}", r.body);
    assert!(
        r.headers
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.starts_with("ferropost_rspamd=") && c.contains("Path=/rspamd")),
        "an admin's login opens the rspamd interface"
    );
    let data = r.body["data"].clone();
    assert_eq!(
        (data["ttl"].clone(), data["accountInfo"]["username"].clone()),
        (json!(86400), json!("admin"))
    );
    let access = bearer(data["token"].as_str().expect("token"));
    let refresh = data["refreshToken"].as_str().expect("refresh").to_owned();
    let r = call(
        &app,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", &access)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "the issued token works: {}", r.body);
    // The captcha was used up, and success cleared the failures.
    let r = call(&app, "/api/get_validate_code", &[], false).await;
    assert_eq!(r.body["data"]["mustValidateCode"], false);
    // A refresh token is not an access token.
    let r = call(
        &app,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", &bearer(&refresh))],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 401);

    // Five failures lock the client out.
    for _ in 0..5 {
        let (id, answer) = captcha(&app, &h).await;
        login(&app, json!({"username": "admin", "password": "nope", "validate_code_id": id, "validate_code": answer})).await;
    }
    let r = login(&app, json!({"username": "admin", "password": PASSWORD})).await;
    let msg = r.body["msg"].as_str().unwrap_or_default().to_owned();
    assert!(
        msg.starts_with("Login failed too many times, please try again after "),
        "{msg}"
    );
    let _: i64 = h
        .store
        .redis
        .del("ferropost:login-failures:203.0.113.9")
        .await
        .expect("unlock");

    // --- Refresh rotation and logout -----------------------------------------------
    let r = send(
        &app,
        "POST",
        "/api/refresh-token",
        &[],
        Some(json!({"refreshToken": refresh})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "Token refreshed successfully", "{}", r.body);
    let rotated = r.body["data"]["refreshToken"]
        .as_str()
        .expect("rotated")
        .to_owned();
    let refreshed_access = bearer(r.body["data"]["token"].as_str().expect("token"));
    let r = send(
        &app,
        "POST",
        "/api/refresh-token",
        &[],
        Some(json!({"refreshToken": refresh})),
        false,
    )
    .await;
    assert_eq!(
        r.body["msg"], "Invalid or expired refresh token",
        "a refresh token works once"
    );
    // A refresh token Go issued (no session ID) still works.
    let go_refresh = token(1, "refresh_token", "go-refresh-1");
    let r = send(
        &app,
        "POST",
        "/api/refresh-token",
        &[],
        Some(json!({"refreshToken": go_refresh})),
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "{}", r.body);

    let r = send(
        &app,
        "POST",
        "/api/logout",
        &[("authorization", &refreshed_access)],
        Some(json!({})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "Logout successful");
    for token in [&refreshed_access, &access] {
        let r = call(
            &app,
            "/api/tags/list?page=1&page_size=10",
            &[("authorization", token)],
            false,
        )
        .await;
        assert_eq!(
            r.body["code"], 401,
            "logout ends every token of the session"
        );
    }
    let r = send(
        &app,
        "POST",
        "/api/refresh-token",
        &[],
        Some(json!({"refreshToken": rotated})),
        false,
    )
    .await;
    assert_eq!(
        r.body["msg"], "Invalid or expired refresh token",
        "and its refresh token (Go kept it)"
    );

    // A disabled account's token stops working (Go honoured it until expiry).
    let viewer = bearer(&token(2, "access_token", "viewer-live"));
    let r = call(
        &app,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", &viewer)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0);
    sqlx::query("UPDATE account SET status = 0 WHERE account_id = 2")
        .execute(pg)
        .await
        .expect("disable");
    let fresh = h.app(&[]);
    let r = call(
        &fresh,
        "/api/tags/list?page=1&page_size=10",
        &[("authorization", &viewer)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 401);

    // --- aaPanel SSO ---------------------------------------------------------------
    let sso = h.app(&[("AAPANEL_SSO_SECRET", "sso-secret"), ("SafePath", "entry")]);
    let now = chrono::Utc::now().timestamp();
    let headers = sso_headers("sso-secret", now, "n-1", "admin");
    let refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let r = send(
        &sso,
        "POST",
        "/api/aapanel/sso",
        &refs,
        Some(json!({"username": "admin"})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "aaPanel SSO successful", "{}", r.body);
    let cookies: Vec<&str> = r
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("ferropost_entrance=")),
        "passes the safe entrance: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("ferropost_rspamd=")),
        "and opens the rspamd interface for an admin"
    );
    let r = send(
        &sso,
        "POST",
        "/api/aapanel/sso",
        &refs,
        Some(json!({"username": "admin"})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "aaPanel SSO nonce already used");
    let wrong = sso_headers("other", now, "n-2", "admin");
    let refs: Vec<(&str, &str)> = wrong
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let r = send(
        &sso,
        "POST",
        "/api/aapanel/sso",
        &refs,
        Some(json!({"username": "admin"})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "invalid aaPanel SSO signature");
    let old = sso_headers("sso-secret", now - 3600, "n-3", "admin");
    let refs: Vec<(&str, &str)> = old.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let r = send(
        &sso,
        "POST",
        "/api/aapanel/sso",
        &refs,
        Some(json!({"username": "admin"})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "aaPanel SSO request expired");
    let r = send(
        &app,
        "POST",
        "/api/aapanel/sso",
        &[],
        Some(json!({"username": "admin"})),
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "aaPanel SSO is disabled");

    // The audit log never holds the issued tokens.
    let logs: String = sqlx::query_scalar(
        "SELECT COALESCE(string_agg(log || info, ' '), '') FROM bm_operation_logs",
    )
    .fetch_one(pg)
    .await
    .expect("logs");
    assert!(logs.contains("The user:admin login was successful"));
    let snapshots = std::fs::read_dir(h.root.path().join("logs/core/operation_log"))
        .map(|days| {
            days.flatten()
                .flat_map(|d| std::fs::read_dir(d.path()).into_iter().flatten().flatten())
                .map(|f| std::fs::read_to_string(f.path()).unwrap_or_default())
                .collect::<String>()
        })
        .unwrap_or_default();
    let issued = data["token"].as_str().expect("token");
    assert!(
        !logs.contains(issued) && !snapshots.contains(issued),
        "tokens in the audit log"
    );
}
