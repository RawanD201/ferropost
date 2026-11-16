//! End-to-end test of the platform layer: authentication, RBAC, i18n, the Go
//! proxy, safe entrance, IP whitelist, base path and tag reads.

mod common;

use axum::http::{StatusCode, header};
use common::*;
use ferropost_api::AppState;
use ferropost_api::access_log::AccessLog;
use fred::prelude::KeysInterface;
use serde_json::json;

#[tokio::test]
async fn end_to_end() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-1"));

    // --- authentication -------------------------------------------------
    let r = call(&app, "/api/tags/list", &[], false).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body,
        json!({"success": false, "code": 401, "msg": "no authorization", "data": null})
    );

    let refresh = bearer(&token(1, "refresh_token", "r-1"));
    let r = call(
        &app,
        "/api/tags/list",
        &[("authorization", &refresh)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 401, "refresh tokens are not access tokens");

    // --- tags/list as admin ---------------------------------------------
    let r = call(&app, "/api/tags/list", &[("authorization", &admin)], false).await;
    assert_eq!(r.body["success"], true);
    assert_eq!(r.body["code"], 0);
    assert_eq!(r.body["msg"], "Get tag list successfully");
    assert_eq!(r.body["data"]["total"], 4);
    let names: Vec<&str> = r.body["data"]["list"]
        .as_array()
        .expect("list")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        ["50% off", "50 off", "vip", "orphan"],
        "create_time DESC"
    );
    assert_eq!(r.body["data"]["list"][3]["group_name"], "Unknown");
    assert_eq!(r.body["data"]["list"][0]["group_name"], "Customers");

    // Keyword is matched literally: "%" is not a wildcard.
    let r = call(
        &app,
        "/api/tags/list?keyword=50%25",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 1);
    assert_eq!(r.body["data"]["list"][0]["name"], "50% off");

    let r = call(
        &app,
        "/api/tags/list?group_id=1&page=2&page_size=1",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 2);
    assert_eq!(r.body["data"]["list"][0]["name"], "vip");

    let r = call(
        &app,
        "/api/tags/list?group_id=&keyword=",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["total"], 4, "empty params mean no filter");

    let r = call(
        &app,
        "/api/tags/list?group_id=-1",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 412);

    let r = call(&app, "/api/tags/all", &[("authorization", &admin)], false).await;
    assert_eq!(r.body["data"]["total"], 4);

    // --- RBAC -----------------------------------------------------------
    let viewer = bearer(&token(2, "access_token", "viewer-1"));
    let r = call(&app, "/api/tags/list", &[("authorization", &viewer)], false).await;
    assert_eq!(r.body["code"], 0, "viewer has tags:read");
    let r = call(&app, "/api/tags/all", &[("authorization", &viewer)], false).await;
    assert_eq!(r.body["code"], 403, "tags/all needs action 'all'");

    let nobody = bearer(&token(3, "access_token", "nobody-1"));
    let r = call(&app, "/api/tags/list", &[("authorization", &nobody)], false).await;
    assert_eq!(
        r.body,
        json!({"success": false, "code": 403, "msg": "Insufficient permissions", "data": null})
    );

    // --- revocation -----------------------------------------------------
    let _: () = h
        .store
        .redis
        .set("JWT_BLACK_LIST:viewer-1", 0, None, None, false)
        .await
        .expect("revoke");
    let r = call(&app, "/api/tags/list", &[("authorization", &viewer)], false).await;
    assert_eq!(r.body["code"], 401, "revoked token");

    // --- i18n -----------------------------------------------------------
    let lang_dir = h.core_dir().join("languages/zh");
    std::fs::create_dir_all(&lang_dir).expect("mkdir");
    std::fs::write(
        lang_dir.join("server.json"),
        json!({ md5_hex("Get tag list successfully"): "获取标签列表成功" }).to_string(),
    )
    .expect("write pack");
    let r = call(
        &h.app(&[]),
        "/api/tags/list?lang=zh-CN",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "获取标签列表成功");

    // --- proxy to Go ----------------------------------------------------
    let r = call(
        &app,
        "/api/domains/list?page=1",
        &[
            ("authorization", &admin),
            ("x-forwarded-for", "127.0.0.1"),
            ("proxy-client-ip", "127.0.0.1"),
        ],
        true,
    )
    .await;
    assert_eq!(r.body["go"], true);
    assert_eq!(r.body["uri"], "/api/domains/list?page=1");
    assert_eq!(
        r.body["x_forwarded_for"], "203.0.113.9",
        "spoofed XFF replaced"
    );
    assert_eq!(r.body["x_real_ip"], "203.0.113.9");
    assert_eq!(r.body["proxy_client_ip"], "");
    assert_eq!(r.body["x_forwarded_proto"], "https");
    assert_eq!(r.body["host"], "console.example.com");
    assert_eq!(
        r.headers[header::SET_COOKIE],
        "billion_mail=sess; Path=/; HttpOnly; Secure"
    );

    // --- safe entrance --------------------------------------------------
    let gated = h.app(&[("SafePath", "/s3cret")]);
    let r = call(
        &gated,
        "/api/tags/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(
        r.body,
        json!({"success": false, "code": 404, "msg": "access denied", "data": null})
    );
    let r = call(&gated, "/", &[], false).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = call(&gated, "/pmta/not-a-token", &[], false).await;
    assert_eq!(
        (r.status, r.body.clone()),
        (StatusCode::OK, json!("Invalid -1")),
        "tracking links stay public and are served natively"
    );
    let r = send(
        &gated,
        "POST",
        "/api/unsubscribe",
        &[],
        Some(json!({})),
        false,
    )
    .await;
    assert_eq!(
        (r.body["code"].clone(), r.body.get("go")),
        (json!(412), None),
        "unsubscribe stays public and is served natively: {}",
        r.body
    );

    let api_token = bearer(&token(1, "api_token", "api-1"));
    let r = call(
        &gated,
        "/api/tags/list",
        &[("authorization", &api_token)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "API tokens skip the entrance");

    let r = call(&gated, "/s3cret", &[], true).await;
    assert_eq!(r.status, StatusCode::FOUND);
    assert_eq!(r.headers[header::LOCATION], "/");
    let set_cookie = r.headers[header::SET_COOKIE].to_str().expect("cookie");
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("Secure"));
    let cookie = set_cookie.split(';').next().expect("pair").to_owned();
    let r = call(
        &gated,
        "/api/tags/list",
        &[("authorization", &admin), ("cookie", &cookie)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "entrance cookie opens the console");

    // --- IP whitelist ---------------------------------------------------
    let listed = h.app(&[("IP_WHITELIST_ENABLE", "true")]);
    let r = call(
        &listed,
        "/api/tags/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.body, "IP not allowed");
    let r = call(&listed, "/unsubscribe.html", &[], false).await;
    assert_eq!(r.body["go"], true, "public pages bypass the whitelist");
    let r = send(
        &listed,
        "POST",
        "/api/unsubscribe",
        &[],
        Some(json!({})),
        false,
    )
    .await;
    assert_eq!(r.body["code"], 412, "public routes bypass the whitelist");

    sqlx::query("INSERT INTO bm_console_ip_whitelist (ip) VALUES ('203.0.113.0/24')")
        .execute(&h.store.pg)
        .await
        .expect("insert");
    let listed = h.app(&[("IP_WHITELIST_ENABLE", "true")]);
    let r = call(
        &listed,
        "/api/tags/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0, "CIDR entry allows the client");

    // --- base path ------------------------------------------------------
    let based = h.app(&[("WEB_BASE_PATH", "/billionmail")]);
    let r = call(
        &based,
        "/billionmail/api/tags/all",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 0);
    let r = call(&based, "/billionmail/api/domains/list", &[], false).await;
    assert_eq!(
        r.body["uri"], "/api/domains/list",
        "Go receives the stripped path"
    );

    // --- Go unavailable -------------------------------------------------
    let config = {
        let db = std::env::var("FERROPOST_TEST_DATABASE_URL").expect("db");
        let redis = std::env::var("FERROPOST_TEST_REDIS_URL").expect("redis");
        config(&h.core_dir(), "http://127.0.0.1:9", &db, &redis, &[])
    };
    let down = ferropost_api::app(
        AppState::with_access_log(config, h.store.clone(), AccessLog::disabled()).expect("state"),
    );
    let r = call(
        &down,
        "/api/domains/list",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["code"], 503);
    let r = call(&down, "/dashboard", &[], false).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
}

fn md5_hex(input: &str) -> String {
    use md5::{Digest, Md5};
    hex::encode(Md5::digest(input.as_bytes()))
}
