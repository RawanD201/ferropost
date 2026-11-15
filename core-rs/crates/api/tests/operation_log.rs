//! End-to-end tests for the operation-log viewer.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn operation_log_viewer() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-oplog"));
    let get = |uri: String| {
        let app = app.clone();
        let admin = admin.clone();
        async move { call(&app, &uri, &[("authorization", &admin)], false).await }
    };

    sqlx::query(
        "INSERT INTO bm_operation_logs (user_id, type, log, ip, info, addtime) VALUES
            (1, 'Contacts-Tag', 'Create tag vip', '1.2.3.4', '', 100),
            (99, 'Domain', '50% done', '5.6.7.8', '', 200),
            (2, 'Contacts-Tag', 'Delete tag', '9.9.9.9', '', 300)",
    )
    .execute(&h.store.pg)
    .await
    .expect("seed");

    // --- list -----------------------------------------------------------
    let r = get("/api/operation_log/list?page_size=10".into()).await;
    assert_eq!(
        (r.body["code"].clone(), r.body["msg"].clone()),
        (json!(412), json!("The page field is required"))
    );

    let r = get("/api/operation_log/list?page=1&page_size=2".into()).await;
    assert_eq!(r.body["msg"], "Get operation logs successfully");
    assert_eq!(r.body["data"]["total"], 3);
    let list = &r.body["data"]["list"];
    assert_eq!(list[0]["log"], "Delete tag", "newest first");
    assert_eq!(list[0]["username"], "viewer");
    assert_eq!(list[1]["username"], "unknown", "deleted account");
    assert_eq!(
        list[1],
        json!({"id": 2, "user_id": 99, "type": "Domain", "log": "50% done", "ip": "5.6.7.8",
               "info": "", "addtime": 200, "username": "unknown"})
    );

    let total = |r: &Reply| r.body["data"]["total"].as_i64().expect("total");
    assert_eq!(
        total(&get("/api/operation_log/list?page=1&page_size=9&type=Contacts-Tag".into()).await),
        2
    );
    assert_eq!(
        total(&get("/api/operation_log/list?page=1&page_size=9&type=all".into()).await),
        3
    );
    assert_eq!(
        total(&get("/api/operation_log/list?page=1&page_size=9&keyword=50%25".into()).await),
        1
    );
    assert_eq!(
        total(&get("/api/operation_log/list?page=1&page_size=9&keyword=9.9".into()).await),
        1,
        "matches IP"
    );
    assert_eq!(
        total(
            &get("/api/operation_log/list?page=1&page_size=9&start_time=150&end_time=250".into())
                .await
        ),
        1
    );

    // --- type_list ------------------------------------------------------
    let r = get("/api/operation_log/type_list".into()).await;
    assert_eq!(r.body["data"]["Tag"], "Contacts-Tag");
    assert_eq!(r.body["data"]["SendAPI"], "Send API");
    assert_eq!(r.body["data"].as_object().expect("map").len(), 18);

    // --- output logs ----------------------------------------------------
    let r = get("/api/operation_log/output/latest".into()).await;
    assert_eq!(
        (r.body["code"].clone(), r.body["msg"].clone()),
        (json!(400), json!("No log files found"))
    );

    let out = h.core_dir().join("../logs/core/out");
    std::fs::create_dir_all(&out).expect("mkdir");
    std::fs::write(out.join("2026-11-14.log"), "old one\nold two error\n").expect("write");
    std::fs::write(out.join("2026-11-15.log"), "new one error\nnew two\n").expect("write");

    let r = get("/api/operation_log/output/latest".into()).await;
    assert_eq!(
        r.body["data"],
        "old one\nold two error\nnew one error\nnew two"
    );

    let r = get(
        "/api/operation_log/output/list?start_date=2026-11-14&end_date=2026-11-15&keyword=error"
            .into(),
    )
    .await;
    assert_eq!(r.body["data"], "old two error\nnew one error");

    let r = get("/api/operation_log/output/list?start_date=2026-11-14&end_date=2026-11-15&page=2&page_size=1".into()).await;
    assert_eq!(r.body["data"], "new one error", "second-newest line");

    let r = get("/api/operation_log/output/list?start_date=2026-11-15&end_date=2026-11-15".into())
        .await;
    assert_eq!(r.body["data"], "new one error\nnew two");

    let r = get("/api/operation_log/output/list?start_date=2026-11-16&end_date=2026-11-01".into())
        .await;
    assert_eq!(r.body["msg"], "No log files found in the given date range");

    let r = get("/api/operation_log/output/list?start_date=2026-11-14".into()).await;
    assert_eq!(r.body["code"], 412);
}
