//! End-to-end tests for bulk contact tags, the subscriber trend and export.

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};

#[tokio::test]
async fn contact_extras() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-extras"));
    let now = chrono::Utc::now().timestamp();
    sqlx::query(&format!(
        "INSERT INTO bm_contacts (id, email, group_id, active, status, attribs, create_time, last_active_at) VALUES
            (10, 'a@x.com', 1, 1, 1, '{{\"n\": \"A\"}}', {}, {}),
            (11, 'a@x.com', 2, 0, 1, '{{}}', {}, 0),
            (12, 'b@x.com', 1, 0, 0, '{{}}', {}, 0)",
        now - 86_400,
        now - 3_600,
        now - 40 * 86_400,
        now - 40 * 86_400
    ))
    .execute(&h.store.pg)
    .await
    .expect("seed");
    sync_sequences(&h.store).await;

    // --- batch_tags_opt ---------------------------------------------------
    let tags = |ids: Value, tag_ids: Value, action: i64| {
        post(
            &app,
            "/api/contact/batch_tags_opt",
            &admin,
            json!({"ids": ids, "tag_ids": tag_ids, "action": action}),
        )
    };
    let r = tags(json!([10, 11]), json!([1, 3]), 1).await;
    assert_eq!(
        r.body["msg"], "Successfully added tags to 2 contacts (2 skipped, 0 errors)",
        "tags only apply within their group"
    );
    let pairs: Vec<(i32, i32)> =
        sqlx::query_as("SELECT contact_id, tag_id FROM bm_contact_tags ORDER BY 1, 2")
            .fetch_all(&h.store.pg)
            .await
            .expect("pairs");
    assert_eq!(pairs, [(10, 1), (11, 3)]);
    assert_eq!(
        tags(json!([10, 11]), json!([1, 3]), 1).await.body["msg"],
        "Successfully added tags to 0 contacts (4 skipped, 0 errors)"
    );
    assert_eq!(
        tags(json!([10]), json!([1]), 2).await.body["msg"],
        "Successfully removed tags from 1 contacts"
    );
    assert_eq!(
        tags(json!([999]), json!([1]), 1).await.body["msg"],
        "Successfully added tags to 0 contacts (1 skipped, 0 errors)"
    );
    assert_eq!(tags(json!([10]), json!([1]), 3).await.body["code"], 412);

    // --- trend ------------------------------------------------------------
    let get = |uri: &str| {
        let (app, admin, uri) = (app.clone(), admin.clone(), uri.to_owned());
        async move { call(&app, &uri, &[("authorization", &admin)], false).await }
    };
    let sum = |points: &Value| -> i64 {
        points
            .as_array()
            .expect("points")
            .iter()
            .map(|p| p["count"].as_i64().expect("count"))
            .sum()
    };
    let r = get("/api/contact/trend?time_interval=7").await;
    assert_eq!(r.body["msg"], "Get contacts trend successfully");
    assert_eq!(r.body["data"]["time_granularity"], "daily");
    assert_eq!(
        r.body["data"]["daily_data"]
            .as_array()
            .expect("daily")
            .len(),
        8
    );
    assert_eq!(
        sum(&r.body["data"]["daily_data"]),
        1,
        "only a@x.com joined this week"
    );
    assert_eq!(r.body["data"]["monthly_data"], json!([]));

    let r = get("/api/contact/trend").await;
    assert_eq!(r.body["data"]["time_granularity"], "monthly");
    assert_eq!(
        r.body["data"]["monthly_data"]
            .as_array()
            .expect("monthly")
            .len(),
        12
    );
    assert_eq!(sum(&r.body["data"]["monthly_data"]), 3);
    assert_eq!(
        sum(&get("/api/contact/trend?active=1").await.body["data"]["monthly_data"]),
        1
    );
    assert_eq!(
        sum(&get("/api/contact/trend?group_id=2").await.body["data"]["monthly_data"]),
        1
    );
    let r = get("/api/contact/trend?time_interval=30&last_active_status=1").await;
    assert_eq!(
        sum(&r.body["data"]["daily_data"]),
        1,
        "bucketed by last activity"
    );

    // --- export -----------------------------------------------------------
    let export = |body: Value| post(&app, "/api/contact/group/export", &admin, body);
    let r = export(json!({"group_ids": [1, 2], "export_type": 1, "format": "csv"})).await;
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/octet-stream");
    let disposition = r.headers[header::CONTENT_DISPOSITION]
        .to_str()
        .expect("header");
    assert!(
        disposition.starts_with("attachment; filename=contacts_export_")
            && disposition.ends_with(".csv")
    );
    let csv = r.body.as_str().expect("csv text");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines[0], "email,attributes,active,create_time");
    assert!(
        lines[1].starts_with("a@x.com,\"{\"\"n\"\":\"\"A\"\"}\",0,"),
        "states differ across groups → 0"
    );
    assert!(lines[2].starts_with("b@x.com,{},0,"));
    assert_eq!(lines.len(), 3);

    let r = export(json!({"group_ids": [1, 2], "export_type": 1, "format": "txt", "include_unsubscribe": false})).await;
    assert_eq!(
        r.body,
        json!(""),
        "every merged address is unsubscribed somewhere; Go ignored false"
    );

    let r = export(json!({"group_ids": [1], "export_type": 1, "format": "excel"})).await;
    assert!(
        r.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .expect("header")
            .ends_with(".xlsx")
    );
    assert!(
        r.body.as_str().expect("bytes").starts_with("PK"),
        "Go answered 'not implemented'"
    );

    let r = export(json!({"group_ids": [1, 2], "export_type": 2, "format": "csv"})).await;
    assert!(
        r.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .expect("header")
            .ends_with(".zip")
    );
    assert!(r.body.as_str().expect("bytes").starts_with("PK"));

    sqlx::query("INSERT INTO bm_contact_groups (id, name) VALUES (7, 'Empty')")
        .execute(&h.store.pg)
        .await
        .expect("group");
    let r = export(json!({"group_ids": [7], "export_type": 2, "format": "csv"})).await;
    assert_eq!(
        (r.body["code"].clone(), r.body["msg"].clone()),
        (json!(400), json!("No contacts to export"))
    );
    assert_eq!(
        export(json!({"group_ids": [1], "export_type": 1, "format": "pdf"}))
            .await
            .body["code"],
        412
    );

    let logs: Vec<String> = sqlx::query_scalar("SELECT log FROM bm_operation_logs ORDER BY id")
        .fetch_all(&h.store.pg)
        .await
        .expect("logs");
    assert!(logs.contains(&"Add tags for 2 contacts successfully".to_owned()));
    assert!(logs.contains(&"Contacts Group exported successfully: Customers, Leads ".to_owned()));
}
