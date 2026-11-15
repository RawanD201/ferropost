//! End-to-end tests for contact listing, editing, moving and deleting.

mod common;

use common::*;
use serde_json::json;

async fn rows(h: &Harness) -> Vec<(i32, String, i32, i32, i32)> {
    sqlx::query_as::<_, (i32, String, i32, i32, i32)>(
        "SELECT id, email, group_id, active, status FROM bm_contacts ORDER BY email, group_id",
    )
    .fetch_all(&h.store.pg)
    .await
    .expect("rows")
}

#[tokio::test]
async fn contacts() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-contacts"));
    let get = |uri: &str| {
        let (app, admin, uri) = (app.clone(), admin.clone(), uri.to_owned());
        async move { call(&app, &uri, &[("authorization", &admin)], false).await }
    };
    let code_msg = |r: &Reply| (r.body["code"].clone(), r.body["msg"].clone());

    let now = chrono::Utc::now().timestamp();
    for sql in [
        format!(
            "INSERT INTO bm_contacts (id, email, group_id, active, status, attribs, create_time, last_active_at) VALUES
                (10, 'a@x.com', 1, 1, 1, '{{\"n\": \"A\"}}', 100, {}),
                (11, 'a@x.com', 2, 1, 1, '{{}}', 200, 0),
                (12, 'b@x.com', 1, 0, 0, '{{}}', 150, 0),
                (13, 'c@x.com', 2, 1, 0, '{{\"c\": \"1\"}}', 300, {})",
            now - 86_400,
            now - 100 * 86_400
        ),
        "INSERT INTO bm_contact_tags (contact_id, tag_id, create_time) VALUES (10, 1, 5)".to_owned(),
    ] {
        sqlx::query(&sql).execute(&h.store.pg).await.expect("seed");
    }
    sync_sequences(&h.store).await;

    // --- list: one entry per address --------------------------------------
    let r = get("/api/contact/list?page=1&page_size=10").await;
    assert_eq!(r.body["msg"], "Get contacts list successfully");
    assert_eq!(r.body["data"]["total"], 2, "a and c are subscribed");
    let list = &r.body["data"]["list"];
    assert_eq!(list[0]["email"], "c@x.com");
    assert_eq!(list[1]["id"], 11, "newest row of a@x.com");
    assert_eq!(
        list[1]["groups"],
        json!([{"id": 1, "name": "Customers"}, {"id": 2, "name": "Leads"}])
    );
    assert_eq!(list[1]["tags"], json!([]));
    assert_eq!(
        get("/api/contact/list?page=1&page_size=10&status=0")
            .await
            .body["data"]["list"][0]["email"],
        "b@x.com"
    );
    assert_eq!(
        get("/api/contact/list?page=1&page_size=10&keyword=a%40")
            .await
            .body["data"]["total"],
        1
    );
    assert_eq!(
        get("/api/contact/list?page=1&page_size=10&group_id=2")
            .await
            .body["data"]["total"],
        2
    );

    // --- list_ndp: one entry per membership -------------------------------
    let total = |r: &Reply| r.body["data"]["total"].as_i64().expect("total");
    let r = get("/api/contact/list_ndp?page=1&page_size=10").await;
    assert_eq!(total(&r), 4);
    let first = &r.body["data"]["list"][0];
    assert_eq!(
        (first["id"].clone(), first["group_name"].clone()),
        (json!(13), json!("Leads"))
    );
    let a = r.body["data"]["list"]
        .as_array()
        .expect("list")
        .iter()
        .find(|c| c["id"] == 10)
        .cloned()
        .expect("row 10");
    assert_eq!(
        a["tags"],
        json!([{"id": 1, "name": "vip", "create_time": 5}])
    );
    assert_eq!(a["attribs"], json!({"n": "A"}));
    assert_eq!(
        total(&get("/api/contact/list_ndp?page=1&page_size=10&active=0").await),
        1
    );
    assert_eq!(
        total(&get("/api/contact/list_ndp?page=1&page_size=10&tags=1").await),
        1
    );
    assert_eq!(
        total(&get("/api/contact/list_ndp?page=1&page_size=10&tags=-1").await),
        4
    );
    assert_eq!(
        total(
            &get("/api/contact/list_ndp?page=1&page_size=10&last_active_status=1&time_interval=7")
                .await
        ),
        1
    );
    assert_eq!(
        total(
            &get("/api/contact/list_ndp?page=1&page_size=10&last_active_status=0&time_interval=30")
                .await
        ),
        3
    );
    let r = get("/api/contact/list_ndp?page=1&page_size=10&sort_by=last_active_at&sort_order=desc")
        .await;
    assert_eq!(
        r.body["data"]["list"][0]["id"], 10,
        "most recently active first"
    );
    assert_eq!(
        get("/api/contact/list_ndp?page=1&page_size=10&sort_by=email")
            .await
            .body["code"],
        412
    );

    // --- edit_ndp ---------------------------------------------------------
    let r = post(
        &app,
        "/api/contact/edit_ndp",
        &admin,
        json!({"id": 12, "active": 1}),
    )
    .await;
    assert_eq!(r.body["msg"], "Contact updated successfully");
    assert!(
        rows(&h).await.contains(&(12, "b@x.com".into(), 1, 1, 0)),
        "status left as is"
    );
    let r = post(
        &app,
        "/api/contact/edit_ndp",
        &admin,
        json!({"id": 999, "active": 1}),
    )
    .await;
    assert_eq!(code_msg(&r), (json!(404), json!("Contact not found")));
    let r = post(&app, "/api/contact/edit_ndp", &admin, json!({"id": 12})).await;
    assert_eq!(
        code_msg(&r),
        (json!(400), json!("No valid fields to update"))
    );
    let r = post(
        &app,
        "/api/contact/edit_ndp",
        &admin,
        json!({"id": 12, "attribs": "[1]"}),
    )
    .await;
    assert_eq!(r.body["code"], 400);

    // --- edit: regroup keeps surviving rows -------------------------------
    let r = post(
        &app,
        "/api/contact/edit",
        &admin,
        json!({"emails": "a@x.com", "group_ids": [1], "active": 0, "attribs": "{\"n\": \"B\"}"}),
    )
    .await;
    assert_eq!(r.body["msg"], "Contact updated successfully");
    let a_rows: Vec<_> = rows(&h)
        .await
        .into_iter()
        .filter(|r| r.1 == "a@x.com")
        .collect();
    assert_eq!(
        a_rows,
        [(10, "a@x.com".into(), 1, 0, 1)],
        "row 10 kept, group 2 row removed"
    );
    let tagged: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bm_contact_tags WHERE contact_id = 10")
            .fetch_one(&h.store.pg)
            .await
            .expect("tags");
    assert_eq!(tagged, 1, "tags survive the edit");
    let r = post(
        &app,
        "/api/contact/edit",
        &admin,
        json!({"emails": "a@x.com", "group_ids": [999]}),
    )
    .await;
    assert_eq!(code_msg(&r), (json!(404), json!("Group 999 not found")));
    let r = post(
        &app,
        "/api/contact/edit",
        &admin,
        json!({"emails": "b@x.com", "active": 0}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    assert!(
        rows(&h).await.contains(&(12, "b@x.com".into(), 1, 0, 0)),
        "applied without group_ids"
    );

    // --- update_group -----------------------------------------------------
    let r = post(
        &app,
        "/api/contact/update_group",
        &admin,
        json!({"emails": ["c@x.com"], "status": 1, "group_ids": [1, 2]}),
    )
    .await;
    assert_eq!(r.body["msg"], "Contacts group updated successfully");
    assert_eq!(r.body["data"]["updated_count"], 2);
    let c_rows: Vec<_> = rows(&h)
        .await
        .into_iter()
        .filter(|r| r.1 == "c@x.com")
        .collect();
    assert_eq!(c_rows.len(), 2);
    assert!(c_rows.iter().any(|r| r.0 == 13), "existing row kept");
    let r = post(
        &app,
        "/api/contact/update_group",
        &admin,
        json!({"emails": ["c@x.com"], "status": 1, "group_ids": [999]}),
    )
    .await;
    assert_eq!(r.body["code"], 404);
    let r = post(
        &app,
        "/api/contact/update_group",
        &admin,
        json!({"emails": [], "status": 1, "group_ids": [1]}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(412), json!("The emails field is required"))
    );

    // --- delete -----------------------------------------------------------
    let r = post(
        &app,
        "/api/contact/delete",
        &admin,
        json!({"emails": ["a@x.com"], "status": 0}),
    )
    .await;
    assert_eq!(r.body["msg"], "Contacts deleted successfully");
    assert_eq!(r.body["data"]["deleted_count"], 1);
    let orphans: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM bm_contact_tags WHERE contact_id = 10")
            .fetch_one(&h.store.pg)
            .await
            .expect("tags");
    assert_eq!(orphans, 0, "tag assignments removed with the contact");

    let r = post(
        &app,
        "/api/contact/delete_ndp",
        &admin,
        json!({"ids": ["13"]}),
    )
    .await;
    assert_eq!(r.body["msg"], "Contacts deleted successfully");
    assert!(!rows(&h).await.iter().any(|r| r.0 == 13));

    let logs: Vec<String> = sqlx::query_scalar(
        "SELECT log FROM bm_operation_logs WHERE type = 'Contacts-Subscribers' ORDER BY id",
    )
    .fetch_all(&h.store.pg)
    .await
    .expect("logs");
    assert_eq!(
        logs.last().map(String::as_str),
        Some("Delete contacts successfully :c@x.com")
    );
    assert!(logs.contains(&"Delete contacts :a@x.com successfully".to_owned()));
}
