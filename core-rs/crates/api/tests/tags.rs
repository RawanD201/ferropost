//! End-to-end tests for tag writes and their operation-log entries.

mod common;

use common::*;
use serde_json::{Value, json};

async fn log_rows(h: &Harness) -> Vec<(i64, String, String, String, String)> {
    sqlx::query_as::<_, (i64, String, String, String, String)>(
        "SELECT user_id, type, log, ip, info FROM bm_operation_logs ORDER BY id",
    )
    .fetch_all(&h.store.pg)
    .await
    .expect("logs")
}

async fn contact_tag_pairs(h: &Harness) -> Vec<(i32, i32)> {
    sqlx::query_as::<_, (i32, i32)>(
        "SELECT contact_id, tag_id FROM bm_contact_tags ORDER BY contact_id, tag_id",
    )
    .fetch_all(&h.store.pg)
    .await
    .expect("pairs")
}

#[tokio::test]
async fn tag_writes() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-tags"));

    // --- create ---------------------------------------------------------
    let r = post(&app, "/api/tags/create", &admin, json!({"group_id": 1})).await;
    assert_eq!(r.body["code"], 412);
    assert_eq!(r.body["msg"], "The name field is required");

    let r = post(
        &app,
        "/api/tags/create",
        &admin,
        json!({"group_id": 999, "name": "x"}),
    )
    .await;
    assert_eq!(
        (r.body["code"].clone(), r.body["msg"].clone()),
        (json!(404), json!("Group not found"))
    );

    let r = post(
        &app,
        "/api/tags/create",
        &admin,
        json!({"group_id": "1", "name": " new "}),
    )
    .await;
    assert_eq!(
        r.body,
        json!({"success": true, "code": 0, "msg": "Tag created successfully", "data": null})
    );
    let new_id: i32 =
        sqlx::query_scalar("SELECT id FROM bm_tags WHERE group_id = 1 AND name = 'new'")
            .fetch_one(&h.store.pg)
            .await
            .expect("created, trimmed");

    let r = post(
        &app,
        "/api/tags/create",
        &admin,
        json!({"group_id": 1, "name": "new"}),
    )
    .await;
    assert_eq!(
        (r.body["code"].clone(), r.body["msg"].clone()),
        (json!(409), json!("Tag name already exists"))
    );

    let long = "x".repeat(51);
    let r = post(
        &app,
        "/api/tags/create",
        &admin,
        json!({"group_id": 1, "name": long}),
    )
    .await;
    assert_eq!(r.body["code"], 412);

    // Audit entry plus snapshot without credentials.
    let logs = log_rows(&h).await;
    assert_eq!(logs.len(), 1, "only successful writes are logged");
    let (user_id, log_type, log, ip, info) = &logs[0];
    assert_eq!((*user_id, log_type.as_str()), (1, "Contacts-Tag"));
    assert_eq!(log, "Create [Customers] tag :new successfully");
    assert_eq!(ip, "203.0.113.9");
    let snapshot: Value =
        serde_json::from_str(&std::fs::read_to_string(info).expect("snapshot file"))
            .expect("snapshot json");
    assert_eq!(snapshot, json!({"group_id": 1, "name": " new "}));
    assert!(
        info.starts_with(
            &h.core_dir()
                .join("../logs/core/operation_log")
                .to_string_lossy()
                .into_owned()
        )
    );

    // RBAC: viewer only has tags:read.
    let viewer = bearer(&token(2, "access_token", "viewer-tags"));
    let r = post(
        &app,
        "/api/tags/create",
        &viewer,
        json!({"group_id": 1, "name": "nope"}),
    )
    .await;
    assert_eq!(r.body["code"], 403);

    // --- update ---------------------------------------------------------
    let r = post(
        &app,
        "/api/tags/update",
        &admin,
        json!({"id": 999, "name": "y"}),
    )
    .await;
    assert_eq!(
        (r.body["code"].clone(), r.body["msg"].clone()),
        (json!(404), json!("Tag not found"))
    );

    let r = post(
        &app,
        "/api/tags/update",
        &admin,
        json!({"id": new_id, "name": "vip"}),
    )
    .await;
    assert_eq!(r.body["code"], 409, "duplicate within the group");

    // Form-encoded bodies work like they did in GoFrame.
    let r = send(
        &app,
        "POST",
        "/api/tags/update",
        &[
            ("authorization", &admin),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        None,
        false,
    )
    .await;
    assert_eq!(r.body["code"], 412, "empty form fails validation");
    let r = post(
        &app,
        "/api/tags/update",
        &admin,
        json!({"id": new_id, "name": "newer"}),
    )
    .await;
    assert_eq!(r.body["msg"], "Tag updated successfully");

    // --- batch_contacts -------------------------------------------------
    for sql in ["INSERT INTO bm_contacts (id, email, group_id) VALUES
            (10, 'a@x.com', 1), (11, 'B@x.com', 1), (12, 'c@x.com', 1), (20, 'a@x.com', 2)"]
    {
        sqlx::query(sql).execute(&h.store.pg).await.expect(sql);
    }
    sync_sequences(&h.store).await;

    let batch = |tags: Value, data: &str, include: i64| json!({"group_id": 1, "tag_ids": tags, "data": data, "mark_include": include});
    let r = post(
        &app,
        "/api/tags/batch_contacts",
        &admin,
        batch(json!([3]), "a@x.com", 1),
    )
    .await;
    assert_eq!(r.body["code"], 400);
    assert_eq!(r.body["msg"], "Tag '50 off' does not belong to this group");

    let r = post(
        &app,
        "/api/tags/batch_contacts",
        &admin,
        batch(json!([1, 404]), "a@x.com", 1),
    )
    .await;
    assert_eq!(r.body["msg"], "Some tags not found");

    let r = post(
        &app,
        "/api/tags/batch_contacts",
        &admin,
        batch(json!([1]), "nonsense", 1),
    )
    .await;
    assert_eq!(r.body["msg"], "No valid emails provided");

    let r = post(
        &app,
        "/api/tags/batch_contacts",
        &admin,
        batch(json!([1]), "a@x.com", 2),
    )
    .await;
    assert_eq!(r.body["code"], 412);

    // Include: a and b (case-insensitive) get both tags; the missing address
    // and group 2's a@x.com are untouched.
    let r = post(
        &app,
        "/api/tags/batch_contacts",
        &admin,
        batch(json!([1, new_id]), "a@x.com\nb@x.com\nmissing@x.com", 1),
    )
    .await;
    assert_eq!(r.body["success"], true);
    assert_eq!(
        r.body["msg"],
        "Batch tag operation completed ( 2  skipped,  0  errors)"
    );
    assert_eq!(
        contact_tag_pairs(&h).await,
        [(10, 1), (10, new_id), (11, 1), (11, new_id)]
    );

    // Exclude: everyone in group 1 except a@x.com gets tag 1; b already has it.
    let r = post(
        &app,
        "/api/tags/batch_contacts",
        &admin,
        batch(json!("1"), "A@X.com", 0),
    )
    .await;
    assert_eq!(
        r.body["msg"],
        "Batch tag operation completed ( 2  skipped,  0  errors)"
    );
    assert!(contact_tag_pairs(&h).await.contains(&(12, 1)));
    assert!(
        !contact_tag_pairs(&h).await.contains(&(20, 1)),
        "other groups untouched"
    );

    let logs = log_rows(&h).await;
    let last = &logs.last().expect("log").2;
    assert_eq!(
        last,
        "Batch add tags: vip Not included for 1 contact-tag pairs successfully"
    );

    // --- delete ---------------------------------------------------------
    let r = post(&app, "/api/tags/delete", &admin, json!({"id": 999})).await;
    assert_eq!(r.body["code"], 404);
    let r = post(&app, "/api/tags/delete", &admin, json!({"id": new_id})).await;
    assert_eq!(r.body["msg"], "Tag deleted successfully");
    assert!(
        contact_tag_pairs(&h)
            .await
            .iter()
            .all(|(_, tag)| *tag != new_id),
        "assignments removed with the tag"
    );
    let logs = log_rows(&h).await;
    assert_eq!(
        logs.last().expect("log").2,
        "Delete tag: newer successfully"
    );
}
