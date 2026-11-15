//! End-to-end tests for contact groups and contact import.

mod common;

use common::*;
use serde_json::{Value, json};

async fn contacts_of(h: &Harness, group: i64) -> Vec<(String, i32, i32, Value)> {
    sqlx::query_as::<_, (String, i32, i32, sqlx::types::JsonValue)>(
        "SELECT email, active, status, attribs FROM bm_contacts WHERE group_id = $1 ORDER BY email",
    )
    .bind(group as i32)
    .fetch_all(&h.store.pg)
    .await
    .expect("contacts")
}

async fn group_id(h: &Harness, name: &str) -> Option<i64> {
    sqlx::query_scalar::<_, i32>("SELECT id FROM bm_contact_groups WHERE name = $1")
        .bind(name)
        .fetch_optional(&h.store.pg)
        .await
        .expect("group")
        .map(i64::from)
}

#[tokio::test]
async fn contact_groups() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-groups"));
    let code_msg = |r: &Reply| (r.body["code"].clone(), r.body["msg"].clone());

    // --- create (type 1) --------------------------------------------------
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 1}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(412), json!("The name field is required"))
    );
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 4, "name": "x"}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 1, "name": "News"}),
    )
    .await;
    assert_eq!(r.body["msg"], "Group created successfully");
    let news = r.body["data"]["group_id"].as_i64().expect("group_id");
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 1, "name": "News"}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(409), json!("The group name already exists"))
    );

    // --- create (type 2): CSV with headers ----------------------------------
    let csv = "email,active,attributes\na@x.com,1,\"{\"\"plan\"\":\"\"pro\"\"}\"\nb@x.com,0,\nbad,1,\na@x.com,1,\n";
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 2, "name": "Imported", "file_data": csv, "file_type": "csv"}),
    )
    .await;
    assert_eq!(
        r.body["msg"],
        "Group created and contacts imported successfully"
    );
    let imported = r.body["data"]["group_id"].as_i64().expect("group_id");
    assert_eq!(
        contacts_of(&h, imported).await,
        [
            ("a@x.com".into(), 1, 1, json!({"plan": "pro"})),
            ("b@x.com".into(), 0, 1, json!({})),
        ]
    );

    // A file without valid contacts creates nothing (Go kept an empty group).
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 2, "name": "Broken", "file_data": "nope\nstill nope"}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(400), json!("No valid contacts found in file"))
    );
    assert_eq!(group_id(&h, "Broken").await, None, "rolled back");

    // --- create (type 3): plain lines into an existing group ----------------
    let lines = "c@x.com\nd@x.com, {\"city\": \"Erbil\"}\n";
    for _ in 0..2 {
        let r = post(
            &app,
            "/api/contact/group/create",
            &admin,
            json!({"create_type": 3, "group_id": news, "file_data": lines}),
        )
        .await;
        assert_eq!(
            r.body["msg"], "Contacts imported to existing group successfully",
            "re-import works"
        );
    }
    assert_eq!(contacts_of(&h, news).await.len(), 2);
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 3, "file_data": lines}),
    )
    .await;
    assert_eq!(
        r.body["msg"],
        "Group ID is required for importing to existing group"
    );
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 3, "group_id": 999, "file_data": lines}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(404), json!("Group 999 does not exist"))
    );

    // --- import -------------------------------------------------------------
    let r = post(
        &app,
        "/api/contact/group/import",
        &admin,
        json!({"group_ids": [news], "import_type": 2, "contacts": "c@x.com\ne@x.com",
               "default_active": 1, "status": 1}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "Successfully imported 1 contacts",
        "c@x.com already there"
    );
    assert_eq!(r.body["data"]["imported_count"], 1);

    let r = post(
        &app,
        "/api/contact/group/import",
        &admin,
        json!({"group_ids": [news], "import_type": 2, "contacts": "c@x.com",
               "default_active": 0, "status": 1, "overwrite": 1}),
    )
    .await;
    assert_eq!(r.body["data"]["imported_count"], 1, "updated in place");
    let c = contacts_of(&h, news).await;
    assert_eq!(
        (c[0].0.as_str(), c[0].1),
        ("c@x.com", 0),
        "overwrite applied the new state"
    );

    let r = post(
        &app,
        "/api/contact/group/import",
        &admin,
        json!({"group_ids": [999], "import_type": 2, "contacts": "z@x.com"}),
    )
    .await;
    assert_eq!(r.body["code"], 404);
    let r = post(
        &app,
        "/api/contact/group/import",
        &admin,
        json!({"group_ids": [news], "import_type": 2}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(400), json!("Contacts content cannot be empty"))
    );
    let r = post(
        &app,
        "/api/contact/group/import",
        &admin,
        json!({"group_ids": [news], "import_type": 3}),
    )
    .await;
    assert_eq!(r.body["code"], 412);

    // --- list / all ---------------------------------------------------------
    let r = call(
        &app,
        "/api/contact/group/list?page=1&page_size=10",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["msg"], "Group list retrieved successfully");
    assert_eq!(
        r.body["data"]["total"], 4,
        "two fixtures plus News and Imported"
    );
    let list = r.body["data"]["list"].as_array().expect("list");
    let row = list
        .iter()
        .find(|g| g["name"] == "Imported")
        .expect("Imported");
    assert_eq!(
        (
            row["total_count"].clone(),
            row["active_count"].clone(),
            row["unsubscribe_count"].clone()
        ),
        (json!(2), json!(1), json!(1))
    );
    assert!(
        list.iter()
            .all(|g| g["token"].as_str().is_some_and(|t| t.len() == 12)),
        "missing tokens backfilled"
    );

    let r = call(
        &app,
        "/api/contact/group/all?keyword=New",
        &[("authorization", &admin)],
        false,
    )
    .await;
    assert_eq!(r.body["data"]["list"].as_array().expect("list").len(), 1);
    assert_eq!(r.body["data"]["list"][0]["name"], "News");

    // --- update -------------------------------------------------------------
    let r = post(
        &app,
        "/api/contact/group/update",
        &admin,
        json!({"group_id": news, "name": "News2", "double_optin": 1}),
    )
    .await;
    assert_eq!(r.body["msg"], "Group updated successfully");
    let r = post(
        &app,
        "/api/contact/group/update",
        &admin,
        json!({"group_id": news, "welcome_subject": "Hi"}),
    )
    .await;
    assert_eq!(r.body["code"], 0);
    let (optin, subject): (i16, String) =
        sqlx::query_as("SELECT double_optin, welcome_subject FROM bm_contact_groups WHERE id = $1")
            .bind(news as i32)
            .fetch_one(&h.store.pg)
            .await
            .expect("group");
    assert_eq!(
        (optin, subject.as_str()),
        (1, "Hi"),
        "omitted flags are kept"
    );

    let r = post(
        &app,
        "/api/contact/group/update",
        &admin,
        json!({"group_id": news, "name": "Customers"}),
    )
    .await;
    assert_eq!(r.body["code"], 409);
    let r = post(
        &app,
        "/api/contact/group/update",
        &admin,
        json!({"group_id": 999, "name": "Nope"}),
    )
    .await;
    assert_eq!(code_msg(&r), (json!(404), json!("Group not found")));
    let r = post(
        &app,
        "/api/contact/group/update",
        &admin,
        json!({"group_id": news}),
    )
    .await;
    assert_eq!(code_msg(&r), (json!(400), json!("No fields to update")));

    let r = post(
        &app,
        "/api/contact/group/update_unsubscribe",
        &admin,
        json!({"group_id": news, "unsubscribe_subject": "Bye", "send_unsubscribe_email": 1}),
    )
    .await;
    assert_eq!(r.body["msg"], "Group updated successfully");

    let logs: Vec<String> = sqlx::query_scalar(
        "SELECT log FROM bm_operation_logs WHERE type = 'Contacts-Group' ORDER BY id",
    )
    .fetch_all(&h.store.pg)
    .await
    .expect("logs");
    assert!(logs.contains(&"Update the subscription link Settings for group: News2 ".to_owned()));
    assert!(logs.contains(&"Update the Unsubscribe Settings for group: News2 ".to_owned()));

    // --- counts -------------------------------------------------------------
    let r = post(
        &app,
        "/api/contact/group/contact_count",
        &admin,
        json!({"group_ids": [news, imported]}),
    )
    .await;
    assert_eq!(r.body["data"]["total"], 3, "d, e and a are subscribed");

    sqlx::query("INSERT INTO bm_tags (id, group_id, name) VALUES (50, $1, 'pro')")
        .bind(imported as i32)
        .execute(&h.store.pg)
        .await
        .expect("tag");
    sqlx::query(
        "INSERT INTO bm_contact_tags (contact_id, tag_id)
         SELECT id, 50 FROM bm_contacts WHERE email = 'a@x.com' AND group_id = $1",
    )
    .bind(imported as i32)
    .execute(&h.store.pg)
    .await
    .expect("assign");
    let tag_count = |logic: &str, tags: Value| {
        post(
            &app,
            "/api/contact/group/tag_contact_count",
            &admin,
            json!({"group_id": imported, "tag_ids": tags, "tag_logic": logic}),
        )
    };
    assert_eq!(tag_count("OR", json!([50])).await.body["data"]["total"], 1);
    assert_eq!(tag_count("AND", json!([50])).await.body["data"]["total"], 1);
    assert_eq!(tag_count("NOT", json!([50])).await.body["data"]["total"], 0);
    assert_eq!(tag_count("OR", json!([])).await.body["data"]["total"], 1);
    assert_eq!(tag_count("XOR", json!([50])).await.body["code"], 412);

    // --- merge --------------------------------------------------------------
    let r = post(
        &app,
        "/api/contact/group/create",
        &admin,
        json!({"create_type": 1, "name": "Merged"}),
    )
    .await;
    let merged = r.body["data"]["group_id"].as_i64().expect("group_id");
    let r = post(
        &app,
        "/api/contact/group/merge_contacts",
        &admin,
        json!({"source_groups": [imported, news], "target_group": merged}),
    )
    .await;
    assert_eq!(r.body["msg"], "Contact groups merged successfully");
    let m = contacts_of(&h, merged).await;
    assert_eq!(m.len(), 5);
    let d = m.iter().find(|c| c.0 == "d@x.com").expect("d");
    assert_eq!(
        (d.1, d.2, d.3.clone()),
        (1, 1, json!({"city": "Erbil"})),
        "status and attributes kept"
    );
    let r = post(
        &app,
        "/api/contact/group/merge_contacts",
        &admin,
        json!({"source_groups": [999], "target_group": merged}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(404), json!("Source group 999 not found"))
    );
    let r = post(
        &app,
        "/api/contact/group/merge_contacts",
        &admin,
        json!({"source_groups": [news], "target_group": 999}),
    )
    .await;
    assert_eq!(code_msg(&r), (json!(404), json!("Target group not found")));

    // --- delete -------------------------------------------------------------
    let r = post(
        &app,
        "/api/contact/group/delete",
        &admin,
        json!({"group_ids": [imported, 999]}),
    )
    .await;
    assert_eq!(r.body["msg"], "Groups deleted successfully");
    assert_eq!(
        r.body["data"],
        json!({"success_count": 1, "failed_count": 1})
    );
    assert!(contacts_of(&h, imported).await.is_empty());
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM bm_tags WHERE id = 50) + (SELECT COUNT(*) FROM bm_contact_tags WHERE tag_id = 50)",
    )
    .fetch_one(&h.store.pg)
    .await
    .expect("count");
    assert_eq!(leftovers, 0, "the group's tags and assignments are gone");
    let r = post(
        &app,
        "/api/contact/group/delete",
        &admin,
        json!({"group_ids": []}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
}
