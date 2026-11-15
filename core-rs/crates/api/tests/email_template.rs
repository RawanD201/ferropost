//! End-to-end tests for email templates.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn email_templates() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-tpl"));
    let get = |uri: &str| {
        let (app, admin, uri) = (app.clone(), admin.clone(), uri.to_owned());
        async move { call(&app, &uri, &[("authorization", &admin)], false).await }
    };
    let code_msg = |r: &Reply| (r.body["code"].clone(), r.body["msg"].clone());

    // --- create ---------------------------------------------------------
    let r = post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"add_type": 0}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(412), json!("The temp_name field is required"))
    );
    let r = post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"temp_name": "x", "add_type": 5}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (
            json!(412),
            json!("The add_type value `5` is not in acceptable range: 0,1,2")
        )
    );
    let r = post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"temp_name": "x", "add_type": 0}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(400), json!("File data is required for upload type"))
    );
    let r = post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"temp_name": "x", "add_type": 1, "html_content": "<p>x</p>"}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (
            json!(400),
            json!("Content and render data are required for drag type")
        )
    );

    let r = post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"temp_name": "Welcome", "add_type": 0, "html_content": "<p>Hi</p>", "drag_data": "ignored"}),
    )
    .await;
    assert_eq!(r.body["msg"], "Template created successfully");
    let welcome = r.body["data"]["id"].as_i64().expect("id");

    let r = post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"temp_name": "Welcome", "add_type": 0, "html_content": "<p>Again</p>"}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(409), json!("Template name already exists"))
    );

    let r = post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"temp_name": "Drag", "add_type": 1, "html_content": "<p>D</p>", "drag_data": "{\"blocks\":[]}"}),
    )
    .await;
    let drag = r.body["data"]["id"].as_i64().expect("id");
    post(
        &app,
        "/api/email_template/create",
        &admin,
        json!({"temp_name": "AI", "add_type": 2, "chat_id": "chat-1"}),
    )
    .await;

    // --- get / list / all -----------------------------------------------
    let r = get(&format!("/api/email_template/get?id={welcome}")).await;
    assert_eq!(r.body["msg"], "Get template successfully");
    let t = &r.body["data"];
    assert_eq!(
        (
            t["temp_name"].clone(),
            t["add_type"].clone(),
            t["html_content"].clone(),
            t["drag_data"].clone(),
            t["chat_id"].clone()
        ),
        (
            json!("Welcome"),
            json!(0),
            json!("<p>Hi</p>"),
            json!(""),
            json!("")
        )
    );
    let r = get("/api/email_template/get?id=999").await;
    assert_eq!(code_msg(&r), (json!(404), json!("Template not found")));

    let r = get("/api/email_template/list?page=1&page_size=10").await;
    assert_eq!(r.body["data"]["total"], 3);
    assert_eq!(r.body["data"]["list"][0]["temp_name"], "AI", "newest first");
    let total = |r: &Reply| r.body["data"]["total"].as_i64().expect("total");
    assert_eq!(
        total(&get("/api/email_template/list?page=1&page_size=10&add_type=1").await),
        1
    );
    assert_eq!(
        total(&get("/api/email_template/list?page=1&page_size=10&add_type=-1").await),
        3
    );
    assert_eq!(
        total(&get("/api/email_template/list?page=1&page_size=10&keyword=Wel").await),
        1
    );
    assert_eq!(
        get("/api/email_template/list?page_size=10").await.body["code"],
        412
    );

    let r = get("/api/email_template/all").await;
    assert_eq!(r.body["data"].as_array().expect("array").len(), 3);

    // --- update ---------------------------------------------------------
    let r = post(
        &app,
        "/api/email_template/update",
        &admin,
        json!({"id": welcome, "temp_name": "Drag"}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(409), json!("Template name already exists"))
    );
    let r = post(
        &app,
        "/api/email_template/update",
        &admin,
        json!({"id": welcome, "html_content": "<p>Updated</p>", "temp_name": ""}),
    )
    .await;
    assert_eq!(r.body["msg"], "Template updated successfully");
    let r = get(&format!("/api/email_template/get?id={welcome}")).await;
    assert_eq!(
        (
            r.body["data"]["temp_name"].clone(),
            r.body["data"]["html_content"].clone()
        ),
        (json!("Welcome"), json!("<p>Updated</p>")),
        "empty fields are left unchanged"
    );
    let r = post(
        &app,
        "/api/email_template/update",
        &admin,
        json!({"id": 999, "temp_name": "z"}),
    )
    .await;
    assert_eq!(r.body["code"], 404);

    // --- copy -----------------------------------------------------------
    for expected in ["Welcome_bak", "Welcome_bak_2"] {
        let r = post(
            &app,
            "/api/email_template/copy",
            &admin,
            json!({"id": welcome}),
        )
        .await;
        assert_eq!(r.body["msg"], "Template copied successfully");
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM email_templates WHERE temp_name = $1)",
        )
        .bind(expected)
        .fetch_one(&h.store.pg)
        .await
        .expect("query");
        assert!(exists, "{expected} created");
    }
    let r = post(&app, "/api/email_template/copy", &admin, json!({"id": 999})).await;
    assert_eq!(r.body["code"], 404);

    // --- delete ---------------------------------------------------------
    let r = post(
        &app,
        "/api/email_template/delete",
        &admin,
        json!({"id": drag}),
    )
    .await;
    assert_eq!(r.body["msg"], "Template deleted successfully");
    let r = post(
        &app,
        "/api/email_template/delete",
        &admin,
        json!({"id": drag}),
    )
    .await;
    assert_eq!(
        code_msg(&r),
        (json!(404), json!("Template not found")),
        "Go crashed here"
    );

    let logs: Vec<String> = sqlx::query_scalar(
        "SELECT log FROM bm_operation_logs WHERE type = 'Email Template' ORDER BY id",
    )
    .fetch_all(&h.store.pg)
    .await
    .expect("logs");
    assert_eq!(
        logs,
        [
            "Create template :Welcome successfully",
            "Create template :Drag successfully",
            "Create template :AI successfully",
            "Update template : successfully",
            "Copy template :Welcome to Welcome_bak successfully",
            "Copy template :Welcome to Welcome_bak_2 successfully",
            "Delete template :Drag successfully",
        ]
    );

    // --- check ----------------------------------------------------------
    let r = post(
        &app,
        "/api/email_template/check",
        &admin,
        json!({"content": "<p>Get it FREE<br>today</p>"}),
    )
    .await;
    assert_eq!(r.body["msg"], "Successful");
    assert_eq!(
        r.body["data"],
        json!({"score": 9.0, "items": [{"name": "Spam Word", "detail": "Contains spam word: free", "score": -1.0}]})
    );
}
