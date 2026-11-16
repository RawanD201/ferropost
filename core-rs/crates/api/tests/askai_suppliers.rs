//! AskAI providers and models against a fake OpenAI-compatible API: the
//! built-in templates, masked keys that keep the stored key when sent
//! back, model listing from the provider, edits that survive a disabled
//! provider, and provider names that cannot leave `conf/supplier`.

mod common;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use common::*;
use serde_json::{Value, json};

const KEY: &str = "sk-test-1234567890";

async fn fake_provider() -> String {
    async fn models(headers: HeaderMap) -> (StatusCode, String) {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if auth != format!("Bearer {KEY}") {
            return (StatusCode::UNAUTHORIZED, "{}".to_owned());
        }
        (
            StatusCode::OK,
            json!({"data": [{"id": "gpt-test"}, {"id": "gpt-mini"}]}).to_string(),
        )
    }
    let app = Router::new()
        .route("/v1", get(|| async { "ok" }))
        .route("/v1/models", get(models));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{addr}/v1")
}

async fn data(app: &Router, auth: &str, path: &str, body: Value) -> Value {
    let r = post(app, &format!("/api/askai/supplier/{path}"), auth, body).await;
    assert_eq!(r.body["code"], 0, "{path}: {}", r.body);
    r.body["data"].clone()
}

#[tokio::test]
async fn suppliers() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let base = fake_provider().await;
    let conf = h.root.path().join("conf/supplier");
    let template = conf.join("template/OpenAI");
    std::fs::create_dir_all(&template).expect("template");
    std::fs::write(
        template.join("config.json"),
        json!({"supplierTitle": "OpenAI", "supplierName": "OpenAI", "baseUrl": "",
               "apiKey": "", "status": true, "sort": 1})
        .to_string(),
    )
    .expect("config");
    std::fs::write(template.join("models.json"), "[]").expect("models");
    let app = h.app(&[]);
    let admin = bearer(&token(1, "access_token", "admin-askai"));
    let auth = admin.as_str();

    // --- Templates are copied, keys never shown -------------------------------------------
    let list = data(&app, auth, "list", json!({})).await;
    assert_eq!(list[0]["supplierName"], "OpenAI");
    assert_eq!(list[0]["status"], false, "no key yet");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(conf.join("OpenAI/config.json"))
            .expect("copied")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "keys are owner-only (Go: 0777)");
    }
    let status = data(&app, auth, "status", json!({})).await;
    assert_eq!(status["is_configured"], false);

    data(
        &app,
        auth,
        "set_supplier_config",
        json!({"supplierName": "OpenAI", "baseUrl": base, "apiKey": KEY}),
    )
    .await;
    let shown = data(
        &app,
        auth,
        "get_supplier_config",
        json!({"supplierName": "OpenAI"}),
    )
    .await;
    let masked = shown["apiKey"].as_str().expect("key").to_owned();
    assert_ne!(masked, KEY);
    assert!(
        masked.starts_with("sk-") && masked.ends_with("7890"),
        "{masked}"
    );
    // The console sends the mask back with other changes: the key stays.
    data(
        &app,
        auth,
        "set_supplier_config",
        json!({"supplierName": "OpenAI", "baseUrl": format!("{base}/"), "apiKey": masked}),
    )
    .await;
    let stored: Value =
        serde_json::from_slice(&std::fs::read(conf.join("OpenAI/config.json")).expect("read"))
            .expect("json");
    assert_eq!(stored["apiKey"], KEY);
    assert_eq!(stored["baseUrl"], format!("{base}/"));
    data(
        &app,
        auth,
        "testing",
        json!({"supplierName": "OpenAI", "baseUrl": base, "apiKey": masked}),
    )
    .await;
    let r = post(
        &app,
        "/api/askai/supplier/testing",
        auth,
        json!({"supplierName": "OpenAI", "baseUrl": base, "apiKey": "sk-wrong-000000000"}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.contains("invalid API key")),
        "{}",
        r.body
    );
    data(
        &app,
        auth,
        "set_supplier_status",
        json!({"supplierName": "OpenAI", "status": true}),
    )
    .await;

    // --- Models come from the provider ------------------------------------------------------
    let r = call(
        &app,
        "/api/askai/supplier/models?supplierName=OpenAI",
        &[("authorization", auth)],
        false,
    )
    .await;
    let models = r.body["data"].as_array().expect("models").clone();
    let ids: Vec<&str> = models
        .iter()
        .filter_map(|m| m["modelId"].as_str())
        .collect();
    assert_eq!(ids, ["gpt-test", "gpt-mini"], "{}", r.body);
    assert_eq!(models[0]["title"], "OpenAI/gpt-test");
    assert_eq!(models[0]["max_tokens"], 8192);
    assert_eq!(
        data(&app, auth, "status", json!({})).await["is_configured"],
        true
    );

    // Edits while the provider is off keep the other models' own status.
    data(
        &app,
        auth,
        "set_supplier_status",
        json!({"supplierName": "OpenAI", "status": false}),
    )
    .await;
    let all = data(&app, auth, "models", json!({})).await;
    assert_eq!(all, json!([]), "a disabled provider offers no model");
    data(
        &app,
        auth,
        "set_model_title",
        json!({"supplierName": "OpenAI", "modelId": "gpt-test", "title": "Test"}),
    )
    .await;
    data(
        &app,
        auth,
        "set_supplier_status",
        json!({"supplierName": "OpenAI", "status": true}),
    )
    .await;
    let models = data(&app, auth, "models", json!({"supplier_name": "OpenAI"})).await;
    assert_eq!(models[0]["title"], "Test");
    assert_eq!(
        (models[0]["status"].clone(), models[1]["status"].clone()),
        (json!(true), json!(true)),
        "Go saved every model as off here"
    );
    data(
        &app,
        auth,
        "modify_model",
        json!({"supplierName": "OpenAI", "modelId": "gpt-mini", "title": "Mini",
               "max_tokens": 4096, "capability": ["llm", "Vision", "llm"]}),
    )
    .await;
    let models = data(&app, auth, "models", json!({"supplierName": "OpenAI"})).await;
    assert_eq!(models[1]["capability"], json!(["llm", "vision"]));
    assert_eq!(models[1]["max_tokens"], 4096);

    let r = post(
        &app,
        "/api/askai/supplier/remove_model",
        auth,
        json!({"supplierName": "OpenAI", "modelId": "gpt-test"}),
    )
    .await;
    assert_eq!(
        r.body["msg"], "Model removed successfully",
        "Go said \"Model not found\""
    );
    let r = post(
        &app,
        "/api/askai/supplier/remove_model",
        auth,
        json!({"supplierName": "OpenAI", "modelId": "gpt-test"}),
    )
    .await;
    assert_eq!(r.body["code"], 404, "{}", r.body);
    let r = post(
        &app,
        "/api/askai/supplier/add_model",
        auth,
        json!({"supplierName": "Nobody", "title": "x", "modelId": "x", "max_tokens": 10,
               "capability": ["llm"]}),
    )
    .await;
    assert_ne!(r.body["code"], 0, "{}", r.body);

    // --- Custom providers ------------------------------------------------------------------
    data(
        &app,
        auth,
        "add_supplier",
        json!({"supplierTitle": "Local", "supplierName": "local-llm", "baseUrl": base, "apiKey": KEY}),
    )
    .await;
    let r = post(
        &app,
        "/api/askai/supplier/add_supplier",
        auth,
        json!({"supplierTitle": "Local", "supplierName": "local-llm", "baseUrl": base, "apiKey": KEY}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.contains("already exists")),
        "{}",
        r.body
    );
    data(
        &app,
        auth,
        "remove_supplier",
        json!({"supplierName": "local-llm"}),
    )
    .await;
    assert!(!conf.join("local-llm").exists());
    let r = post(
        &app,
        "/api/askai/supplier/remove_supplier",
        auth,
        json!({"supplierName": "OpenAI"}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.contains("built-in")),
        "{}",
        r.body
    );
    std::fs::create_dir_all(h.root.path().join("victim")).expect("victim");
    for name in ["../../victim", "..", "template"] {
        let r = post(
            &app,
            "/api/askai/supplier/remove_supplier",
            auth,
            json!({"supplierName": name}),
        )
        .await;
        assert_eq!(r.body["code"], 412, "{name}: {}", r.body);
    }
    assert!(
        h.root.path().join("victim").exists(),
        "Go deleted any folder named this way"
    );
}
