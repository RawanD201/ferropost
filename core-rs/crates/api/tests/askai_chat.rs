//! AskAI chats against a fake streaming provider: the answer streamed as
//! server-sent events, the `http_request` tool fetching a (local) page
//! from this server, the template HTML saved to the chat and to the
//! template made from it, provider errors shown in the chat, and chat ids
//! that cannot leave `conf/chat`.

mod common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::response::IntoResponse;
use axum::routing;
use common::*;
use serde_json::{Value, json};

const PAGE: &str =
    "<html><head><title>Acme</title></head><body><p>We build rockets.</p></body></html>";
const HTML: &str = "<!DOCTYPE html>\n<html><body>Hi <a href=\"{{ UnsubscribeURL . }}\">Unsubscribe</a></body></html>";

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{addr}")
}

fn sse(events: &[Value]) -> axum::response::Response {
    let mut body: String = events.iter().map(|e| format!("data: {e}\n\n")).collect();
    body.push_str("data: [DONE]\n\n");
    ([("content-type", "text/event-stream")], body).into_response()
}

/// First a tool call for the page, then (with the page) the template.
async fn fake_provider(site: String, asked: Arc<Mutex<Vec<Value>>>) -> String {
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            routing::post(move |body: String| {
                let (site, asked) = (site.clone(), asked.clone());
                async move {
                    let request: Value = serde_json::from_str(&body).unwrap_or_default();
                    asked.lock().expect("lock").push(request.clone());
                    let has_tool_reply = request["messages"]
                        .as_array()
                        .is_some_and(|m| m.iter().any(|m| m["role"] == "tool"));
                    if !has_tool_reply {
                        let args = json!({"url": format!("{site}/")}).to_string();
                        let (a, b) = args.split_at(5);
                        return sse(&[
                            json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1",
                                "type": "function", "function": {"name": "http_request", "arguments": a}}]}}]}),
                            json!({"choices": [{"delta": {"tool_calls": [{"index": 0,
                                "function": {"arguments": b}}]}, "finish_reason": "tool_calls"}]}),
                        ]);
                    }
                    let (first, rest) = HTML.split_at(20);
                    sse(&[
                        json!({"choices": [{"delta": {"reasoning_content": "Thinking about rockets."}}]}),
                        json!({"choices": [{"delta": {"content": "Here is your email:\n```html\n"}}]}),
                        json!({"choices": [{"delta": {"content": first}}]}),
                        json!({"choices": [{"delta": {"content": rest}}]}),
                        json!({"choices": [{"delta": {"content": "\n```"}, "finish_reason": "stop"}]}),
                        json!({"choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}),
                    ])
                }
            }),
        )
        .route(
            "/broken/chat/completions",
            routing::post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        );
    serve(app).await
}

fn events(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str(d.trim()).ok())
        .collect()
}

async fn data(app: &Router, auth: &str, path: &str, body: Value) -> Value {
    let r = post(app, &format!("/api/askai/chat/{path}"), auth, body).await;
    assert_eq!(r.body["code"], 0, "{path}: {}", r.body);
    r.body["data"].clone()
}

fn supplier(h: &Harness, name: &str, base_url: &str) {
    let dir = h.root.path().join("conf/supplier").join(name);
    std::fs::create_dir_all(&dir).expect("supplier");
    std::fs::write(
        dir.join("config.json"),
        json!({"supplierTitle": name, "supplierName": name, "baseUrl": base_url,
               "apiKey": "sk-test-1234567890", "status": true})
        .to_string(),
    )
    .expect("config");
    std::fs::write(
        dir.join("models.json"),
        json!([{"modelId": "mail-model", "status": true, "capability": ["llm", "tools"], "max_tokens": 4096}])
            .to_string(),
    )
    .expect("models");
}

#[tokio::test]
async fn chats() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let site =
        serve(Router::new().route("/", routing::get(|| async { axum::response::Html(PAGE) })))
            .await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let provider = fake_provider(site.clone(), asked.clone()).await;
    supplier(&h, "OpenAI", &format!("{provider}/v1"));
    supplier(&h, "Broken", &format!("{provider}/broken"));
    let project = h.root.path().join("conf/askai/acme.test");
    std::fs::create_dir_all(&project).expect("project");
    std::fs::write(
        project.join("company_profile.json"),
        json!({"legal_company_name": "Acme Rockets Ltd."}).to_string(),
    )
    .expect("profile");
    let app = h.app(&[("FERROPOST_FETCH_PRIVATE", "1")]);
    let admin = bearer(&token(1, "access_token", "admin-chat"));
    let auth = admin.as_str();

    let created = data(
        &app,
        auth,
        "create_chat",
        json!({"domain": "acme.test", "add_type": 99, "temp_name": "AI_temp_1"}),
    )
    .await;
    let chat_id = created["chatId"].as_str().expect("id").to_owned();
    sqlx::query(
        "INSERT INTO email_templates (temp_name, add_type, content, render, create_time, update_time, chat_id)
         VALUES ('AI_temp_1', 99, '', '', 1, 1, $1)",
    )
    .bind(&chat_id)
    .execute(pg)
    .await
    .expect("template");
    let list = data(&app, auth, "get_chat_list", json!({})).await;
    assert_eq!(list[0]["chatId"], chat_id);

    // --- Validation ------------------------------------------------------------------------
    for (body, code) in [
        (
            json!({"chatId": chat_id, "supplierName": "OpenAI", "modelId": "mail-model", "content": " "}),
            412,
        ),
        (
            json!({"chatId": chat_id, "supplierName": "OpenAI", "modelId": "nope", "content": "x"}),
            404,
        ),
        (
            json!({"chatId": "../../supplier", "supplierName": "OpenAI", "modelId": "mail-model", "content": "x"}),
            412,
        ),
    ] {
        let r = post(&app, "/api/askai/chat/chat", auth, body.clone()).await;
        assert_eq!(r.body["code"], code, "{body}: {}", r.body);
    }
    std::fs::create_dir_all(h.root.path().join("keep")).expect("keep");
    let r = post(
        &app,
        "/api/askai/chat/remove_chat",
        auth,
        json!({"chatId": "../../keep"}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    assert!(
        h.root.path().join("keep").exists(),
        "Go deleted any folder named this way"
    );

    // --- An answer, with the page fetched by the tool -------------------------------------------
    let r = post(
        &app,
        "/api/askai/chat/chat",
        auth,
        json!({"chatId": chat_id, "supplierName": "OpenAI", "modelId": "mail-model",
               "content": format!("Make an email from {site}/"), "is_text": "false"}),
    )
    .await;
    assert_eq!(
        r.headers["content-type"],
        "text/event-stream; charset=utf-8"
    );
    let stream = events(r.body.as_str().unwrap_or_default());
    let content: String = stream
        .iter()
        .filter_map(|e| e["content"].as_str())
        .collect();
    assert!(
        content.contains(&format!("<tool>Requesting URL: {site}/ complete</tool>")),
        "{content}"
    );
    assert!(content.contains("```html\n<!DOCTYPE html>"), "{content}");
    assert!(
        stream
            .iter()
            .any(|e| e["reasoning"] == "Thinking about rockets." && e["content"] == ""),
        "reasoning is sent apart"
    );
    assert_eq!(stream.last().expect("events")["is_end"], true);

    let requests = asked.lock().expect("lock").clone();
    assert_eq!(requests.len(), 2, "one tool round, then the answer");
    let system = requests[0]["messages"][0]["content"]
        .as_str()
        .unwrap_or_default();
    assert!(system.starts_with("You are a seasoned marketing email expert"));
    assert!(
        system.contains("LegalCompanyName: Acme Rockets Ltd."),
        "{system}"
    );
    assert_eq!(requests[0]["tools"][0]["function"]["name"], "http_request");
    let tool_reply = requests[1]["messages"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["role"] == "tool"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or_default()
        .to_owned();
    assert!(tool_reply.contains("We build rockets."), "{tool_reply}");

    let html = data(&app, auth, "get_html", json!({"chatId": chat_id})).await;
    assert_eq!(html["html_content"], HTML);
    assert_eq!(
        html["last_usage"],
        json!({"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}),
        "the provider's own counts"
    );
    let saved: String =
        sqlx::query_scalar("SELECT content FROM email_templates WHERE chat_id = $1")
            .bind(&chat_id)
            .fetch_one(pg)
            .await
            .expect("template");
    assert_eq!(saved, HTML);
    let info = data(&app, auth, "info", json!({"chatId": chat_id})).await;
    assert_eq!(info["supplierName"], "OpenAI");
    assert_eq!(info["modelId"], "mail-model");
    let messages = info["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 2);
    assert_eq!(
        (messages[0]["role"].as_str(), messages[1]["role"].as_str()),
        (Some("user"), Some("assistant"))
    );
    assert_eq!(messages[1]["reasoning"], "Thinking about rockets.");
    assert_eq!(messages[1]["ppid"], messages[0]["messageId"]);

    // --- Edits and copies -------------------------------------------------------------------------
    data(
        &app,
        auth,
        "modify_html",
        json!({"chatId": chat_id, "content": "<p>edited</p>"}),
    )
    .await;
    let saved: String =
        sqlx::query_scalar("SELECT content FROM email_templates WHERE chat_id = $1")
            .bind(&chat_id)
            .fetch_one(pg)
            .await
            .expect("template");
    assert_eq!(saved, "<p>edited</p>");
    let copied = data(
        &app,
        auth,
        "copy_chat",
        json!({"chatId": chat_id, "domain": "acme.test"}),
    )
    .await;
    assert_eq!(copied["content"], "<p>edited</p>");
    let copy_id = copied["chatId"].as_str().expect("copy").to_owned();
    let copy_info = data(&app, auth, "info", json!({"chatId": copy_id})).await;
    assert_eq!(copy_info["modelId"], "mail-model");
    let r = post(
        &app,
        "/api/askai/chat/stop",
        auth,
        json!({"chatId": chat_id}),
    )
    .await;
    assert!(
        r.body["msg"]
            .as_str()
            .is_some_and(|m| m.contains("already stopped")),
        "{}",
        r.body
    );

    // --- A provider error is shown in the chat -----------------------------------------------------
    let r = post(
        &app,
        "/api/askai/chat/chat",
        auth,
        json!({"chatId": copy_id, "supplierName": "Broken", "modelId": "mail-model", "content": "Hello"}),
    )
    .await;
    let content: String = events(r.body.as_str().unwrap_or_default())
        .iter()
        .filter_map(|e| e["content"].as_str())
        .collect();
    assert!(
        content.contains("Error: the AI provider answered 500"),
        "{content}"
    );
    let copy_info = data(&app, auth, "info", json!({"chatId": copy_id})).await;
    assert_eq!(
        copy_info["messages"],
        json!([]),
        "a failed answer is not kept"
    );

    data(&app, auth, "remove_chat", json!({"chatId": copy_id})).await;
    let r = post(
        &app,
        "/api/askai/chat/info",
        auth,
        json!({"chatId": copy_id}),
    )
    .await;
    assert_eq!(r.body["code"], 404);
}
