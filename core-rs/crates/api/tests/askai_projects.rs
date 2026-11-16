//! AskAI brand projects: reading a (fake, local) brand site with a (fake)
//! AI model filling in the details, the settings routes, uploaded images
//! served from this server, and private addresses refused unless allowed.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing;
use common::*;
use serde_json::{Value, json};

const SITE: &str = r##"<!DOCTYPE html><html><head><title>Acme Rockets</title>
<meta name="description" content="Rockets for everyone.">
<link rel="icon" href="/static/fav.png">
<style>body{color:#222222} .btn{background:#ee3333}</style></head><body>
<header><img class="logo" src="/img/logo.png" alt="Acme"><nav><a href="/about">About</a></nav></header>
<main><h1>Rockets</h1><p>We build rockets.</p><img src="/hero.jpg" alt="Launch"></main>
<footer><p>© 2026 Acme Rockets Ltd.</p><a href="mailto:hello@acme.test">Mail</a></footer>
</body></html>"##;

const PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAwS2OUAAAAABJRU5ErkJggg==";

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{addr}")
}

/// A provider whose model answers every chat with brand details, keeping
/// what it was asked.
async fn fake_ai(asked: Arc<Mutex<Vec<Value>>>) -> String {
    let app = Router::new().route(
        "/v1/chat/completions",
        routing::post(move |body: String| {
            let asked = asked.clone();
            async move {
                asked
                    .lock()
                    .expect("lock")
                    .push(serde_json::from_str(&body).unwrap_or_default());
                let details = json!({"project_name": "Acme Rockets", "industry": "Aerospace",
                    "legal_company_name": "Acme Rockets Ltd.", "accent_color": "#123ABC",
                    "disclaimer": "No refunds on launched rockets."});
                axum::Json(json!({"choices": [{"message": {"role": "assistant",
                    "content": format!("```json\n{details}\n```")}}]}))
            }
        }),
    );
    format!("{}/v1", serve(app).await)
}

async fn data(app: &Router, auth: &str, path: &str, body: Value) -> Value {
    let r = post_json(app, auth, path, body).await;
    assert_eq!(r.body["code"], 0, "{path}: {}", r.body);
    r.body["data"].clone()
}

async fn post_json(app: &Router, auth: &str, path: &str, body: Value) -> Reply {
    post(app, &format!("/api/askai/project/{path}"), auth, body).await
}

async fn wait_read(app: &Router, auth: &str, domain: &str) -> Value {
    for _ in 0..200 {
        let r = post_json(app, auth, "get_base_info", json!({"domain": domain})).await;
        if r.body["data"]["update_time"].as_i64().unwrap_or(0) > 0 {
            return r.body["data"].clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{domain} was never read");
}

#[tokio::test]
async fn projects() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pg = &h.store.pg;
    let site = serve(
        Router::new()
            .route("/", routing::get(|| async { axum::response::Html(SITE) }))
            .route(
                "/gone",
                routing::get(|| async { (axum::http::StatusCode::NOT_FOUND, "no") }),
            ),
    )
    .await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let ai = fake_ai(asked.clone()).await;
    let supplier = h.root.path().join("conf/supplier/OpenAI");
    std::fs::create_dir_all(&supplier).expect("supplier");
    std::fs::write(
        supplier.join("config.json"),
        json!({"supplierTitle": "OpenAI", "supplierName": "OpenAI", "baseUrl": ai,
               "apiKey": "sk-test-1234567890", "status": true})
        .to_string(),
    )
    .expect("config");
    std::fs::write(
        supplier.join("models.json"),
        json!([{"modelId": "brand-model", "status": true, "capability": ["llm"], "max_tokens": 4096}])
            .to_string(),
    )
    .expect("models");
    for domain in ["acme.test", "closed.test"] {
        sqlx::query(
            "INSERT INTO domain (domain, a_record, create_time, active) VALUES ($1, '', 1, 1)",
        )
        .bind(domain)
        .execute(pg)
        .await
        .expect("domain");
    }
    let app = h.app(&[("FERROPOST_FETCH_PRIVATE", "1")]);
    let admin = bearer(&token(1, "access_token", "admin-projects"));
    let auth = admin.as_str();

    // --- Validation ------------------------------------------------------------------------
    let r = post_json(&app, auth, "create", json!({"domain": "../etc"})).await;
    assert_eq!(r.body["code"], 412, "{}", r.body);
    let r = post_json(&app, auth, "create", json!({"domain": "nowhere.test"})).await;
    assert_eq!(
        r.body["code"], 404,
        "projects belong to domains: {}",
        r.body
    );
    let four: Vec<String> = (0..4).map(|i| format!("https://{i}.test")).collect();
    let r = post_json(
        &app,
        auth,
        "create",
        json!({"domain": "acme.test", "urls": four}),
    )
    .await;
    assert_eq!(r.body["msg"], "Add up to 3 URLs");

    // --- The site is read here, the AI model fills in ------------------------------------------
    data(
        &app,
        auth,
        "create",
        json!({"domain": "acme.test", "urls": [format!("{site}/gone"), format!("{site}/")]}),
    )
    .await;
    let status = data(
        &app,
        auth,
        "get_project_status",
        json!({"domain": "acme.test"}),
    )
    .await;
    assert_eq!(status, json!({"status": true, "create_status": true}));
    let base = wait_read(&app, auth, "acme.test").await;
    assert_eq!(base["project_name"], "Acme Rockets");
    assert_eq!(base["industry"], "Aerospace", "from the AI model");
    assert_eq!(base["description"], "Rockets for everyone.");
    assert_eq!(base["favicon"], format!("{site}/static/fav.png"));
    assert_eq!(base["primary_logo"], format!("{site}/img/logo.png"));
    let docs = base["knowledge_base"].as_array().expect("docs").clone();
    assert_eq!(docs.len(), 1, "{base}");
    assert!(
        docs[0]["content"]
            .as_str()
            .is_some_and(|c| c.contains("We build rockets."))
    );
    let prompt = asked.lock().expect("lock")[0]["messages"][1]["content"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        prompt.contains("We build rockets.") && prompt.contains("#ee3333"),
        "{prompt}"
    );

    let company = data(
        &app,
        auth,
        "get_company_profile",
        json!({"domain": "acme.test"}),
    )
    .await;
    assert_eq!(company["legal_company_name"], "Acme Rockets Ltd.");
    assert_eq!(company["email"], "hello@acme.test");
    assert_eq!(company["web_site"], format!("{site}/"));
    let style = data(
        &app,
        auth,
        "get_style_config",
        json!({"domain": "acme.test"}),
    )
    .await;
    assert_eq!(style["accent_color"], "#123abc");
    assert_eq!(style["text_color"], "#222222");
    let footer = data(&app, auth, "get_footer", json!({"domain": "acme.test"})).await;
    assert_eq!(footer["copyright_text"], "© 2026 Acme Rockets Ltd.");
    assert_eq!(footer["disclaimer"], "No refunds on launched rockets.");
    let sitemap = data(&app, auth, "get_sitemap", json!({"domain": "acme.test"})).await;
    assert_eq!(sitemap[0]["uri_path"], "/about");
    let images = data(&app, auth, "get_images", json!({"domain": "acme.test"})).await;
    assert!(images.as_array().expect("images").len() >= 2, "{images}");

    // --- Settings: empty clears, absent keeps ---------------------------------------------------
    data(
        &app,
        auth,
        "modify_style_config",
        json!({"domain": "acme.test", "heading_font": "Georgia, serif", "body_font": "Verdana"}),
    )
    .await;
    let style = data(
        &app,
        auth,
        "get_style_config",
        json!({"domain": "acme.test"}),
    )
    .await;
    assert_eq!(
        (style["accent_color"].clone(), style["heading_font"].clone()),
        (json!("#123abc"), json!("Georgia, serif")),
        "Go wiped the colours when only fonts were saved"
    );
    let r = post_json(
        &app,
        auth,
        "modify_style_config",
        json!({"domain": "acme.test", "accent_color": "red; background:url(x)"}),
    )
    .await;
    assert_eq!(r.body["code"], 412);
    data(
        &app,
        auth,
        "modify_company_profile",
        json!({"domain": "acme.test", "phone": "", "web_site": "https://acme.test"}),
    )
    .await;
    let company = data(
        &app,
        auth,
        "get_company_profile",
        json!({"domain": "acme.test"}),
    )
    .await;
    assert_eq!(
        company["web_site"], "https://acme.test",
        "the console's `web_site`"
    );
    assert_eq!(company["email"], "hello@acme.test");
    let defaults = data(&app, auth, "get_prompt", json!({"domain": "fresh.test"})).await;
    assert_eq!(
        defaults["prompt"],
        "This is a default prompt. Please customize it."
    );
    assert!(
        !h.root.path().join("conf/askai/fresh.test").exists(),
        "reading no longer writes (Go wrote the default, or failed)"
    );

    // --- Knowledge base ------------------------------------------------------------------------
    let created = data(
        &app,
        auth,
        "create_knowledge_base_file",
        json!({"domain": "acme.test", "title": "Prices", "content": "Rockets cost $1."}),
    )
    .await;
    let kid = created["kid"].as_str().expect("kid").to_owned();
    data(
        &app,
        auth,
        "modify_knowledge_base_file",
        json!({"domain": "acme.test", "kid": kid, "title": "Prices", "content": "Rockets cost $2."}),
    )
    .await;
    for bad in ["../../supplier/OpenAI/config", "x/y"] {
        let r = post_json(
            &app,
            auth,
            "remove_knowledge_base_file",
            json!({"domain": "acme.test", "kid": bad}),
        )
        .await;
        assert_eq!(r.body["code"], 412, "{bad}: {}", r.body);
    }
    data(
        &app,
        auth,
        "remove_knowledge_base_file",
        json!({"domain": "acme.test", "kid": kid}),
    )
    .await;
    let r = post_json(
        &app,
        auth,
        "remove_knowledge_base_file",
        json!({"domain": "acme.test", "kid": kid}),
    )
    .await;
    assert_eq!(r.body["code"], 404);

    // --- Images live on this server --------------------------------------------------------------
    let uploaded = data(
        &app,
        auth,
        "upload_image",
        json!({"domain": "acme.test", "image": PNG, "filename": "logo.png",
               "alt_text": "primary logo", "image_tag": "primary logo"}),
    )
    .await;
    let url = uploaded["url"].as_str().expect("url").to_owned();
    let path = format!("/media/{}", url.rsplit_once("/media/").expect("media").1);
    let r = call(&app, &path, &[], false).await;
    assert_eq!(
        r.status,
        axum::http::StatusCode::OK,
        "public: mail clients load it"
    );
    assert_eq!(r.headers["content-type"], "image/png");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    let base = data(&app, auth, "get_base_info", json!({"domain": "acme.test"})).await;
    assert_eq!(
        base["primary_logo"], url,
        "an uploaded logo is the project's logo"
    );
    let svg = format!(
        "data:image/svg+xml;base64,{}",
        base64_encode(b"<svg onload=alert(1)></svg>")
    );
    let r = post_json(
        &app,
        auth,
        "upload_image",
        json!({"domain": "acme.test", "image": svg, "filename": "x.svg", "alt_text": "x"}),
    )
    .await;
    assert_eq!(r.body["code"], 412, "{}", r.body);
    let images = data(&app, auth, "get_images", json!({"domain": "acme.test"})).await;
    let id = images
        .as_array()
        .expect("images")
        .iter()
        .find(|i| i["image_url"] == url)
        .and_then(|i| i["image_id"].as_str())
        .expect("uploaded")
        .to_owned();
    data(
        &app,
        auth,
        "remove_image",
        json!({"domain": "acme.test", "image_id": id}),
    )
    .await;
    let r = call(&app, &path, &[], false).await;
    assert_eq!(r.status, axum::http::StatusCode::NOT_FOUND);
    let r = call(&app, "/media/..%2F..%2F.env", &[], false).await;
    assert_eq!(r.status, axum::http::StatusCode::NOT_FOUND);

    data(
        &app,
        auth,
        "set_project_status",
        json!({"domain": "acme.test", "status": false}),
    )
    .await;
    let status = data(
        &app,
        auth,
        "get_project_status",
        json!({"domain": "acme.test"}),
    )
    .await;
    assert_eq!(status["status"], false);

    // --- Private addresses are refused --------------------------------------------------------
    let closed = h.app(&[]);
    data(
        &closed,
        auth,
        "create",
        json!({"domain": "closed.test", "urls": [format!("{site}/")]}),
    )
    .await;
    let base = wait_read(&closed, auth, "closed.test").await;
    assert_eq!(
        base["knowledge_base"],
        json!([]),
        "127.0.0.1 is not fetched; the project is marked read so the console stops waiting"
    );
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
