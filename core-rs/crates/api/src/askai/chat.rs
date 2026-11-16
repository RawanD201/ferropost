//! AskAI chats (Go: `askai/chat.go`, `askai/openai.go`): an AI model
//! designs an email template, streamed to the console as server-sent
//! events, in Go's files under `conf/chat/<id>/`.
//!
//! Differences from Go: the `http_request` tool fetches pages from this
//! server (public addresses only, see `fetch`) instead of BillionMail's
//! own service; a model may call it five times per answer (Go had no
//! limit); a chat answers one question at a time; token counts come from
//! the provider when it reports them (Go counted streamed chunks); chat ids
//! are checked before they become folder names (Go's `../` reached, and
//! removing a chat deleted, any folder); a provider error is shown in the
//! chat instead of a JSON body after the stream's headers.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use axum::body::{Body, Bytes};
use axum::http::header;
use axum::response::Response;
use ferropost_domain::askai::{
    ChatInfo, ChatMessage, ChatUsage, TempChat, extract_html, is_item_id, reference_block,
};
use md5::{Digest, Md5};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::openai::ChatModel;
use super::projects::{self, now};
use crate::state::AppState;

/// The system prompt (Go's `INITIAL_SYSTEM_PROMPT`, word for word).
pub const SYSTEM_PROMPT: &str = include_str!("email_prompt.txt");
const MAX_TOOL_ROUNDS: usize = 5;
const TOOL_PAGE_BYTES: usize = 2 * 1024 * 1024;
const TOOL_TEXT: usize = 20_000;
const TOOL: &str = "http_request";

static RUNNING: std::sync::Mutex<Vec<(String, Arc<AtomicBool>)>> =
    std::sync::Mutex::new(Vec::new());
static WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn root(state: &AppState) -> PathBuf {
    state.config.conf_dir.join("chat")
}

/// A chat's folder.
pub fn folder(state: &AppState, chat_id: &str) -> Result<PathBuf> {
    if !is_item_id(chat_id) {
        bail!("invalid chat id");
    }
    Ok(root(state).join(chat_id))
}

fn read<T: DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::fsio::write_atomic(path, &serde_json::to_vec(value)?, 0o644)
        .with_context(|| format!("write {}", path.display()))
}

pub fn temp(state: &AppState, chat_id: &str) -> Option<TempChat> {
    read(&folder(state, chat_id).ok()?.join("config.json"))
}

fn stored_info(state: &AppState, chat_id: &str) -> Option<ChatInfo> {
    read(&folder(state, chat_id).ok()?.join("info.json"))
}

pub fn messages(state: &AppState, chat_id: &str) -> Vec<ChatMessage> {
    folder(state, chat_id)
        .ok()
        .and_then(|dir| read(&dir.join("message.json")))
        .unwrap_or_default()
}

/// A chat with its messages (Go's `GetChatInfo`).
pub fn info(state: &AppState, chat_id: &str) -> Option<ChatInfo> {
    let mut info = stored_info(state, chat_id)?;
    info.messages = messages(state, chat_id);
    Some(info)
}

/// Every chat (Go's `GetChatList`), oldest first.
pub fn list(state: &AppState) -> Vec<TempChat> {
    let Ok(entries) = std::fs::read_dir(root(state)) else {
        return Vec::new();
    };
    let mut chats: Vec<TempChat> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| read(&e.path().join("config.json")))
        .collect();
    chats.sort_by(|a, b| {
        a.create_time
            .cmp(&b.create_time)
            .then(a.chat_id.cmp(&b.chat_id))
    });
    chats
}

/// A new chat (Go's `CreateChat`). Returns its id.
pub async fn create(state: &AppState, domain: &str, add_type: i64, title: &str) -> Result<String> {
    let id = uuid::Uuid::now_v7().to_string();
    let dir = folder(state, &id)?;
    let at = now();
    let _writes = WRITES.lock().await;
    write(
        &dir.join("config.json"),
        &TempChat {
            chat_id: id.clone(),
            domain: domain.to_owned(),
            add_type,
            temp_name: title.to_owned(),
            create_time: at,
            update_time: at,
            ..TempChat::default()
        },
    )?;
    write(
        &dir.join("info.json"),
        &ChatInfo {
            chat_id: id.clone(),
            domain: domain.to_owned(),
            title: title.to_owned(),
            create_time: at,
            update_time: at,
            ..ChatInfo::default()
        },
    )?;
    Ok(id)
}

pub async fn remove(state: &AppState, chat_id: &str) -> Result<bool> {
    let dir = folder(state, chat_id)?;
    stop(chat_id);
    let _writes = WRITES.lock().await;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).context("remove chat"),
    }
}

/// The chat's template HTML (Go's `GetHtml`): `code.html`, else the HTML
/// in its last answer.
pub fn html(state: &AppState, chat_id: &str) -> String {
    if let Ok(dir) = folder(state, chat_id)
        && let Ok(html) = std::fs::read_to_string(dir.join("code.html"))
    {
        return html;
    }
    messages(state, chat_id)
        .last()
        .and_then(|m| {
            if m.html_content.is_empty() {
                extract_html(&m.content)
            } else {
                Some(m.html_content.clone())
            }
        })
        .unwrap_or_default()
}

/// Saves the template HTML, in the chat and in the template made from it.
pub async fn set_html(state: &AppState, chat_id: &str, content: &str) -> Result<()> {
    let path = folder(state, chat_id)?.join("code.html");
    {
        let _writes = WRITES.lock().await;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::fsio::write_atomic(&path, content.as_bytes(), 0o644)?;
    }
    ferropost_store::templates::set_chat_content(
        &state.store.pg,
        chat_id,
        content,
        crate::routes::now(),
    )
    .await?;
    Ok(())
}

/// A copy of a chat for another template (Go's `CopyChat`). Returns the
/// new id and the HTML copied.
pub async fn copy(state: &AppState, chat_id: &str, domain: &str) -> Result<(String, String)> {
    let info = stored_info(state, chat_id).context("Chat not found")?;
    let id = create(state, domain, 99, &info.title).await?;
    {
        let _writes = WRITES.lock().await;
        let path = folder(state, &id)?.join("info.json");
        let mut copied: ChatInfo = read(&path).unwrap_or_default();
        copied.prompt = info.prompt;
        copied.supplier_name = info.supplier_name;
        copied.model_id = info.model_id;
        write(&path, &copied)?;
    }
    let code = std::fs::read_to_string(folder(state, chat_id)?.join("code.html")).ok();
    if let Some(code) = &code {
        let path = folder(state, &id)?.join("code.html");
        crate::fsio::write_atomic(&path, code.as_bytes(), 0o644)?;
    }
    Ok((id, code.unwrap_or_default()))
}

/// The token counts of the last answer.
pub fn last_usage(state: &AppState, chat_id: &str) -> ChatUsage {
    messages(state, chat_id)
        .last()
        .map(|m| m.usage)
        .unwrap_or_default()
}

/// Stops a running answer; `false` when none runs.
pub fn stop(chat_id: &str) -> bool {
    let running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    match running.iter().find(|(id, _)| id == chat_id) {
        Some((_, go_on)) => {
            go_on.store(false, Ordering::SeqCst);
            true
        }
        None => false,
    }
}

fn claim(chat_id: &str) -> Option<Arc<AtomicBool>> {
    let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    if running.iter().any(|(id, _)| id == chat_id) {
        return None;
    }
    let go_on = Arc::new(AtomicBool::new(true));
    running.push((chat_id.to_owned(), go_on.clone()));
    Some(go_on)
}

fn release(chat_id: &str) {
    RUNNING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(id, _)| id != chat_id);
}

/// What the model is told about the brand (Go's `GetSystemPrompt`).
pub fn system_prompt(state: &AppState, domain: &str) -> String {
    let mut added = format!(
        "Current time: {}\n\nThe following is reference information, segmented in the format \
         of<xxx-START>...<xxx-END>, which you can use as needed:\n\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    if ferropost_domain::domains::is_domain_name(domain) {
        if let Ok(c) = projects::company(state, domain) {
            added.push_str(&reference_block(
                "Company Profile",
                &[vec![
                    ("LegalCompanyName", c.legal_company_name),
                    ("WebSite", c.web_site),
                    ("CompanyProfile", c.company_profile),
                    ("Email", c.email),
                    ("Phone", c.phone),
                    ("SupportUrl", c.support_url),
                ]],
            ));
        }
        if let Some(p) = projects::project(state, domain) {
            added.push_str(&reference_block(
                "Project Config",
                &[vec![
                    ("ProjectName", p.project_name),
                    ("Description", p.description),
                    ("Industry", p.industry),
                    ("PrimaryLogo", p.primary_logo),
                    ("SecondaryLogo", p.secondary_logo),
                    ("Favicon", p.favicon),
                ]],
            ));
        }
        if let Ok(map) = projects::sitemap(state, domain) {
            let nodes: Vec<Vec<(&str, String)>> = map
                .into_iter()
                .map(|n| vec![("Title", n.title), ("UriPath", n.uri_path)])
                .collect();
            added.push_str(&reference_block("Sitemap", &nodes));
        }
        if let Ok(s) = projects::style(state, domain) {
            added.push_str(&reference_block(
                "Style Config",
                &[vec![
                    ("AccentColor", s.accent_color),
                    ("TextColor", s.text_color),
                    ("PageBackground", s.page_background),
                    ("ContainerBackground", s.container_background),
                    ("LinkSocialColor", s.link_social_color),
                    ("LinkFooterColor", s.link_footer_color),
                    ("HeadingFont", s.heading_font),
                    ("BodyFont", s.body_font),
                ]],
            ));
        }
        if let Ok(f) = projects::footer(state, domain) {
            added.push_str(&reference_block(
                "Footer",
                &[vec![
                    ("CopyrightText", f.copyright_text),
                    ("Disclaimer", f.disclaimer),
                ]],
            ));
        }
        let docs: Vec<Vec<(&str, String)>> = projects::knowledge(state, domain)
            .into_iter()
            .rev()
            .filter(|d| d.content.len() < 10_240)
            .map(|d| vec![("Content", d.content)])
            .collect();
        added.push_str(&reference_block("Knowledge Base", &docs));
        if let Ok(images) = projects::images(state, domain) {
            let shown: Vec<Vec<(&str, String)>> = images
                .into_iter()
                .take(51)
                .map(|i| {
                    vec![
                        ("ImageUrl", i.image_url),
                        ("AltText", i.alt_text),
                        ("Size", i.size),
                    ]
                })
                .collect();
            added.push_str(&reference_block("Images", &shown));
        }
    }
    format!("{SYSTEM_PROMPT}\n\n{added}")
}

/// The conversation sent to the model (Go's `GetMessages`): long earlier
/// answers shortened, the last one replaced by the current template.
pub fn conversation(
    system: &str,
    history: &[ChatMessage],
    html: &str,
    question: &str,
) -> Vec<Value> {
    let mut messages = vec![json!({"role": "system", "content": system})];
    for message in history {
        let mut content = message.content.as_str();
        if content.is_empty() || (message.role == "assistant" && content.len() > 512) {
            content = "...";
        }
        messages.push(json!({"role": message.role, "content": content}));
    }
    if messages.len() > 1
        && messages.last().is_some_and(|m| m["role"] == "assistant")
        && !html.is_empty()
        && let Some(last) = messages.last_mut()
    {
        last["content"] = json!(html);
    }
    if !question.trim().is_empty() {
        messages.push(json!({"role": "user", "content": question}));
    }
    messages
}

fn tool_definition() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": TOOL,
            "description": "Request and retrieve webpage content from a specified URL\n\t\tArgs:\n\t\t\turl: <string> url of the webpage to retrieve\n\t\tReturns:\n\t\t\tstring: json title and body of the webpage content.\n\t\t",
            "strict": true,
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "The URL of the webpage to retrieve"}},
                "required": ["url"],
                "additionalProperties": false,
            },
        },
    })
}

/// One event of the answer (Go's `ResultJson`).
#[derive(Serialize)]
struct Event<'a> {
    think_start: bool,
    think_end: bool,
    is_think: bool,
    content: &'a str,
    reasoning: &'a str,
    is_html: bool,
    role: &'static str,
    is_end: bool,
    update_time: i64,
}

/// Writes the answer to the console as it comes.
struct Output {
    tx: mpsc::Sender<Bytes>,
    chat_id: String,
    is_text: bool,
    content: String,
    reasoning: String,
    thinking: bool,
}

impl Output {
    async fn emit(&self, content: &str, reasoning: &str, flags: (bool, bool, bool), is_end: bool) {
        let bytes = if self.is_text {
            Bytes::from(
                if reasoning.is_empty() {
                    content
                } else {
                    reasoning
                }
                .to_owned(),
            )
        } else {
            let event = Event {
                think_start: flags.0,
                think_end: flags.1,
                is_think: flags.2,
                content,
                reasoning,
                is_html: self.content.matches("```").count() % 2 == 1,
                role: "assistant",
                is_end,
                update_time: now(),
            };
            Bytes::from(format!(
                "id: {}\ndata: {}\n\n",
                self.chat_id,
                serde_json::to_string(&event).unwrap_or_default()
            ))
        };
        if bytes.is_empty() {
            return;
        }
        // The answer is saved even if the console went away.
        let _ = self.tx.send(bytes).await;
    }

    async fn text(&mut self, text: &str) {
        if self.thinking {
            self.thinking = false;
            self.content.push('\n');
            self.emit("\n", "", (false, true, false), false).await;
        }
        self.content.push_str(text);
        self.emit(text, "", (false, false, false), false).await;
    }

    async fn reasoning(&mut self, text: &str) {
        let start = !self.thinking;
        self.thinking = true;
        self.reasoning.push_str(text);
        self.emit("", text, (start, false, true), false).await;
    }

    async fn end(&self) {
        self.emit("", "", (false, false, false), true).await;
    }
}

/// A tool call being streamed.
#[derive(Debug, Default, Clone)]
struct ToolCall {
    id: String,
    name: String,
    arguments: String,
}

#[derive(Debug, Default)]
struct Round {
    calls: Vec<ToolCall>,
    finish_reason: String,
    usage: Option<ChatUsage>,
}

fn usage_of(value: &Value) -> Option<ChatUsage> {
    let usage = value.get("usage")?;
    let n = |k: &str| usage.get(k).and_then(Value::as_i64);
    Some(ChatUsage {
        prompt_tokens: n("prompt_tokens")?,
        completion_tokens: n("completion_tokens").unwrap_or(0),
        total_tokens: n("total_tokens").unwrap_or(0),
    })
}

async fn send_request(model: &ChatModel, body: &Value) -> Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(180))
        .build()?;
    client
        .post(model.endpoint())
        .bearer_auth(&model.api_key)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(serde_json::to_vec(body)?)
        .send()
        .await
        .context("the AI provider did not answer")
}

/// One streamed request; tool calls are returned, not run.
async fn stream_round(
    model: &ChatModel,
    messages: &[Value],
    tools: bool,
    go_on: &AtomicBool,
    out: &mut Output,
) -> Result<Round> {
    let mut body = json!({
        "model": model.model_id,
        "max_completion_tokens": model.max_tokens,
        "messages": messages,
        "temperature": 0.6,
        "stream": true,
        "stream_options": {"include_usage": true},
    });
    if tools {
        body["tools"] = json!([tool_definition()]);
    }
    let mut response = send_request(model, &body).await?;
    if response.status() == reqwest::StatusCode::BAD_REQUEST {
        // Providers that do not know `stream_options` refuse the request.
        let text = response.text().await.unwrap_or_default();
        if !text.contains("stream_options") {
            bail!(
                "the AI provider answered 400: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        if let Some(map) = body.as_object_mut() {
            map.remove("stream_options");
        }
        response = send_request(model, &body).await?;
    }
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        bail!(
            "the AI provider answered {status}: {}",
            text.chars().take(300).collect::<String>()
        );
    }
    let mut round = Round::default();
    let mut pending = Vec::new();
    'stream: while let Some(chunk) = response.chunk().await? {
        pending.extend_from_slice(&chunk);
        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            let Some(data) = line.trim().strip_prefix("data:").map(str::trim) else {
                continue;
            };
            if data == "[DONE]" {
                break 'stream;
            }
            let Ok(event) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if let Some(usage) = usage_of(&event) {
                round.usage = Some(usage);
            }
            let choice = &event["choices"][0];
            if let Some(reason) = choice["finish_reason"].as_str() {
                round.finish_reason = reason.to_owned();
            }
            let delta = &choice["delta"];
            if let Some(calls) = delta["tool_calls"].as_array() {
                for (position, call) in calls.iter().enumerate() {
                    let index = call["index"]
                        .as_u64()
                        .map_or(position, |i| usize::try_from(i).unwrap_or(position));
                    if round.calls.len() <= index {
                        round.calls.resize(index + 1, ToolCall::default());
                    }
                    let entry = &mut round.calls[index];
                    if let Some(id) = call["id"].as_str().filter(|i| !i.is_empty()) {
                        entry.id = id.to_owned();
                    }
                    if let Some(name) = call["function"]["name"].as_str().filter(|n| !n.is_empty())
                    {
                        entry.name = name.to_owned();
                    }
                    if let Some(args) = call["function"]["arguments"].as_str() {
                        entry.arguments.push_str(args);
                    }
                }
            }
            if let Some(reasoning) = delta["reasoning_content"]
                .as_str()
                .filter(|r| !r.is_empty())
            {
                out.reasoning(reasoning).await;
            }
            if let Some(text) = delta["content"].as_str().filter(|t| !t.is_empty()) {
                out.text(text).await;
            }
            if !go_on.load(Ordering::SeqCst) {
                round.finish_reason = "stop".to_owned();
                round.calls.clear();
                break 'stream;
            }
        }
    }
    round.calls.retain(|c| !c.name.is_empty());
    Ok(round)
}

/// The `http_request` tool: a page's text, fetched from here (cached in
/// the chat's `temp/`, as Go cached the bot's answers).
async fn http_request(state: &AppState, chat_id: &str, url: &str) -> String {
    let cache = folder(state, chat_id).ok().map(|dir| {
        dir.join("temp")
            .join(hex::encode(Md5::digest(url.as_bytes())))
    });
    if let Some(cache) = &cache
        && let Ok(cached) = std::fs::read_to_string(cache)
        && cached.len() > 100
    {
        return cached;
    }
    let answer = match super::fetch::get(state, url, TOOL_PAGE_BYTES).await {
        Ok(page) => {
            let read = super::crawl::extract(&page.text(), &page.url);
            json!({
                "url": page.url.as_str(),
                "title": read.title,
                "description": read.description,
                "content": read.markdown.chars().take(TOOL_TEXT).collect::<String>(),
            })
            .to_string()
        }
        Err(err) => return json!({"url": url, "error": format!("{err:#}")}).to_string(),
    };
    if let Some(cache) = cache
        && let Some(dir) = cache.parent()
        && std::fs::create_dir_all(dir).is_ok()
    {
        let _ = crate::fsio::write_atomic(&cache, answer.as_bytes(), 0o600);
    }
    answer
}

/// A question for a chat's model.
pub struct Ask {
    pub chat_id: String,
    pub model: ChatModel,
    pub question: String,
    pub is_text: bool,
}

/// Answers in the background, streaming to the console; `None` when the
/// chat is already answering.
pub fn respond(state: &AppState, ask: Ask) -> Option<Response> {
    let go_on = claim(&ask.chat_id)?;
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let state = state.clone();
    tokio::spawn(async move {
        run(&state, &ask, tx, &go_on).await;
        release(&ask.chat_id);
    });
    let body = Body::from_stream(futures_util::stream::poll_fn(move |cx| {
        rx.poll_recv(cx).map(|item| item.map(Ok::<_, Infallible>))
    }));
    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(body)
        .ok()
}

async fn run(state: &AppState, ask: &Ask, tx: mpsc::Sender<Bytes>, go_on: &AtomicBool) {
    let asked_at = now();
    let domain = temp(state, &ask.chat_id)
        .map(|t| t.domain)
        .unwrap_or_default();
    let history = messages(state, &ask.chat_id);
    let mut messages = conversation(
        &system_prompt(state, &domain),
        &history,
        &html(state, &ask.chat_id),
        &ask.question,
    );
    let prompt_chars: usize = messages
        .iter()
        .map(|m| m["content"].as_str().map_or(0, str::len))
        .sum();
    let mut out = Output {
        tx,
        chat_id: ask.chat_id.clone(),
        is_text: ask.is_text,
        content: String::new(),
        reasoning: String::new(),
        thinking: false,
    };
    let mut usage: Option<ChatUsage> = None;
    let mut finish_reason = String::new();
    let mut failed = false;
    for round in 0..=MAX_TOOL_ROUNDS {
        let result = stream_round(
            &ask.model,
            &messages,
            round < MAX_TOOL_ROUNDS,
            go_on,
            &mut out,
        )
        .await;
        let round_result = match result {
            Ok(r) => r,
            Err(err) => {
                failed = out.content.is_empty();
                out.text(&format!("\n\nError: {err:#}")).await;
                finish_reason = "error".to_owned();
                break;
            }
        };
        if let Some(u) = round_result.usage {
            let total = usage.get_or_insert_with(ChatUsage::default);
            total.prompt_tokens += u.prompt_tokens;
            total.completion_tokens += u.completion_tokens;
            total.total_tokens += u.total_tokens;
        }
        finish_reason = round_result.finish_reason;
        if round_result.calls.is_empty() {
            break;
        }
        messages.push(json!({
            "role": "assistant",
            "content": Value::Null,
            "tool_calls": round_result.calls.iter().map(|c| json!({
                "id": c.id, "type": "function",
                "function": {"name": c.name, "arguments": c.arguments},
            })).collect::<Vec<_>>(),
        }));
        for call in round_result.calls {
            let reply = if call.name == TOOL {
                let url = serde_json::from_str::<Value>(&call.arguments)
                    .ok()
                    .and_then(|a| a["url"].as_str().map(str::to_owned))
                    .unwrap_or_default();
                out.text(&format!("\n\n<tool>Requesting URL: {url}")).await;
                let page = http_request(state, &ask.chat_id, &url).await;
                out.text(" complete</tool>\n\n").await;
                page
            } else {
                json!({"error": format!("unknown tool {}", call.name)}).to_string()
            };
            messages.push(json!({"role": "tool", "tool_call_id": call.id, "content": reply}));
        }
    }

    if !failed
        && let Err(err) = save_answer(
            state,
            ask,
            &out,
            asked_at,
            prompt_chars,
            usage,
            &finish_reason,
        )
        .await
    {
        tracing::warn!(chat = %ask.chat_id, error = %format!("{err:#}"), "AI answer not saved");
    }
    out.end().await;
}

async fn save_answer(
    state: &AppState,
    ask: &Ask,
    out: &Output,
    asked_at: i64,
    prompt_chars: usize,
    usage: Option<ChatUsage>,
    finish_reason: &str,
) -> Result<()> {
    let html = extract_html(&out.content).unwrap_or_default();
    if !html.is_empty() {
        set_html(state, &ask.chat_id, &html).await?;
    }
    let usage = usage.unwrap_or_else(|| {
        let prompt = i64::try_from(prompt_chars / 4).unwrap_or(i64::MAX);
        let completion = i64::try_from(out.content.len() / 4).unwrap_or(i64::MAX);
        ChatUsage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
        }
    });
    let ended = now();
    let question_id = uuid::Uuid::now_v7().to_string();
    let question = ChatMessage {
        message_id: question_id.clone(),
        chat_id: ask.chat_id.clone(),
        role: "user".to_owned(),
        content: ask.question.clone(),
        create_time: asked_at,
        end_time: ended,
        supplier_name: ask.model.supplier.clone(),
        model_id: ask.model.model_id.clone(),
        time_consuming: ended - asked_at,
        ..ChatMessage::default()
    };
    let answer = ChatMessage {
        message_id: uuid::Uuid::now_v7().to_string(),
        chat_id: ask.chat_id.clone(),
        ppid: question_id,
        content: out.content.clone(),
        html_content: html,
        role: "assistant".to_owned(),
        create_time: asked_at,
        end_time: ended,
        reasoning: out.reasoning.clone(),
        supplier_name: ask.model.supplier.clone(),
        model_id: ask.model.model_id.clone(),
        finish_reason: finish_reason.to_owned(),
        usage,
        time_consuming: ended - asked_at,
    };
    let path = folder(state, &ask.chat_id)?.join("message.json");
    let _writes = WRITES.lock().await;
    let mut all: Vec<ChatMessage> = read(&path).unwrap_or_default();
    all.push(question);
    all.push(answer);
    write(&path, &all)
}

/// Remembers the model a chat uses (Go saved it before answering).
pub async fn use_model(state: &AppState, chat_id: &str, model: &ChatModel) -> Result<()> {
    let path = folder(state, chat_id)?.join("info.json");
    let _writes = WRITES.lock().await;
    let mut info: ChatInfo = read(&path).ok_or_else(|| anyhow!("Chat not found"))?;
    info.supplier_name = model.supplier.clone();
    info.model_id = model.model_id.clone();
    info.update_time = now();
    write(&path, &info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_follows_go() {
        let history = vec![
            ChatMessage {
                role: "user".to_owned(),
                content: "Make a newsletter".to_owned(),
                ..ChatMessage::default()
            },
            ChatMessage {
                role: "assistant".to_owned(),
                content: "x".repeat(600),
                ..ChatMessage::default()
            },
        ];
        let messages = conversation("SYS", &history, "<html>now</html>", "Make it blue");
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(
            messages[2]["content"], "<html>now</html>",
            "the current template"
        );
        assert_eq!(
            messages[3],
            json!({"role": "user", "content": "Make it blue"})
        );
        let without = conversation("SYS", &history, "", "again");
        assert_eq!(without[2]["content"], "...", "long answers are shortened");
        assert!(SYSTEM_PROMPT.starts_with("You are a seasoned marketing email expert"));
        assert!(SYSTEM_PROMPT.contains("{{ UnsubscribeURL . }}"));
    }
}
