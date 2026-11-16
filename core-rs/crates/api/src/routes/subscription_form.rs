//! `/subscription/form` (Go: `controller/campaign`): a hosted page to
//! subscribe to the listed groups, outside `/api` and without a login.
//!
//! Differences from Go: subscribing goes through each group's own rules
//! (double opt-in, confirmation and welcome mails, the confirmation rate
//! limit) where Go added the address as active everywhere and sent a
//! "subscription confirmed" mail with the visitor's name pasted into the
//! HTML; every value on the pages is HTML-escaped (Go's templates did not
//! escape group names or the address); the form token is signed and
//! expires instead of living in a server session.

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use ferropost_domain::contacts::is_valid_email;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use super::subscriptions::join_group;
use crate::envelope::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/subscription/form", get(form).post(submit))
}

/// How long a form may be filled in.
const TOKEN_TTL_SECS: i64 = 2 * 3600;

fn mac(state: &AppState, issued: i64) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(state.config.jwt_secret.as_bytes()).expect("any key length");
    mac.update(format!("ferropost:subscription-form:{issued}").as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}

fn issue_token(state: &AppState, now: i64) -> String {
    format!("{now}.{}", mac(state, now))
}

fn token_valid(state: &AppState, token: &str, now: i64) -> bool {
    let Some((issued, sig)) = token.split_once('.') else {
        return false;
    };
    let Ok(issued) = issued.parse::<i64>() else {
        return false;
    };
    let expected = mac(state, issued);
    let fresh = issued <= now && now - issued <= TOKEN_TTL_SECS;
    fresh
        && expected.len() == sig.len()
        && expected
            .bytes()
            .zip(sig.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(state: &AppState, file: &str, data: &serde_json::Value) -> Result<Response, ApiError> {
    let template = std::fs::read_to_string(state.config.template_dir.join(file))
        .map_err(|e| anyhow::anyhow!("{file}: {e}"))?;
    let html = ferropost_sender::template::render_value(&template, data)
        .map_err(|e| anyhow::anyhow!("{file}: {e}"))?;
    Ok(Html(html).into_response())
}

fn plain(status: StatusCode, text: &str) -> Response {
    (
        status,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        text.to_owned(),
    )
        .into_response()
}

async fn form(State(state): State<AppState>) -> Result<Response, ApiError> {
    let groups = ferropost_store::groups::all(&state.store.pg, None).await?;
    let data = json!({
        "Groups": groups.iter().map(|g| json!({"Id": g.id, "Name": escape(&g.name)})).collect::<Vec<_>>(),
        "CSRFToken": issue_token(&state, chrono::Utc::now().timestamp()),
    });
    page(&state, "subscription_form.html", &data)
}

/// `application/x-www-form-urlencoded` with repeated `group_ids` (what the
/// page's checkboxes post), which serde's form decoding cannot express.
fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi << 4 | lo);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                },
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(k), decode(v))
        })
        .collect()
}

async fn submit(State(state): State<AppState>, body: Bytes) -> Result<Response, ApiError> {
    let fields = form_fields(&body);
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.trim().to_owned())
            .unwrap_or_default()
    };
    let now = chrono::Utc::now().timestamp();
    let token = field("token");
    if token.is_empty() {
        return Ok(plain(StatusCode::BAD_REQUEST, "CSRF token not provided"));
    }
    if !token_valid(&state, &token, now) {
        return Ok(plain(StatusCode::BAD_REQUEST, "CSRF token not valid"));
    }
    let email = field("email").to_ascii_lowercase();
    if !is_valid_email(&email) {
        return Ok(plain(StatusCode::BAD_REQUEST, "Invalid email format"));
    }
    let name = field("name");
    let mut group_ids: Vec<i32> = fields
        .iter()
        .filter(|(k, _)| k == "group_ids" || k == "group_ids[]")
        .filter_map(|(_, v)| v.trim().parse().ok())
        .collect();
    group_ids.sort_unstable();
    group_ids.dedup();

    let host = crate::base_url::global(&state).await;
    let attribs = json!({"Username": name});
    for id in group_ids {
        if let Some(group) = ferropost_store::groups::get(&state.store.pg, id).await? {
            join_group(&state, &group, &email, attribs.clone(), &host).await?;
        }
    }
    page(
        &state,
        "subscription_success.html",
        &json!({"EmailAddress": escape(&email)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_form_fields() {
        let fields = form_fields(
            "email=a%40x.com&group_ids=1&group_ids=2&name=Ann+Lee&bad=%zz&u=%ü1".as_bytes(),
        );
        assert_eq!(fields[0], ("email".into(), "a@x.com".into()));
        assert_eq!(fields.iter().filter(|(k, _)| k == "group_ids").count(), 2);
        assert_eq!(fields[3], ("name".into(), "Ann Lee".into()));
        assert_eq!(fields[4], ("bad".into(), "%zz".into()));
        assert_eq!(
            fields[5],
            ("u".into(), "%ü1".into()),
            "no panic on non-ASCII after %"
        );
        assert_eq!(
            escape("<b>\"x\" & 'y'</b>"),
            "&lt;b&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/b&gt;"
        );
    }
}
