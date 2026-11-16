//! `/api/languages/*` (Go: `controller/languages`): the console language.
//!
//! `get` stays public (the login page reads it); `set` now needs a login:
//! Go let anyone change the language of the whole console.

use axum::Router;
use axum::extract::State;
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use serde::{Deserialize, Serialize};

use crate::audit::Audit;
use crate::body::ApiBody;
use crate::de::opt_string;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;
use crate::validate;

pub fn public_routes() -> Router<AppState> {
    Router::new().route("/api/languages/get", get(get_languages))
}

/// Needs a login but no permission (as in Go, any role may switch).
pub fn signed_in_routes() -> Router<AppState> {
    Router::new().route("/api/languages/set", post(set_language))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Language {
    name: String,
    #[serde(default)]
    google: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    cn: String,
}

#[derive(Deserialize)]
struct Settings {
    languages: Vec<Language>,
}

/// `languages/settings.json`, or Go's built-in list.
fn available(state: &AppState) -> Vec<Language> {
    std::fs::read_to_string(state.config.root.join("languages/settings.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Settings>(&raw).ok())
        .map(|s| s.languages)
        .unwrap_or_else(|| {
            [
                ("zh", "zh-cn", "简体中文", "简体中文"),
                ("en", "en", "English", "English"),
            ]
            .into_iter()
            .map(|(name, google, title, cn)| Language {
                name: name.into(),
                google: google.into(),
                title: title.into(),
                cn: cn.into(),
            })
            .collect()
        })
}

#[derive(Serialize)]
struct Languages {
    current_language: String,
    available_languages: Vec<Language>,
}

async fn get_languages(
    State(state): State<AppState>,
    Lang(lang): Lang,
) -> Result<ApiResponse<Languages>, ApiError> {
    let current =
        ferropost_store::options::get(&state.store.pg, ferropost_store::options::CURRENT_LANGUAGE)
            .await?
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| lang.clone());
    Ok(ApiResponse::ok(
        state
            .i18n
            .tr(&lang, "Language information retrieved successfully", &[]),
        Languages {
            current_language: current,
            available_languages: available(&state),
        },
    ))
}

#[derive(Debug, Deserialize)]
struct SetBody {
    #[serde(default, deserialize_with = "opt_string")]
    language: Option<String>,
}

async fn set_language(
    State(state): State<AppState>,
    Lang(lang): Lang,
    audit: Audit,
    ApiBody(body): ApiBody<SetBody>,
) -> Result<ApiResponse<()>, ApiError> {
    let language = validate::required("language", &body.language)?.to_owned();
    if !available(&state).iter().any(|l| l.name == language) {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Invalid language code: {}",
            &[&language],
        )));
    }
    ferropost_store::options::set(
        &state.store.pg,
        ferropost_store::options::CURRENT_LANGUAGE,
        &language,
    )
    .await?;
    state.caches.default_language.invalidate_all();
    audit
        .record(
            LogType::Language,
            &format!("Language changed to: {language} "),
        )
        .await;
    Ok(ApiResponse::ok(
        state.i18n.tr(&language, "Setup successful", &[]),
        (),
    ))
}
