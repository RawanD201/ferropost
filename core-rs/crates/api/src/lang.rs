//! Language used for server messages.

use axum::extract::FromRequestParts;
use axum::http::header::ACCEPT_LANGUAGE;
use axum::http::request::Parts;
use bm_common::i18n::{DEFAULT_LANGUAGE, normalize_language};

use crate::state::AppState;

/// Resolved language of the current request.
///
/// Order: `?lang=`, the console default (`bm_options.CurrentLanguage`), the
/// browser's `Accept-Language` when a pack exists, then English. Go also
/// consulted its server-side session and *wrote* the browser language to the
/// database on reads; neither is reproduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lang(pub String);

impl FromRequestParts<AppState> for Lang {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(lang) = query_lang(parts.uri.query()) {
            return Ok(Self(lang));
        }

        let configured = state
            .caches
            .default_language
            .try_get_with((), async {
                bm_store::options::get(&state.store.pg, bm_store::options::CURRENT_LANGUAGE)
                    .await
                    .map(|v| v.as_deref().and_then(normalize_language))
            })
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %format!("{e:#}"), "read default language");
                None
            });
        if let Some(lang) = configured {
            return Ok(Self(lang));
        }

        let browser = parts
            .headers
            .get(ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .and_then(normalize_language)
            .filter(|lang| state.i18n.supports(lang));
        Ok(Self(browser.unwrap_or_else(|| DEFAULT_LANGUAGE.to_owned())))
    }
}

fn query_lang(query: Option<&str>) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "lang")
        .and_then(|(_, value)| normalize_language(value))
}

#[cfg(test)]
mod tests {
    use super::query_lang;

    #[test]
    fn reads_lang_parameter() {
        assert_eq!(query_lang(Some("page=1&lang=zh-CN")).as_deref(), Some("zh"));
        assert_eq!(query_lang(Some("lang=")), None);
        assert_eq!(query_lang(Some("language=ja")), None);
        assert_eq!(query_lang(None), None);
    }
}
