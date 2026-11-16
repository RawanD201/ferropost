//! Calls to OpenAI-compatible chat APIs (Go used `go-openai`).

use std::time::Duration;

use anyhow::{Context, Result, bail};
use ferropost_domain::askai::{self as rules, ModelInfo};
use serde_json::{Value, json};

use crate::state::AppState;

/// A model ready to be called: its provider's address and key.
#[derive(Debug, Clone)]
pub struct ChatModel {
    pub supplier: String,
    pub model_id: String,
    pub base_url: String,
    pub api_key: String,
    pub max_tokens: i64,
}

impl ChatModel {
    /// A provider's model, when both are switched on.
    pub fn of(state: &AppState, supplier: &str, model_id: &str) -> Option<Self> {
        let config = super::suppliers::config(state, supplier)?;
        if !config.is_active() {
            return None;
        }
        let model = super::suppliers::model(state, supplier, model_id)?;
        Some(Self::from_parts(&config, &model))
    }

    fn from_parts(config: &rules::Supplier, model: &ModelInfo) -> Self {
        Self {
            supplier: config.supplier_name.clone(),
            model_id: model.model_id.clone(),
            base_url: config.base_url.clone(),
            api_key: config.api_key.clone(),
            max_tokens: model.max_tokens,
        }
    }

    /// The first usable text model, for work no user picked a model for.
    pub async fn any(state: &AppState) -> Option<Self> {
        let models = super::suppliers::models(state, None).await;
        let model = models
            .iter()
            .find(|m| m.capability.iter().any(|c| c == "llm"))
            .or_else(|| models.first())?;
        Self::of(state, &model.supplier_name, &model.model_id)
    }

    pub fn endpoint(&self) -> String {
        rules::endpoint(&self.base_url, "chat/completions")
    }
}

/// One answer, without streaming.
pub async fn complete(model: &ChatModel, messages: &[Value], max_tokens: i64) -> Result<String> {
    let body = json!({
        "model": model.model_id,
        "messages": messages,
        "max_completion_tokens": max_tokens.min(model.max_tokens).max(1),
        "temperature": 0.2,
        "stream": false,
    });
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?
        .post(model.endpoint())
        .bearer_auth(&model.api_key)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body)?)
        .send()
        .await
        .context("the AI provider did not answer")?;
    let status = response.status();
    let raw = response.bytes().await?;
    if !status.is_success() {
        bail!(
            "the AI provider answered {status}: {}",
            String::from_utf8_lossy(&raw)
                .chars()
                .take(300)
                .collect::<String>()
        );
    }
    let answer: Value = serde_json::from_slice(&raw).context("the AI provider's answer")?;
    answer["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_owned)
        .context("the AI provider's answer has no content")
}

/// The JSON object in a model's answer (which may wrap it in a code fence
/// or text).
pub fn json_in(answer: &str) -> Option<Value> {
    let start = answer.find('{')?;
    let end = answer.rfind('}')?;
    (end > start)
        .then(|| serde_json::from_str(&answer[start..=end]).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_in_answers() {
        assert_eq!(json_in("```json\n{\"a\": 1}\n```"), Some(json!({"a": 1})));
        assert_eq!(
            json_in("Here: {\"a\": {\"b\": 2}} done"),
            Some(json!({"a": {"b": 2}}))
        );
        assert_eq!(json_in("no json"), None);
    }
}
