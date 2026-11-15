//! The JSON envelope every API response uses.
//!
//! The frontend treats `success: true, code: 0` as success and `code: 401` as
//! "log in again". Errors are sent with HTTP 200, exactly like the Go server;
//! the axios interceptor only inspects the body.

use axum::Json;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub code: i32,
    pub msg: String,
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(msg: impl Into<String>, data: T) -> Self {
        Self {
            success: true,
            code: 0,
            msg: msg.into(),
            data,
        }
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Missing or invalid credentials. An empty message makes the frontend
    /// redirect to the login page without showing a toast.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("insufficient permissions")]
    Forbidden,
    #[error("not found: {0}")]
    NotFound(String),
    /// Invalid input (Go answered validation failures with code 412).
    #[error("validation: {0}")]
    Validation(String),
    /// A dependency (database, Redis, Go core) is unreachable.
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    pub fn code(&self) -> i32 {
        match self {
            Self::Unauthorized(_) => 401,
            Self::Forbidden => 403,
            Self::NotFound(_) => 404,
            Self::Validation(_) => 412,
            Self::Unavailable(_) => 503,
            Self::Internal(_) => 500,
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::Unauthorized(msg) | Self::NotFound(msg) | Self::Validation(msg) => msg.clone(),
            Self::Forbidden => "Insufficient permissions".to_owned(),
            Self::Unavailable(_) => "Service temporarily unavailable".to_owned(),
            // Go returned raw error strings (SQL errors included). Details are
            // logged instead of sent to the browser.
            Self::Internal(_) => "Internal server error".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match &self {
            Self::Internal(err) => tracing::error!(error = %format!("{err:#}"), "request failed"),
            Self::Unavailable(what) => tracing::warn!(%what, "dependency unavailable"),
            _ => {}
        }
        ApiResponse {
            success: false,
            code: self.code(),
            msg: self.public_message(),
            data: (),
        }
        .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn success_envelope_matches_go() {
        let response = ApiResponse::ok("done", serde_json::json!({"total": 0})).into_response();
        assert_eq!(response.status(), 200);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"success": true, "code": 0, "msg": "done", "data": {"total": 0}})
        );
    }

    #[tokio::test]
    async fn errors_use_http_200_and_hide_internals() {
        let response =
            ApiError::Internal(anyhow::anyhow!("relation \"x\" does not exist")).into_response();
        assert_eq!(response.status(), 200);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"success": false, "code": 500, "msg": "Internal server error", "data": null})
        );
    }

    #[tokio::test]
    async fn unauthorized_keeps_message() {
        let body =
            body_json(ApiError::Unauthorized("no authorization".into()).into_response()).await;
        assert_eq!(body["code"], 401);
        assert_eq!(body["msg"], "no authorization");
    }
}
