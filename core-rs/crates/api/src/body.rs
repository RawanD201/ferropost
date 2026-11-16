//! Request bodies for write endpoints.

use axum::Form;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;

use crate::envelope::ApiError;

/// JSON body (what the console sends) or form-encoded body (what GoFrame
/// also accepted). Decoding failures become a 412 envelope. An empty body
/// decodes as `{}`, so request types should default every field and leave
/// "required" checks to [`crate::validate`], which gives readable messages.
pub struct ApiBody<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiBody<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let is_form = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));

        if is_form {
            let Form(value) = Form::<T>::from_request(req, state)
                .await
                .map_err(|e| ApiError::Validation(e.body_text()))?;
            return Ok(Self(value));
        }

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| ApiError::Validation(e.body_text()))?;
        let raw: &[u8] = if bytes.iter().all(u8::is_ascii_whitespace) {
            b"{}"
        } else {
            &bytes
        };
        serde_json::from_slice(raw)
            .map(Self)
            .map_err(|e| ApiError::Validation(format!("Invalid request body: {e}")))
    }
}

/// The query string of a `GET`, else the body: for routes Go served on
/// both methods.
pub struct Input<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Input<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        if req.method() == axum::http::Method::GET || req.method() == axum::http::Method::HEAD {
            let axum::extract::Query(value) = axum::extract::Query::<T>::try_from_uri(req.uri())
                .map_err(|e| ApiError::Validation(e.body_text()))?;
            return Ok(Self(value));
        }
        ApiBody::<T>::from_request(req, state)
            .await
            .map(|ApiBody(value)| Self(value))
    }
}
