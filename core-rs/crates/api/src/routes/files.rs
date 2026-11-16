//! `/api/file/*` (Go: `controller/files`). Go declared reading and
//! downloading files by path but never implemented them; they stay
//! unimplemented here, natively, so no arbitrary path ever reaches a file
//! read through the proxy either.

use axum::Router;
use axum::routing::get;

use crate::envelope::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/file/download", get(not_implemented))
        .route("/api/file/read", get(not_implemented))
}

async fn not_implemented() -> ApiError {
    ApiError::Coded(501, "Not yet achieved".to_owned())
}
