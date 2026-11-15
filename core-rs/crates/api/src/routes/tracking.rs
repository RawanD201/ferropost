//! `/pmta/<token>`: open pixels and click redirects in sent mail (Go:
//! `maillog_stat.CampaignEventHandler`). Public: recipients have no session.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use ferropost_domain::tracking::{EventKind, PIXEL_PNG, TokenError, decode_legacy};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/pmta/{*token}", any(track))
}

async fn track(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let event = match decode_legacy(&token) {
        Ok(event) => event,
        Err(TokenError::Malformed) => return text("Invalid -1"),
        Err(TokenError::Invalid) => return text("Invalid -2"),
    };

    let now = chrono::Utc::now().timestamp_millis();
    let known = match ferropost_store::tracking::record(&state.store.pg, &event, now).await {
        Ok(known) => known,
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "tracking event not stored");
            false
        }
    };

    match event.kind {
        // The pixel is always served so mail clients show no broken image.
        EventKind::Open => pixel(),
        EventKind::Click if known => redirect(&event.url),
        // Unknown message: likely a forged token. Go redirected anywhere.
        EventKind::Click => text("Invalid -3"),
    }
}

fn text(body: &'static str) -> Response {
    (StatusCode::OK, body).into_response()
}

fn pixel() -> Response {
    (
        [
            (CONTENT_TYPE, HeaderValue::from_static("image/png")),
            (
                CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache, must-revalidate"),
            ),
        ],
        PIXEL_PNG,
    )
        .into_response()
}

fn redirect(url: &str) -> Response {
    match HeaderValue::from_str(url) {
        Ok(location) => (StatusCode::FOUND, [(LOCATION, location)]).into_response(),
        Err(_) => text("Invalid -2"),
    }
}
