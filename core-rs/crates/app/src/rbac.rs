//! Permission checks for authenticated API routes.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use ferropost_domain::rbac::route_info;

use crate::auth::CurrentUser;
use crate::envelope::ApiError;
use crate::state::AppState;

/// Route layer that runs after [`crate::auth::require_auth`]. The required
/// permission is derived from the path exactly as Go does, so permissions
/// stored in the database keep their meaning.
pub async fn require_permission(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let user = req
        .extensions()
        .get::<CurrentUser>()
        .cloned()
        .ok_or_else(|| ApiError::Unauthorized(String::new()))?;

    if user.is_admin() {
        return Ok(next.run(req).await);
    }

    let route = route_info(req.uri().path());
    if !route.is_complete() {
        tracing::warn!(
            path = req.uri().path(),
            "no permission mapping for path; denying"
        );
        return Err(ApiError::Forbidden);
    }

    let granted = state
        .caches
        .permissions
        .try_get_with((user.account_id, route.clone()), async {
            ferropost_store::rbac::has_permission(&state.store.pg, user.account_id, &route).await
        })
        .await
        .map_err(|e| anyhow::anyhow!("permission check: {e:#}"))?;

    if granted {
        Ok(next.run(req).await)
    } else {
        Err(ApiError::Forbidden)
    }
}
