//! Operation log for write endpoints, compatible with Go's `public.WriteLog`.
//!
//! Each entry is a `bm_operation_logs` row. When there is request data to
//! keep, it is written as a pretty-printed JSON snapshot under
//! `<root>/../logs/core/operation_log/<date>/` and the row points at it.
//! Failures are logged and never fail the request, as in Go.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::Local;
use ferropost_domain::audit::LogType;
use serde::Serialize;

use crate::auth::CurrentUser;
use crate::conn::ClientIp;
use crate::state::AppState;

/// Handle for recording what the current user did.
#[derive(Clone)]
pub struct Audit {
    state: AppState,
    user_id: i64,
    ip: IpAddr,
}

impl FromRequestParts<AppState> for Audit {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            state: state.clone(),
            user_id: parts
                .extensions
                .get::<CurrentUser>()
                .map_or(0, |u| u.account_id),
            ip: parts
                .extensions
                .get::<ClientIp>()
                .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0),
        })
    }
}

impl Audit {
    /// Records an entry with no snapshot.
    pub async fn record(&self, log_type: LogType, log: &str) {
        self.write(log_type, log, None).await;
    }

    /// Records an entry and keeps `data` as a JSON snapshot. Pass the
    /// request payload, never credentials: unlike Go, the `Authorization`
    /// header is not part of the snapshot.
    pub async fn record_with<T: Serialize>(&self, log_type: LogType, log: &str, data: &T) {
        let data = serde_json::to_value(data).ok();
        self.write(log_type, log, data).await;
    }

    async fn write(&self, log_type: LogType, log: &str, data: Option<serde_json::Value>) {
        let info = match data {
            Some(value) => self.snapshot(log_type, &value).await.unwrap_or_default(),
            None => String::new(),
        };
        let ip = self.ip.to_string();
        let entry = ferropost_store::audit::NewEntry {
            user_id: self.user_id,
            log_type: log_type.as_str(),
            log,
            ip: &ip,
            info: &info,
            addtime: chrono::Utc::now().timestamp(),
        };
        if let Err(err) = ferropost_store::audit::insert(&self.state.store.pg, &entry).await {
            tracing::warn!(error = %format!("{err:#}"), "operation log not written");
        }
    }

    async fn snapshot(&self, log_type: LogType, value: &serde_json::Value) -> Option<String> {
        let now = Local::now();
        let dir: PathBuf = self
            .state
            .config
            .root
            .join("../logs/core/operation_log")
            .join(now.format("%Y-%m-%d").to_string());
        let name = format!(
            "{}_{}_{}_{}.json",
            log_type.as_str(),
            self.user_id,
            now.format("%Y%m%d_%H%M%S"),
            random_suffix()
        );
        let path = dir.join(name);
        let content = serde_json::to_vec_pretty(value).ok()?;

        let result = async {
            tokio::fs::create_dir_all(&dir).await?;
            tokio::fs::write(&path, content).await
        }
        .await;
        match result {
            Ok(()) => Some(path.to_string_lossy().into_owned()),
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "operation log snapshot not written");
                None
            }
        }
    }
}

/// Five ASCII letters, like Go's `RandomStr(5)`; only used to keep file
/// names unique within a second.
fn random_suffix() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    let mut bits = hasher.finish();
    (0..5)
        .map(|_| {
            let c = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[(bits % 52) as usize];
            bits /= 52;
            char::from(c)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::random_suffix;

    #[test]
    fn suffix_shape() {
        let s = random_suffix();
        assert_eq!(s.len(), 5);
        assert!(s.bytes().all(|b| b.is_ascii_alphabetic()));
    }
}
