//! The rspamd web interface behind the console (Go: the `/rspamd/*` proxy
//! in `cmd.go`), logged in with the controller password Go generated.
//!
//! The console shows it in an iframe, which sends cookies but no token.
//! Go accepted any token it had stored in its server session, which only
//! held one after the browser's last call to a route Go served, and kept it
//! after logout. Here an admin's API calls set a signed `ferropost_rspamd`
//! cookie bound to their login session: logging out, losing the admin role
//! or a disabled account ends access at once.

use std::net::{IpAddr, Ipv4Addr};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use ferropost_domain::rbac::ADMIN_ROLE;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::auth::Claims;
use crate::conn::{ClientIp, ConnInfo};
use crate::state::AppState;

pub const COOKIE_NAME: &str = "ferropost_rspamd";
const PASSWORD_OPTION: &str = "rspamd_worker_controller_password";
/// A cookie this close to its end is renewed by the next API call.
const RENEW_SECS: i64 = 3600;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/rspamd", any(proxy))
        .route("/rspamd/", any(proxy))
        .route("/rspamd/{*rest}", any(proxy))
}

/// The login session a cookie belongs to: the session ID of a token
/// issued here, else the ID of a token Go issued.
fn session_of(claims: &Claims) -> Option<String> {
    let session = match (&claims.sid, &claims.jti) {
        (Some(sid), _) => sid.clone(),
        (None, Some(jti)) => format!("j:{jti}"),
        (None, None) => return None,
    };
    session
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-' || b == b'_')
        .then_some(session)
}

fn mac(secret: &str, account: i64, session: &str, exp: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(format!("ferropost:rspamd:{secret}").as_bytes())
        .expect("any key length");
    mac.update(format!("{account}.{session}.{exp}").as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}

/// A verified cookie.
#[derive(Debug, PartialEq, Eq)]
struct Pass {
    account: i64,
    session: String,
    exp: i64,
}

fn verify(secret: &str, value: &str, now: i64) -> Option<Pass> {
    let (body, tag) = value.rsplit_once('.')?;
    let mut fields = body.splitn(3, '.');
    let account: i64 = fields.next()?.parse().ok()?;
    let session = fields.next()?.to_owned();
    let exp: i64 = fields.next()?.parse().ok()?;
    let expected = mac(secret, account, &session, exp);
    let same = expected.len() == tag.len()
        && expected
            .bytes()
            .zip(tag.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    (same && exp > now).then_some(Pass {
        account,
        session,
        exp,
    })
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
}

/// The `Set-Cookie` an admin's API response carries when their rspamd
/// cookie is missing, belongs to another session or is about to end.
pub fn renewal(
    state: &AppState,
    headers: &HeaderMap,
    claims: &Claims,
    tls: bool,
    now: i64,
) -> Option<HeaderValue> {
    let exp = claims.exp?;
    let session = session_of(claims)?;
    let secret = &state.config.jwt_secret;
    let current = cookie(headers, COOKIE_NAME).and_then(|v| verify(secret, v, now));
    let fine = current.is_some_and(|c| {
        c.account == claims.account_id
            && c.session == session
            && (c.exp >= exp || c.exp - now > RENEW_SECS)
    });
    if fine || exp <= now {
        return None;
    }
    issue(secret, claims.account_id, &session, exp, tls, now)
}

fn issue(
    secret: &str,
    account: i64,
    session: &str,
    exp: i64,
    tls: bool,
    now: i64,
) -> Option<HeaderValue> {
    let value = format!(
        "{account}.{session}.{exp}.{}",
        mac(secret, account, session, exp)
    );
    HeaderValue::from_str(&format!(
        "{COOKIE_NAME}={value}; Path=/rspamd; Max-Age={}; HttpOnly; SameSite=Strict{}",
        exp - now,
        if tls { "; Secure" } else { "" }
    ))
    .ok()
}

/// The cookie for a token pair just issued (login, refresh, SSO), so the
/// interface works before the console's first other call.
pub fn for_new_tokens(
    state: &AppState,
    account: i64,
    roles: &[String],
    session: &str,
    tls: bool,
) -> Option<HeaderValue> {
    if !roles.iter().any(|r| r == ADMIN_ROLE) {
        return None;
    }
    let now = chrono::Utc::now().timestamp();
    issue(
        &state.config.jwt_secret,
        account,
        session,
        now + crate::auth::ACCESS_TTL_SECS,
        tls,
        now,
    )
}

/// Clears the cookie (logout).
pub fn clearing() -> HeaderValue {
    HeaderValue::from_static(
        "ferropost_rspamd=; Path=/rspamd; Max-Age=0; HttpOnly; SameSite=Strict",
    )
}

/// Whether the request carries a live admin session.
async fn allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let now = chrono::Utc::now().timestamp();
    let Some(pass) =
        cookie(headers, COOKIE_NAME).and_then(|v| verify(&state.config.jwt_secret, v, now))
    else {
        return false;
    };
    let redis = &state.store.redis;
    let revoked = match pass.session.strip_prefix("j:") {
        Some(jti) => ferropost_store::tokens::is_revoked(redis, jti).await,
        None => ferropost_store::tokens::session_revoked(redis, &pass.session).await,
    };
    if !matches!(revoked, Ok(false)) {
        return false;
    }
    matches!(
        crate::auth::account_roles(state, pass.account).await,
        Ok(Some(roles)) if roles.iter().any(|r| r == ADMIN_ROLE)
    )
}

async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    if !allowed(&state, req.headers()).await {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }
    let password = ferropost_store::options::get_string(&state.store.pg, PASSWORD_OPTION)
        .await
        .ok()
        .flatten();
    let tls = req.extensions().get::<ConnInfo>().is_some_and(|c| c.tls);
    let ip = req
        .extensions()
        .get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path();
    let path = path.strip_prefix("/rspamd").unwrap_or(path);
    let path = if path.is_empty() { "/" } else { path };
    let target = match parts.uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    let Ok(uri) = target.parse::<Uri>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    parts.uri = uri;
    // rspamd needs none of the console's credentials.
    parts.headers.remove(COOKIE);
    parts.headers.remove(AUTHORIZATION);
    let password_header = HeaderName::from_static("password");
    parts.headers.remove(&password_header);
    if let Some(value) = password.and_then(|p| HeaderValue::from_str(&p).ok()) {
        parts.headers.insert(password_header, value);
    }
    match state
        .rspamd
        .send(Request::from_parts(parts, body), ip, tls)
        .await
    {
        Ok(mut response) => {
            // Logged here: rspamd keeps no access log for us.
            response.extensions_mut().remove::<crate::proxy::Proxied>();
            response
        }
        Err(err) => {
            tracing::warn!(error = %err, "rspamd controller unreachable");
            (StatusCode::BAD_GATEWAY, Body::from("Bad Gateway")).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_verify() {
        let value = format!("7.sid1.100.{}", mac("s", 7, "sid1", 100));
        assert_eq!(
            verify("s", &value, 50),
            Some(Pass {
                account: 7,
                session: "sid1".into(),
                exp: 100
            })
        );
        assert_eq!(verify("s", &value, 100), None, "expired");
        assert_eq!(verify("other", &value, 50), None, "another secret");
        let forged = value.replacen("7.", "1.", 1);
        assert_eq!(verify("s", &forged, 50), None, "another account");
        assert_eq!(verify("s", "garbage", 50), None);
        let j = format!("1.j:abc.100.{}", mac("s", 1, "j:abc", 100));
        assert_eq!(verify("s", &j, 0).map(|p| p.session), Some("j:abc".into()));
    }

    #[test]
    fn reads_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("a=1; ferropost_rspamd=v.1; b=2"),
        );
        assert_eq!(cookie(&headers, COOKIE_NAME), Some("v.1"));
        assert_eq!(cookie(&headers, "c"), None);
    }
}
