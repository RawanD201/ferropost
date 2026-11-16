//! Signing in and out (Go: `controller/rbac`): `login`, `aapanel/sso`,
//! `logout`, `refresh-token`, `get_validate_code`. Go's account, role and
//! permission routes were never wired up and stay absent.
//!
//! Differences from Go: disabled accounts cannot sign in, refresh or keep
//! using their tokens; logout also ends the refresh token, and a refresh
//! token works once (Go left both usable for seven days); failed-login
//! counters and captchas live in Redis, per real client IP (Go kept them in
//! memory, keyed on an `X-Forwarded-For` anyone could set); an unknown
//! username takes as long to reject as a wrong password; the audit log no
//! longer records the issued tokens.

use std::sync::LazyLock;

use axum::Extension;
use axum::Router;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ferropost_domain::audit::LogType;
use ferropost_store::rbac::{self, LoginAccount};
use ferropost_store::tokens;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::now;
use crate::audit::Audit;
use crate::auth::{REFRESH_TTL_SECS, TokenPair, new_session_id};
use crate::body::ApiBody;
use crate::conn::{ClientIp, ConnInfo};
use crate::de::opt_string;
use crate::envelope::{ApiError, ApiResponse};
use crate::lang::Lang;
use crate::state::AppState;

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/aapanel/sso", post(aapanel_sso))
        .route("/api/refresh-token", post(refresh))
        .route("/api/get_validate_code", get(validate_code))
}

pub fn signed_in_routes() -> Router<AppState> {
    Router::new().route("/api/logout", post(logout))
}

const MAX_FAILURES: i64 = 5;
const FAILURE_WINDOW_SECS: i64 = 300;
const SSO_SKEW_SECS: i64 = 300;

/// Compared against when the username does not exist, so both failures
/// take the same time.
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| pwhash::bcrypt::hash("ferropost-no-such-account").unwrap_or_default());

#[derive(Serialize)]
struct AccountInfo {
    id: i64,
    username: String,
    email: String,
    status: i32,
    lang: String,
}

#[derive(Serialize)]
struct SignedIn {
    #[serde(flatten)]
    tokens: TokenPair,
    #[serde(rename = "accountInfo")]
    account_info: AccountInfo,
}

/// Issues a session's tokens, with the rspamd interface's cookie for an
/// admin.
async fn sign_in(
    state: &AppState,
    account: LoginAccount,
    tls: bool,
) -> Result<(SignedIn, Option<HeaderValue>), ApiError> {
    let roles = rbac::account_role_names(&state.store.pg, account.account_id).await?;
    let sid = new_session_id();
    let tokens = state
        .jwt
        .issue_pair(account.account_id, &account.username, &roles, &sid);
    let cookie = crate::rspamd::for_new_tokens(state, account.account_id, &roles, &sid, tls);
    rbac::touch_login(&state.store.pg, account.account_id, now()).await?;
    Ok((
        SignedIn {
            tokens,
            account_info: AccountInfo {
                id: account.account_id,
                username: account.username,
                email: account.email,
                status: account.status,
                lang: account.language,
            },
        },
        cookie,
    ))
}

/// A response with an optional `Set-Cookie`.
fn with_cookie(response: impl IntoResponse, cookie: Option<HeaderValue>) -> Response {
    let mut response = response.into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    response
}

fn redis_down(e: anyhow::Error) -> ApiError {
    ApiError::Unavailable(format!("redis: {e:#}"))
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    #[serde(default, deserialize_with = "opt_string")]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    validate_code_id: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    validate_code: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    conn: Option<Extension<ConnInfo>>,
    audit: Audit,
    ApiBody(body): ApiBody<LoginBody>,
) -> Result<Response, ApiError> {
    let tr = |msg: &str| state.i18n.tr(&lang, msg, &[]);
    let redis = &state.store.redis;
    let client = ip.to_canonical().to_string();
    let (failures, wait) = tokens::login_failures(redis, &client)
        .await
        .map_err(redis_down)?;
    if failures >= MAX_FAILURES {
        return Err(ApiError::Rejected(state.i18n.tr(
            &lang,
            "Login failed too many times, please try again after {} seconds",
            &[&wait],
        )));
    }
    if failures > 0 {
        let (Some(id), Some(code)) = (&body.validate_code_id, &body.validate_code) else {
            return Err(ApiError::Rejected(tr(
                "Validation code ID and code cannot be empty",
            )));
        };
        if !crate::captcha::check(&state, id, code)
            .await
            .map_err(redis_down)?
        {
            return Err(ApiError::Rejected(tr("Invalid validation code")));
        }
    }
    let username = body
        .username
        .ok_or_else(|| ApiError::Validation(tr("Username cannot be empty")))?;
    let password = body
        .password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ApiError::Validation(tr("Password cannot be empty")))?;

    let account = rbac::account_by_username(&state.store.pg, &username).await?;
    let hash = account
        .as_ref()
        .map_or_else(|| DUMMY_HASH.clone(), |a| a.password.clone());
    let matches = tokio::task::spawn_blocking(move || pwhash::bcrypt::verify(password, &hash))
        .await
        .unwrap_or(false);
    let account = match account {
        Some(a) if matches && a.status == 1 => a,
        _ => {
            tokens::record_login_failure(redis, &client, FAILURE_WINDOW_SECS)
                .await
                .map_err(redis_down)?;
            return Err(ApiError::Rejected(tr("Invalid username or password")));
        }
    };
    tokens::clear_login_failures(redis, &client)
        .await
        .map_err(redis_down)?;
    let tls = conn.is_some_and(|c| c.0.tls);
    let (signed_in, cookie) = sign_in(&state, account, tls).await?;
    audit
        .record_with(
            LogType::Login,
            &format!("The user:{} login was successful", signed_in.account_info.username),
            &serde_json::json!({"account_id": signed_in.account_info.id, "username": signed_in.account_info.username}),
        )
        .await;
    Ok(with_cookie(
        ApiResponse::ok(tr("Login successful"), signed_in),
        cookie,
    ))
}

#[derive(Serialize)]
struct ValidateCode {
    #[serde(rename = "mustValidateCode")]
    must_validate_code: bool,
    #[serde(rename = "loginRetries")]
    login_retries: i64,
    #[serde(rename = "maxLoginRetries")]
    max_login_retries: i64,
    #[serde(rename = "validateCodeBase64")]
    validate_code_base64: String,
    #[serde(rename = "validateCodeId")]
    validate_code_id: String,
}

async fn validate_code(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Extension(ClientIp(ip)): Extension<ClientIp>,
) -> Result<ApiResponse<ValidateCode>, ApiError> {
    let client = ip.to_canonical().to_string();
    let (failures, _) = tokens::login_failures(&state.store.redis, &client)
        .await
        .map_err(redis_down)?;
    let (id, image) = crate::captcha::issue(&state).await.map_err(redis_down)?;
    Ok(ApiResponse::ok(
        state.i18n.tr(&lang, "Success", &[]),
        ValidateCode {
            must_validate_code: failures > 0,
            login_retries: failures,
            max_login_retries: MAX_FAILURES,
            validate_code_base64: image,
            validate_code_id: id,
        },
    ))
}

async fn logout(
    State(state): State<AppState>,
    Lang(lang): Lang,
    headers: HeaderMap,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let invalid = || {
        ApiError::Rejected(
            state
                .i18n
                .tr(&lang, "Invalid or expired refresh token", &[]),
        )
    };
    let token = crate::auth::bearer_token(&headers).ok_or_else(invalid)?;
    let claims = state.jwt.verify(token).ok_or_else(invalid)?;
    let redis = &state.store.redis;
    if let (Some(jti), Some(exp)) = (&claims.jti, claims.exp) {
        tokens::revoke(redis, jti, exp - chrono::Utc::now().timestamp())
            .await
            .map_err(redis_down)?;
    }
    if let Some(sid) = &claims.sid {
        tokens::revoke_session(redis, sid, REFRESH_TTL_SECS)
            .await
            .map_err(redis_down)?;
    }
    Ok((
        [(axum::http::header::SET_COOKIE, crate::rspamd::clearing())],
        ApiResponse::ok(state.i18n.tr(&lang, "Logout successful", &[]), ()),
    ))
}

#[derive(Debug, Deserialize)]
struct RefreshBody {
    #[serde(default, rename = "refreshToken", deserialize_with = "opt_string")]
    refresh_token: Option<String>,
}

async fn refresh(
    State(state): State<AppState>,
    Lang(lang): Lang,
    conn: Option<Extension<ConnInfo>>,
    ApiBody(body): ApiBody<RefreshBody>,
) -> Result<Response, ApiError> {
    let invalid = || {
        ApiError::Rejected(
            state
                .i18n
                .tr(&lang, "Invalid or expired refresh token", &[]),
        )
    };
    let token = body.refresh_token.ok_or_else(|| {
        ApiError::Validation(state.i18n.tr(&lang, "Refresh token cannot be empty", &[]))
    })?;
    let claims = state.jwt.verify_refresh(&token).ok_or_else(invalid)?;
    if crate::auth::revoked(&state, &claims).await? {
        return Err(invalid());
    }
    let account = rbac::account_by_id(&state.store.pg, claims.account_id)
        .await?
        .filter(|a| a.status == 1)
        .ok_or_else(invalid)?;
    // One use per refresh token.
    if let (Some(jti), Some(exp)) = (&claims.jti, claims.exp) {
        tokens::revoke(
            &state.store.redis,
            jti,
            exp - chrono::Utc::now().timestamp(),
        )
        .await
        .map_err(redis_down)?;
    }
    let sid = claims.sid.unwrap_or_else(new_session_id);
    let roles = rbac::account_role_names(&state.store.pg, account.account_id).await?;
    let pair = state
        .jwt
        .issue_pair(account.account_id, &account.username, &roles, &sid);
    let tls = conn.is_some_and(|c| c.0.tls);
    let cookie = crate::rspamd::for_new_tokens(&state, account.account_id, &roles, &sid, tls);
    Ok(with_cookie(
        ApiResponse::ok(
            state.i18n.tr(&lang, "Token refreshed successfully", &[]),
            pair,
        ),
        cookie,
    ))
}

#[derive(Debug, Deserialize)]
struct SsoBody {
    #[serde(default, deserialize_with = "opt_string")]
    username: Option<String>,
}

fn sso_secret(state: &AppState) -> Option<String> {
    ["AAPANEL_SSO_SECRET", "BT_PANEL_SSO_SECRET"]
        .into_iter()
        .find_map(|key| {
            std::env::var(key)
                .ok()
                .or_else(|| state.config.env.get(key))
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
}

fn sso_mac(secret: &str, timestamp: &str, nonce: &str, username: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(format!("{timestamp}\n{nonce}\n{username}").as_bytes());
    mac
}

/// Signs in from aaPanel with an HMAC-signed request (Go's scheme: the
/// signature covers timestamp, nonce and username; each nonce works once).
async fn aapanel_sso(
    State(state): State<AppState>,
    Lang(lang): Lang,
    Extension(conn): Extension<ConnInfo>,
    audit: Audit,
    headers: HeaderMap,
    ApiBody(body): ApiBody<SsoBody>,
) -> Result<Response, ApiError> {
    let reject = |msg: &str| ApiError::Rejected(state.i18n.tr(&lang, msg, &[]));
    let username = body
        .username
        .or_else(|| {
            state
                .config
                .env
                .get("ADMIN_USERNAME")
                .filter(|v| !v.trim().is_empty())
        })
        .ok_or_else(|| reject("username cannot be empty"))?;
    let secret = sso_secret(&state).ok_or_else(|| reject("aaPanel SSO is disabled"))?;
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_owned())
            .unwrap_or_default()
    };
    let (timestamp, nonce, signature) = (
        header("X-Aapanel-Timestamp"),
        header("X-Aapanel-Nonce"),
        header("X-Aapanel-Signature"),
    );
    if timestamp.is_empty() || nonce.is_empty() || signature.is_empty() {
        return Err(reject("missing aaPanel SSO signature headers"));
    }
    if nonce.len() > 128 {
        return Err(reject("invalid aaPanel SSO nonce"));
    }
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| reject("invalid aaPanel SSO timestamp"))?;
    if (chrono::Utc::now().timestamp() - ts).abs() > SSO_SKEW_SECS {
        return Err(reject("aaPanel SSO request expired"));
    }
    let given = signature.to_ascii_lowercase();
    let given = hex::decode(given.strip_prefix("sha256=").unwrap_or(&given))
        .map_err(|_| reject("invalid aaPanel SSO signature"))?;
    if sso_mac(&secret, &timestamp, &nonce, &username)
        .verify_slice(&given)
        .is_err()
    {
        return Err(reject("invalid aaPanel SSO signature"));
    }
    let fresh = ferropost_store::ratelimit::first_in_window(
        &state.store.redis,
        &format!("aapanel-sso:{nonce}"),
        SSO_SKEW_SECS,
    )
    .await
    .map_err(redis_down)?;
    if !fresh {
        return Err(reject("aaPanel SSO nonce already used"));
    }
    let account = rbac::account_by_username(&state.store.pg, &username)
        .await?
        .ok_or_else(|| reject("account does not exist"))?;
    if account.status != 1 {
        return Err(reject("account is disabled"));
    }
    let (signed_in, rspamd_cookie) = sign_in(&state, account, conn.tls).await?;
    audit
        .record(
            LogType::Login,
            &format!(
                "The user:{} login by aaPanel SSO was successful",
                signed_in.account_info.username
            ),
        )
        .await;
    let mut response = with_cookie(
        ApiResponse::ok(
            state.i18n.tr(&lang, "aaPanel SSO successful", &[]),
            signed_in,
        ),
        rspamd_cookie,
    );
    if let Some(cookie) = crate::edge::entrance_set_cookie(&state, conn.tls)
        && let Ok(value) = cookie.parse()
    {
        response.headers_mut().append(SET_COOKIE, value);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sso_signature_matches_go() {
        // hmac-sha256("secret", "1800000000\nn1\nadmin") per Go's
        // aaPanelSSOExpectedSignature (computed with openssl).
        assert_eq!(
            hex::encode(
                sso_mac("secret", "1800000000", "n1", "admin")
                    .finalize()
                    .into_bytes()
            ),
            "2fb401e751839ca905829e4ae63ea194d860b8b130c5e7eeaeb518bbbd44aaa5"
        );
    }
}
