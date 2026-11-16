//! JWT authentication, compatible with tokens issued by the Go core.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use ferropost_domain::rbac::ADMIN_ROLE;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::envelope::ApiError;
use crate::state::AppState;

/// Claims written by Go's `JWTService` (`JWTCustomClaims`).
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    #[serde(rename = "accountId")]
    pub account_id: i64,
    pub username: String,
    #[serde(rename = "apiToken", default)]
    pub api_token: bool,
    pub exp: Option<i64>,
    pub sub: Option<String>,
    pub jti: Option<String>,
    /// Login session shared by an access and refresh token pair (Rust-issued
    /// tokens only), so logout can end both.
    #[serde(default)]
    pub sid: Option<String>,
}

const ACCESS_SUBJECT: &str = "access_token";
const API_SUBJECT: &str = "api_token";
const REFRESH_SUBJECT: &str = "refresh_token";
/// Go's `consts.DEFAULT_SERVER_NAME`.
const ISSUER: &str = "billion-mail";
/// Lifetimes Go used (`jwt.accessExpiry`, `jwt.refreshExpiry`).
pub const ACCESS_TTL_SECS: i64 = 86_400;
pub const REFRESH_TTL_SECS: i64 = 7 * 86_400;

#[derive(Serialize)]
struct Issued<'a> {
    #[serde(rename = "accountId")]
    account_id: i64,
    username: &'a str,
    roles: Option<&'a [String]>,
    #[serde(rename = "apiToken")]
    api_token: bool,
    exp: i64,
    iat: i64,
    nbf: i64,
    iss: &'static str,
    sub: &'static str,
    jti: String,
    sid: &'a str,
}

/// A fresh access and refresh token.
#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    pub token: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
    pub ttl: i64,
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// A new login session ID.
pub fn new_session_id() -> String {
    random_hex(16)
}

pub struct JwtVerifier {
    key: DecodingKey,
    signing: EncodingKey,
    validation: Validation,
}

impl JwtVerifier {
    pub fn new(secret: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        // API tokens carry no `exp`; it is still enforced whenever present.
        validation.required_spec_claims.clear();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0;
        Self {
            key: DecodingKey::from_secret(secret.as_bytes()),
            signing: EncodingKey::from_secret(secret.as_bytes()),
            validation,
        }
    }

    /// Verifies signature, expiry and subject. Unlike Go, refresh tokens are
    /// rejected here: they are long-lived and only meant for `/api/refresh-token`.
    pub fn verify(&self, token: &str) -> Option<Claims> {
        let claims = jsonwebtoken::decode::<Claims>(token, &self.key, &self.validation)
            .ok()?
            .claims;
        matches!(claims.sub.as_deref(), Some(ACCESS_SUBJECT | API_SUBJECT)).then_some(claims)
    }

    /// A refresh token (never accepted by [`JwtVerifier::verify`]).
    pub fn verify_refresh(&self, token: &str) -> Option<Claims> {
        let claims = jsonwebtoken::decode::<Claims>(token, &self.key, &self.validation)
            .ok()?
            .claims;
        (claims.sub.as_deref() == Some(REFRESH_SUBJECT) && claims.exp.is_some()).then_some(claims)
    }

    /// A new API token for `account_id` (Go's `GenerateApiToken`): no
    /// expiry, so it stays valid until the next one is issued.
    pub fn issue_api_token(&self, account_id: i64, username: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "accountId": account_id,
            "username": username,
            "roles": [ADMIN_ROLE],
            "apiToken": true,
            "iat": now,
            "nbf": now,
            "iss": ISSUER,
            "sub": API_SUBJECT,
            "jti": random_hex(32),
        });
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &self.signing)
            .unwrap_or_default()
    }

    /// Issues an access and refresh token in Go's format, tied to `sid`.
    pub fn issue_pair(
        &self,
        account_id: i64,
        username: &str,
        roles: &[String],
        sid: &str,
    ) -> TokenPair {
        let now = chrono::Utc::now().timestamp();
        let sign = |sub: &'static str, ttl: i64, roles: Option<&[String]>| {
            let claims = Issued {
                account_id,
                username,
                roles,
                api_token: false,
                exp: now + ttl,
                iat: now,
                nbf: now,
                iss: ISSUER,
                sub,
                jti: random_hex(32),
                sid,
            };
            jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &self.signing)
                .unwrap_or_default()
        };
        TokenPair {
            token: sign(ACCESS_SUBJECT, ACCESS_TTL_SECS, Some(roles)),
            refresh_token: sign(REFRESH_SUBJECT, REFRESH_TTL_SECS, None),
            ttl: ACCESS_TTL_SECS,
        }
    }
}

/// Extracts the token from `Authorization: Bearer <token>` (Go also accepted
/// the bare token).
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?.trim_start();
    let token = value.strip_prefix("Bearer ").unwrap_or(value).trim();
    (!token.is_empty()).then_some(token)
}

/// The authenticated caller, available to handlers as an extractor.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub account_id: i64,
    pub username: String,
    pub roles: Arc<[String]>,
    pub api_token: bool,
}

impl CurrentUser {
    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r == ADMIN_ROLE)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<CurrentUser>()
            .cloned()
            .ok_or_else(|| ApiError::Unauthorized(String::new()))
    }
}

/// Whether the token or its login session was revoked.
pub async fn revoked(state: &AppState, claims: &Claims) -> Result<bool, ApiError> {
    let redis = &state.store.redis;
    let unavailable = |e: anyhow::Error| ApiError::Unavailable(format!("redis: {e:#}"));
    let jti = claims.jti.as_deref().unwrap_or_default();
    if ferropost_store::tokens::is_revoked(redis, jti)
        .await
        .map_err(unavailable)?
    {
        return Ok(true);
    }
    match claims.sid.as_deref() {
        Some(sid) => ferropost_store::tokens::session_revoked(redis, sid)
            .await
            .map_err(unavailable),
        None => Ok(false),
    }
}

/// Whether `token`, an API token, is the one issued last. Go never checked,
/// so regenerating the token left every earlier one working.
pub async fn api_token_current(state: &AppState, token: &str) -> Result<bool, ApiError> {
    let pg = state.store.pg.clone();
    let current = state
        .caches
        .api_token
        .try_get_with((), async move {
            ferropost_store::options::get_string(&pg, API_TOKEN_OPTION)
                .await
                .map(|t| t.map(|t| Arc::<str>::from(t.trim())))
        })
        .await
        .map_err(|e| ApiError::Unavailable(format!("load API token: {e:#}")))?;
    Ok(current.is_some_and(|current| {
        current.len() == token.len()
            && current
                .bytes()
                .zip(token.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }))
}

/// Option holding the API token (Go's name).
pub const API_TOKEN_OPTION: &str = "API_TOKEN";

/// Route layer for every authenticated API route.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer_token(req.headers())
        .ok_or_else(|| ApiError::Unauthorized("no authorization".to_owned()))?;
    let claims = state
        .jwt
        .verify(token)
        .ok_or_else(|| ApiError::Unauthorized(String::new()))?;

    // Logout revokes a token by writing its ID to Redis. Go skipped the check
    // when Redis failed; here an unavailable Redis rejects the request.
    if claims.exp.is_some() && revoked(&state, &claims).await? {
        return Err(ApiError::Unauthorized(String::new()));
    }
    if claims.api_token && !api_token_current(&state, token).await? {
        return Err(ApiError::Unauthorized("API token revoked".to_owned()));
    }

    // `None` for an account that is disabled or gone: Go kept honouring
    // their tokens until they expired.
    let roles = state
        .caches
        .roles
        .try_get_with(claims.account_id, async {
            ferropost_store::rbac::account_access(&state.store.pg, claims.account_id)
                .await
                .map(|access| match access {
                    Some((1, roles)) => Some(Arc::<[String]>::from(roles)),
                    _ => None,
                })
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "load account roles");
            ApiError::Unauthorized("failed to get account roles".to_owned())
        })?
        .ok_or_else(|| ApiError::Unauthorized(String::new()))?;

    req.extensions_mut().insert(CurrentUser {
        account_id: claims.account_id,
        username: claims.username,
        roles,
        api_token: claims.api_token,
    });
    Ok(next.run(req).await)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    pub(crate) fn sign(secret: &str, claims: serde_json::Value) -> String {
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("sign")
    }

    pub(crate) fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn accepts_go_access_token() {
        let token = sign(
            "s3cret",
            json!({
                "accountId": 1, "username": "admin", "roles": ["admin"], "apiToken": false,
                "iss": "billion-mail", "sub": "access_token", "jti": "abc",
                "exp": now() + 60, "nbf": now() - 1, "iat": now() - 1
            }),
        );
        let claims = JwtVerifier::new("s3cret").verify(&token).expect("valid");
        assert_eq!(claims.account_id, 1);
        assert_eq!(claims.jti.as_deref(), Some("abc"));
        assert!(!claims.api_token);
    }

    #[test]
    fn accepts_api_token_without_exp() {
        let token = sign(
            "s3cret",
            json!({"accountId": 1, "username": "a", "roles": null, "apiToken": true, "sub": "api_token"}),
        );
        let claims = JwtVerifier::new("s3cret").verify(&token).expect("valid");
        assert!(claims.api_token);
        assert!(claims.exp.is_none());
    }

    #[test]
    fn rejects_expired_wrong_key_and_refresh_tokens() {
        let verifier = JwtVerifier::new("s3cret");
        let expired = sign(
            "s3cret",
            json!({"accountId": 1, "username": "a", "sub": "access_token", "exp": now() - 1}),
        );
        let other_key = sign(
            "other",
            json!({"accountId": 1, "username": "a", "sub": "access_token", "exp": now() + 60}),
        );
        let refresh = sign(
            "s3cret",
            json!({"accountId": 1, "username": "a", "sub": "refresh_token", "exp": now() + 60}),
        );
        let not_yet = sign(
            "s3cret",
            json!({"accountId": 1, "username": "a", "sub": "access_token", "nbf": now() + 60}),
        );
        assert!(verifier.verify(&expired).is_none());
        assert!(verifier.verify(&other_key).is_none());
        assert!(verifier.verify(&refresh).is_none());
        assert!(verifier.verify(&not_yet).is_none());
        assert!(verifier.verify("garbage").is_none());
    }

    #[test]
    fn bearer_parsing() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, "Bearer abc".parse().expect("header"));
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, "abc".parse().expect("header"));
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, "Bearer ".parse().expect("header"));
        assert_eq!(bearer_token(&headers), None);
    }
}
