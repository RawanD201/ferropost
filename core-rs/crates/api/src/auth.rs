//! JWT authentication, compatible with tokens issued by the Go core.

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use bm_domain::rbac::ADMIN_ROLE;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

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
}

const ACCESS_SUBJECT: &str = "access_token";
const API_SUBJECT: &str = "api_token";

pub struct JwtVerifier {
    key: DecodingKey,
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
    if claims.exp.is_some() {
        let jti = claims.jti.as_deref().unwrap_or_default();
        let revoked = bm_store::tokens::is_revoked(&state.store.redis, jti)
            .await
            .map_err(|e| ApiError::Unavailable(format!("redis: {e:#}")))?;
        if revoked {
            return Err(ApiError::Unauthorized(String::new()));
        }
    }

    let roles = state
        .caches
        .roles
        .try_get_with(claims.account_id, async {
            bm_store::rbac::account_role_names(&state.store.pg, claims.account_id)
                .await
                .map(Arc::<[String]>::from)
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "load account roles");
            ApiError::Unauthorized("failed to get account roles".to_owned())
        })?;

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
