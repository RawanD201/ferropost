//! Unsubscribe and subscribe-confirmation links (Go: `batch_mail/jwt.go`).
//!
//! Go signed these HS256 JWTs with a secret derived from fixed default
//! config values, the same on every default install, so anyone could forge
//! an unsubscribe link for any address. New tokens use a random secret.
//! Links already in people's inboxes (valid 30 days) carry Go's secret and
//! are still accepted, reported as [`Origin::Legacy`] so callers can apply
//! extra checks. Go also shared one cached secret between both kinds of
//! token, so legacy tokens of either kind are checked against both of its
//! stored secrets.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// How long links stay valid (Go: 30 days).
pub const TOKEN_TTL_SECS: i64 = 30 * 86_400;

#[derive(Debug, Clone)]
pub struct TokenKeys {
    /// Random secret for new tokens.
    pub current: String,
    /// Go's secrets, accepted for links it issued.
    pub legacy: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Current,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeClaims {
    pub email: String,
    #[serde(default)]
    pub template_id: i64,
    #[serde(default)]
    pub task_id: i64,
    pub group_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeClaims {
    pub email: String,
    pub group_token: String,
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    #[serde(flatten)]
    claims: T,
    exp: i64,
    iat: i64,
}

fn issue<T: Serialize>(secret: &str, claims: T, now: i64) -> String {
    let envelope = Envelope {
        claims,
        exp: now + TOKEN_TTL_SECS,
        iat: now,
    };
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &envelope,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap_or_default()
}

fn verify<T: for<'de> Deserialize<'de>>(keys: &TokenKeys, token: &str) -> Option<(T, Origin)> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.leeway = 0;
    let decode = |secret: &str| {
        jsonwebtoken::decode::<Envelope<T>>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .ok()
        .map(|data| data.claims.claims)
    };
    if let Some(claims) = decode(&keys.current) {
        return Some((claims, Origin::Current));
    }
    keys.legacy
        .iter()
        .find_map(|secret| decode(secret))
        .map(|claims| (claims, Origin::Legacy))
}

pub fn issue_unsubscribe(keys: &TokenKeys, claims: UnsubscribeClaims, now: i64) -> String {
    issue(&keys.current, claims, now)
}

/// Checks signature and expiry; `email` and `group_id` are required (Go's
/// rules).
pub fn verify_unsubscribe(keys: &TokenKeys, token: &str) -> Option<(UnsubscribeClaims, Origin)> {
    verify(keys, token).filter(|(c, _): &(UnsubscribeClaims, _)| !c.email.is_empty())
}

pub fn issue_subscribe(keys: &TokenKeys, claims: SubscribeClaims, now: i64) -> String {
    issue(&keys.current, claims, now)
}

pub fn verify_subscribe(keys: &TokenKeys, token: &str) -> Option<(SubscribeClaims, Origin)> {
    verify(keys, token)
        .filter(|(c, _): &(SubscribeClaims, _)| !c.email.is_empty() && !c.group_token.is_empty())
}

/// 32 random bytes as hex, for a new secret.
pub fn new_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> TokenKeys {
        TokenKeys {
            current: "new-secret".into(),
            legacy: vec!["go-unsubscribe".into(), "go-subscribe".into()],
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn claims() -> UnsubscribeClaims {
        UnsubscribeClaims {
            email: "a@x.com".into(),
            template_id: 3,
            task_id: 7,
            group_id: 2,
        }
    }

    #[test]
    fn current_tokens_roundtrip() {
        let token = issue_unsubscribe(&keys(), claims(), now());
        assert_eq!(
            verify_unsubscribe(&keys(), &token),
            Some((claims(), Origin::Current))
        );
        let sub = SubscribeClaims {
            email: "a@x.com".into(),
            group_token: "tok".into(),
        };
        let token = issue_subscribe(&keys(), sub.clone(), now());
        assert_eq!(
            verify_subscribe(&keys(), &token),
            Some((sub, Origin::Current))
        );
    }

    #[test]
    fn go_tokens_are_legacy() {
        // Shape of Go's GenerateUnsubscribeJWT, signed with either Go secret.
        for secret in ["go-unsubscribe", "go-subscribe"] {
            let token = issue(secret, claims(), now());
            assert_eq!(
                verify_unsubscribe(&keys(), &token),
                Some((claims(), Origin::Legacy))
            );
        }
    }

    /// Signed by Go's golang-jwt v5 with `jwt.go`'s claims struct (expiry
    /// set to 2099 so the fixture does not go stale).
    #[test]
    fn decodes_a_token_signed_by_go() {
        let go = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFAeC5jb20iLCJ0ZW1wbGF0ZV9pZCI6MywidGFza19pZCI6NywiZ3JvdXBfaWQiOjIsImV4cCI6NDA3MDkwODgwMCwiaWF0IjoxNzk0NzAwODAwfQ.Um8b5ObVzzWoyeYB5yzdClbN8tUC09iSnJ1_8Jds0Xw";
        assert_eq!(
            verify_unsubscribe(&keys(), go),
            Some((claims(), Origin::Legacy))
        );
    }

    #[test]
    fn rejections() {
        let expired = issue(&keys().current, claims(), now() - TOKEN_TTL_SECS - 10);
        assert_eq!(verify_unsubscribe(&keys(), &expired), None);
        let stranger = issue("someone-else", claims(), now());
        assert_eq!(verify_unsubscribe(&keys(), &stranger), None);
        // group_id is required, as in Go.
        let no_group = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({"email": "a@x.com", "exp": now() + 60}),
            &EncodingKey::from_secret(b"new-secret"),
        )
        .expect("sign");
        assert_eq!(verify_unsubscribe(&keys(), &no_group), None);
        assert_eq!(verify_unsubscribe(&keys(), "garbage"), None);
    }

    #[test]
    fn secrets_are_random() {
        let (a, b) = (new_secret(), new_secret());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
