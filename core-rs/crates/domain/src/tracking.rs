//! Open/click tracking tokens (`/pmta/<token>`).
//!
//! New links are signed: `v2.<base64url(json)>.<base64url(hmac)>`, with an
//! HMAC-SHA256 (truncated to 128 bits) under a key derived from the server
//! secret, so they cannot be forged.
//!
//! Go's "encryption" (`maillog_stat.Encrypt`) is AES-128-CBC with a random
//! key and IV that are stored *inside* the token: key and IV bytes are
//! interleaved, the first 16 interleaved bytes go before the ciphertext and
//! the last 16 after it, all URL-safe base64 without padding. Anyone can
//! therefore decode or forge a token. Links in mail already sent use this
//! format, so it is still accepted; callers must treat its content as
//! untrusted (see `ferropost_store::tracking`).

use aes::Aes128;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::contacts::is_valid_email;

type Decryptor = cbc::Decryptor<Aes128>;
type Encryptor = cbc::Encryptor<Aes128>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Open,
    Click,
}

/// What a tracking link says happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackingEvent {
    #[serde(rename = "type")]
    pub kind: EventKind,
    pub campaign_id: i64,
    pub recipient: String,
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Not a decodable token (Go answered "Invalid -1").
    Malformed,
    /// Decoded but the fields are invalid (Go answered "Invalid -2").
    Invalid,
}

/// Campaign IDs above this are API sends, which have no contact group.
pub const API_CAMPAIGN_FLOOR: i64 = 1_000_000_000;

/// How a decoded token was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// HMAC-signed by this server.
    Signed,
    /// Go's format: anyone could have made it.
    Legacy,
}

const SIGNED_PREFIX: &str = "v2.";
const TAG_LEN: usize = 16;

/// Key for signing tracking links, derived from the server secret.
pub fn tracking_key(secret: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(b"ferropost/tracking/v2");
    mac.finalize().into_bytes().into()
}

fn tag(key: &[u8; 32], payload: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("any key length");
    mac.update(payload);
    mac
}

/// Encodes a signed token.
pub fn encode_signed(event: &TrackingEvent, key: &[u8; 32]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(event).unwrap_or_default());
    let sig = tag(key, payload.as_bytes()).finalize().into_bytes();
    format!(
        "{SIGNED_PREFIX}{payload}.{}",
        URL_SAFE_NO_PAD.encode(&sig[..TAG_LEN])
    )
}

/// Decodes a signed or legacy token and validates it.
pub fn decode(token: &str, key: &[u8; 32]) -> Result<(TrackingEvent, Origin), TokenError> {
    let Some(rest) = token.strip_prefix(SIGNED_PREFIX) else {
        return decode_legacy(token).map(|e| (e, Origin::Legacy));
    };
    let (payload, sig) = rest.split_once('.').ok_or(TokenError::Malformed)?;
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| TokenError::Malformed)?;
    if sig.len() != TAG_LEN {
        return Err(TokenError::Malformed);
    }
    tag(key, payload.as_bytes())
        .verify_truncated_left(&sig)
        .map_err(|_| TokenError::Malformed)?;
    let json = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TokenError::Malformed)?;
    let event: TrackingEvent = serde_json::from_slice(&json).map_err(|_| TokenError::Invalid)?;
    validate(event).map(|e| (e, Origin::Signed))
}

/// Decodes a legacy token and validates its fields with Go's rules, plus:
/// click URLs must be `http`/`https` (Go accepted any URL, so a token could
/// redirect to `javascript:` or `data:`), and `user+tag@` recipients are
/// accepted (Go rejected them, losing their events).
pub fn decode_legacy(token: &str) -> Result<TrackingEvent, TokenError> {
    let raw = URL_SAFE_NO_PAD
        .decode(token.trim_end_matches('='))
        .map_err(|_| TokenError::Malformed)?;
    if raw.len() < 48 || (raw.len() - 32) % 16 != 0 {
        return Err(TokenError::Malformed);
    }
    let (head, rest) = raw.split_at(16);
    let (ciphertext, tail) = rest.split_at(rest.len() - 16);
    let interleaved: Vec<u8> = head.iter().chain(tail).copied().collect();
    let key: Vec<u8> = interleaved.iter().step_by(2).copied().collect();
    let iv: Vec<u8> = interleaved.iter().skip(1).step_by(2).copied().collect();

    let plaintext = Decryptor::new_from_slices(&key, &iv)
        .map_err(|_| TokenError::Malformed)?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| TokenError::Malformed)?;
    let event: TrackingEvent =
        serde_json::from_slice(&plaintext).map_err(|_| TokenError::Invalid)?;
    validate(event)
}

fn validate(event: TrackingEvent) -> Result<TrackingEvent, TokenError> {
    let url_ok = match event.kind {
        EventKind::Open => event.url.is_empty() || is_web_url(&event.url),
        EventKind::Click => is_web_url(&event.url),
    };
    if event.message_id.is_empty()
        || !is_valid_email(&event.recipient)
        || event.campaign_id < 1
        || !url_ok
    {
        return Err(TokenError::Invalid);
    }
    Ok(event)
}

/// Encodes a token in the legacy format with the given key and IV (tests,
/// and compatibility until links are signed).
pub fn encode_legacy(event: &TrackingEvent, key: [u8; 16], iv: [u8; 16]) -> String {
    let json = serde_json::to_vec(event).unwrap_or_default();
    let ciphertext = Encryptor::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&json);
    let interleaved: Vec<u8> = key
        .iter()
        .zip(iv.iter())
        .flat_map(|(k, i)| [*k, *i])
        .collect();
    let mut out = Vec::with_capacity(ciphertext.len() + 32);
    out.extend_from_slice(&interleaved[..16]);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&interleaved[16..]);
    URL_SAFE_NO_PAD.encode(out)
}

fn is_web_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    rest.is_some_and(|r| {
        r.split(['/', '?', '#'])
            .next()
            .is_some_and(|host| !host.is_empty())
    }) && !url.contains(['\r', '\n'])
}

/// A 1×1 transparent PNG, the open-tracking pixel.
pub const PIXEL_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn click(url: &str) -> TrackingEvent {
        TrackingEvent {
            kind: EventKind::Click,
            campaign_id: 7,
            recipient: "bob+news@example.com".into(),
            message_id: "abc@mail.example.com".into(),
            url: url.into(),
        }
    }

    #[test]
    fn roundtrip() {
        let event = click("https://example.com/sale?x=1");
        let token = encode_legacy(&event, [3; 16], [9; 16]);
        assert!(!token.contains('='));
        assert_eq!(decode_legacy(&token), Ok(event));
        assert_eq!(
            decode_legacy(&format!("{token}==")).map(|e| e.campaign_id),
            Ok(7)
        );
    }

    /// Tokens produced by Go's `maillog_stat.Encrypt` (its code compiled
    /// unchanged, with GoFrame's random helper replaced by `crypto/rand`).
    #[test]
    fn decodes_tokens_made_by_go() {
        let open = decode_legacy("sJ1qX6p9PNTYuCHkLUQXhQt2EY7nKxwwoxlIx52-yMLctwWY6VLGNppRRHmgBwTbJPdSAWjPTUnizpD1n9QVaP-0M3n1GZIFUfsJLAaoUNv0iIeMyd1OiqUTIZR9nuxwjvyCv7IRj7RbaUYVfP7nGdz_6jpHiGZNOla2wSmsiHo").expect("open");
        assert_eq!(
            open,
            TrackingEvent {
                kind: EventKind::Open,
                campaign_id: 12,
                recipient: "a@x.com".into(),
                message_id: "m1@mail.x.com".into(),
                url: String::new(),
            }
        );
        let click = decode_legacy("ZeYg37KGM6ZKVa9WnlkYukCWJr32tRNgxuUSUOeP6UggjEql8VVj1192c9_FY4dvumUqpMMiFsRnhAl1Nfq1nkaBgZHjXDGVI0dzhWOzx47uOjHY49I7f8GrGG_ucdb6MZnNYT3oCPOIAw0gY4yqWol5iL_R_ftPiFRsPCVm01_DR8IGHpg35bUYqu-APkGohqCvfaKMQwSJYhZUEDPr8w").expect("click");
        assert_eq!(click.kind, EventKind::Click);
        assert_eq!(click.url, "https://example.com/p?q=1&r=2");
    }

    #[test]
    fn rejections() {
        assert_eq!(decode_legacy("not-a-token"), Err(TokenError::Malformed));
        assert_eq!(decode_legacy(""), Err(TokenError::Malformed));
        let token = |e: &TrackingEvent| encode_legacy(e, [1; 16], [2; 16]);
        assert_eq!(
            decode_legacy(&token(&click("javascript:alert(1)"))),
            Err(TokenError::Invalid)
        );
        assert_eq!(decode_legacy(&token(&click(""))), Err(TokenError::Invalid));
        assert_eq!(
            decode_legacy(&token(&click("https://"))),
            Err(TokenError::Invalid)
        );
        let mut bad = click("https://example.com");
        bad.recipient = "nope".into();
        assert_eq!(decode_legacy(&token(&bad)), Err(TokenError::Invalid));
        let mut bad = click("https://example.com");
        bad.campaign_id = 0;
        assert_eq!(decode_legacy(&token(&bad)), Err(TokenError::Invalid));
    }

    #[test]
    fn signed_tokens() {
        let key = tracking_key("secret");
        let event = click("https://example.com/sale");
        let token = encode_signed(&event, &key);
        assert!(token.starts_with("v2."));
        assert_eq!(decode(&token, &key), Ok((event.clone(), Origin::Signed)));

        // Tampering with the payload or using another key fails.
        let (payload, sig) = token["v2.".len()..].split_once('.').expect("parts");
        let mut forged = click("https://evil.example");
        forged.message_id = event.message_id.clone();
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).expect("json"));
        assert_eq!(
            decode(&format!("v2.{forged_payload}.{sig}"), &key),
            Err(TokenError::Malformed)
        );
        assert_eq!(
            decode(&token, &tracking_key("other")),
            Err(TokenError::Malformed)
        );
        assert_eq!(
            decode(&format!("v2.{payload}"), &key),
            Err(TokenError::Malformed)
        );

        // Legacy tokens still decode, marked as such.
        let legacy = encode_legacy(&event, [1; 16], [2; 16]);
        assert_eq!(decode(&legacy, &key), Ok((event, Origin::Legacy)));
    }

    #[test]
    fn pixel_is_a_png() {
        assert_eq!(&PIXEL_PNG[1..4], b"PNG");
    }
}
