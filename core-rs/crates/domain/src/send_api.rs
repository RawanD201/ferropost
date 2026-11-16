//! The send API (Go: `batch_mail` `api_*`): API keys tied to a template,
//! and the queue of messages sent through them (`api_mail_logs`).

use crate::tracking::API_CAMPAIGN_FLOOR;

/// `api_mail_logs.status`.
pub mod status {
    pub const PENDING: i32 = 0;
    /// Claimed by the sender (Ferropost; Go has no such state).
    pub const CLAIMED: i32 = 1;
    pub const SENT: i32 = 2;
    pub const FAILED: i32 = 3;
}

/// Error codes of `/batch_mail/api/send` and `batch_send`, kept from Go.
pub mod code {
    pub const INVALID_KEY: i32 = 1001;
    pub const IP_NOT_ALLOWED: i32 = 1002;
    pub const BAD_RECIPIENT: i32 = 1003;
    pub const NO_TEMPLATE: i32 = 1004;
    pub const NOT_QUEUED: i32 = 1005;
}

/// Campaign ID that tracking events of an API's mail carry.
pub fn campaign_id(api_id: i32) -> i64 {
    API_CAMPAIGN_FLOOR + i64::from(api_id)
}

/// Contact group collecting the recipients of an API without its own group.
pub fn api_group_name(api_id: i32) -> String {
    format!("api_group_{api_id}")
}

/// Whether a key is still valid: `expire_time` counts seconds from when the
/// key was issued, 0 meaning forever. Go stored the value but never
/// checked it.
pub fn key_valid(expire_time: i64, issued_at: i64, now: i64) -> bool {
    expire_time <= 0 || now < issued_at.saturating_add(expire_time)
}

/// A sender other than the API's own must be on the same domain: an API key
/// is handed to another system, and Go let it send as any mailbox on the
/// server.
pub fn sender_allowed(api_addresser: &str, requested: &str) -> bool {
    let domain = |a: &str| a.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase());
    requested.eq_ignore_ascii_case(api_addresser)
        || (domain(requested).is_some() && domain(requested) == domain(api_addresser))
}

/// IP whitelist entries as Go stored them: trimmed, valid addresses only,
/// without duplicates.
pub fn clean_whitelist(ips: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ip in ips {
        let ip = ip.trim();
        if ip.parse::<std::net::IpAddr>().is_ok() && !out.iter().any(|o| o == ip) {
            out.push(ip.to_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert_eq!(campaign_id(7), 1_000_000_007);
        assert_eq!(api_group_name(7), "api_group_7");
        assert!(key_valid(0, 0, 1_800_000_000));
        assert!(key_valid(3600, 1000, 4599));
        assert!(!key_valid(3600, 1000, 4600));
        assert!(sender_allowed("news@ex.com", "news@ex.com"));
        assert!(sender_allowed("news@ex.com", "Sales@EX.com"));
        assert!(!sender_allowed("news@ex.com", "admin@other.com"));
        assert!(!sender_allowed("news@ex.com", "nobody"));
        assert_eq!(
            clean_whitelist(&[
                " 1.2.3.4 ".into(),
                "x".into(),
                "1.2.3.4".into(),
                "::1".into()
            ]),
            ["1.2.3.4", "::1"]
        );
    }
}
