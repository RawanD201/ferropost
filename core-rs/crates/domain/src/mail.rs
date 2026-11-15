//! Mail-infrastructure naming rules.

/// Mail hostname to use when the `domain` table has no row for `domain`.
///
/// Mirrors the fallback branch of Go's `public.FormatMX`. Callers must try the
/// database first (a domain's `a_record` may be customised) and only fall back
/// to this. Never use a bare domain for DNS, certificates, DKIM or dedicated
/// IPs.
pub fn mx_hostname_fallback(domain: &str) -> String {
    format!("mail.{}", domain.strip_prefix("mail.").unwrap_or(domain))
}

/// True when `name` is safe to use as a single path component (for example a
/// certificate directory under the SSL root). Rejects traversal and anything
/// that is not a plausible DNS name.
pub fn is_safe_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_adds_single_mail_prefix() {
        assert_eq!(mx_hostname_fallback("example.com"), "mail.example.com");
        assert_eq!(mx_hostname_fallback("mail.example.com"), "mail.example.com");
        assert_eq!(
            mx_hostname_fallback("mail.mail.example.com"),
            "mail.mail.example.com"
        );
    }

    #[test]
    fn hostname_safety() {
        assert!(is_safe_hostname("mail.example.com"));
        assert!(is_safe_hostname("xn--bcher-kva.example"));
        assert!(!is_safe_hostname(""));
        assert!(!is_safe_hostname("../etc"));
        assert!(!is_safe_hostname("a/b"));
        assert!(!is_safe_hostname(".hidden"));
    }
}
