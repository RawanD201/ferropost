//! Mail service settings the console edits (Go: `controller/mail_services`):
//! the services' main configuration files, BCC rules and mail forwarding.

use crate::contacts::is_valid_email;

/// A mail service whose main configuration file the console edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Postfix,
    Dovecot,
    Rspamd,
}

impl Service {
    /// From the console's service type: a container name such as
    /// `/billionmail-postfix-billionmail-1` (Go matched by substring).
    pub fn from_type(service_type: &str) -> Option<Self> {
        let lower = service_type.to_ascii_lowercase();
        if lower.contains("dovecot") {
            Some(Self::Dovecot)
        } else if lower.contains("postfix") {
            Some(Self::Postfix)
        } else if lower.contains("rspamd") {
            Some(Self::Rspamd)
        } else {
            None
        }
    }

    /// The file under the shared `conf/` directory.
    pub fn config_file(self) -> &'static str {
        match self {
            Self::Postfix => "postfix/main.cf",
            Self::Dovecot => "dovecot/dovecot.conf",
            Self::Rspamd => "rspamd/rspamd.conf",
        }
    }

    /// The service's own configuration check, run in its container.
    pub fn check_command(self) -> &'static [&'static str] {
        match self {
            Self::Postfix => &["postfix", "check"],
            Self::Dovecot => &["doveconf", "-n"],
            Self::Rspamd => &["rspamadm", "configtest"],
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Postfix => "postfix",
            Self::Dovecot => "dovecot",
            Self::Rspamd => "rspamd",
        }
    }
}

/// Largest configuration file the editor reads in full or saves (Go: 3 MB).
pub const MAX_CONFIG_BYTES: u64 = 3 * 1024 * 1024;

/// Backups kept per configuration file (Go kept every one, forever).
pub const KEEP_BACKUPS: usize = 10;

/// Go's domain pattern for BCC rules: labels and a letters-only TLD.
pub fn is_domain(text: &str) -> bool {
    let labels: Vec<&str> = text.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
}

/// A BCC rule's address: a mailbox or a whole domain (`example.com` or
/// `@example.com`), lower-cased and without the `@` for a domain. Go wrote
/// any text into the Postfix map, where a space or line break added rules.
pub fn bcc_address(raw: &str) -> Option<String> {
    let address = raw.trim().to_ascii_lowercase();
    let address = address.strip_prefix('@').unwrap_or(&address).to_owned();
    (is_valid_email(&address) || is_domain(&address)).then_some(address)
}

/// The domain a BCC rule or forward belongs to (Go's `ExtractDomain`).
pub fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map_or(address, |(_, d)| d)
}

/// A forwarded address: a mailbox address or `@domain` (every address of
/// the domain), lower-cased.
pub fn forward_address(raw: &str) -> Option<String> {
    let address = raw.trim().to_ascii_lowercase();
    match address.strip_prefix('@') {
        Some(domain) => is_domain(domain).then_some(address.clone()),
        None => is_valid_email(&address).then_some(address),
    }
}

/// Forwarding targets as stored (comma-separated). The console sends one
/// per line, or the stored list back when it toggles a forward; Go also
/// accepted a literal `\n`.
pub fn forward_targets(raw: &str) -> Result<Vec<String>, String> {
    let mut targets: Vec<String> = Vec::new();
    for part in raw
        .replace("\\n", "\n")
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let target = part.to_ascii_lowercase();
        if !is_valid_email(&target) {
            return Err(format!("invalid forward target address: {part}"));
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    if targets.is_empty() {
        return Err("forward target address cannot be empty".to_owned());
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services() {
        assert_eq!(
            Service::from_type("/billionmail-postfix-billionmail-1"),
            Some(Service::Postfix)
        );
        assert_eq!(Service::from_type("Dovecot"), Some(Service::Dovecot));
        assert_eq!(Service::from_type("core-billionmail"), None);
        assert_eq!(Service::Rspamd.config_file(), "rspamd/rspamd.conf");
    }

    #[test]
    fn bcc_addresses() {
        assert_eq!(bcc_address(" @Ex.Test ").as_deref(), Some("ex.test"));
        assert_eq!(bcc_address("Boss@ex.test").as_deref(), Some("boss@ex.test"));
        for bad in ["ex", "a b@ex.test", "ex.test\nx y", "ex.123", "-a.test"] {
            assert_eq!(bcc_address(bad), None, "{bad:?}");
        }
        assert_eq!(domain_of("a@ex.test"), "ex.test");
        assert_eq!(domain_of("ex.test"), "ex.test");
    }

    #[test]
    fn forwards() {
        assert_eq!(
            forward_address("Info@Ex.test").as_deref(),
            Some("info@ex.test")
        );
        assert_eq!(forward_address("@ex.test").as_deref(), Some("@ex.test"));
        assert_eq!(forward_address("nope"), None);
        assert_eq!(
            forward_targets("a@x.test\nB@y.test,a@x.test\\nc@z.test").expect("targets"),
            ["a@x.test", "b@y.test", "c@z.test"]
        );
        assert!(forward_targets("a@x.test\nnot an address").is_err());
        assert!(forward_targets(" \n ").is_err());
    }
}
