//! Console settings kept in the shared `.env` file (Go:
//! `controller/settings`): which keys the console may change and how their
//! values are checked.
//!
//! `bm.sh` runs `source .env` as root, so a value is shell code waiting to
//! happen. Go refused a list of characters but let spaces and quotes through
//! (`ADMIN_PASSWORD=x touch /tmp/owned` runs `touch`); values are checked
//! against an allow-list here instead.

/// How a console key takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apply {
    /// Applied by the running services as soon as `.env` changes.
    Live,
    /// Only takes effect when `bm.sh` recreates the containers (published
    /// ports, the container time zone, the Docker network, credentials the
    /// databases were created with). Go wrote these and restarted the core,
    /// which applied nothing and, for the HTTP ports, left the console
    /// listening on a port Docker does not publish.
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// Name the console uses (`set_system_config_key`).
    pub json: &'static str,
    /// Name in `.env`.
    pub env: &'static str,
    pub apply: Apply,
}

const fn key(json: &'static str, env: &'static str, apply: Apply) -> Key {
    Key { json, env, apply }
}

/// Go's `convertJsonKeyToEnvKey` table.
pub const KEYS: &[Key] = &[
    key("admin_username", "ADMIN_USERNAME", Apply::Live),
    key("admin_password", "ADMIN_PASSWORD", Apply::Live),
    key("safe_path", "SafePath", Apply::Live),
    key("billionmail_hostname", "BILLIONMAIL_HOSTNAME", Apply::Live),
    key("ip_whitelist_enable", "IP_WHITELIST_ENABLE", Apply::Live),
    key("retention_days", "RETENTION_DAYS", Apply::Live),
    key("db_name", "DBNAME", Apply::Host),
    key("db_user", "DBUSER", Apply::Host),
    key("db_pass", "DBPASS", Apply::Host),
    key("redis_pass", "REDISPASS", Apply::Host),
    key("redis_port", "REDIS_PORT", Apply::Host),
    key("smtp", "SMTP_PORT", Apply::Host),
    key("smtps", "SMTPS_PORT", Apply::Host),
    key("submission", "SUBMISSION_PORT", Apply::Host),
    key("imap", "IMAP_PORT", Apply::Host),
    key("imaps", "IMAPS_PORT", Apply::Host),
    key("pop", "POP_PORT", Apply::Host),
    key("pops", "POPS_PORT", Apply::Host),
    key("http", "HTTP_PORT", Apply::Host),
    key("https", "HTTPS_PORT", Apply::Host),
    key("timezone", "TZ", Apply::Host),
    key("ipv4_network", "IPV4_NETWORK", Apply::Host),
    key("fail2ban", "FAIL2BAN_INIT", Apply::Host),
];

/// Looks a console key up (any case, as Go lowercased it).
pub fn lookup(json: &str) -> Option<&'static Key> {
    let json = json.trim().to_ascii_lowercase();
    KEYS.iter().find(|k| k.json == json)
}

/// Go's `maxLength` for any value.
pub const MAX_VALUE_LEN: usize = 1024;

/// Characters a `.env` value may contain: nothing the shell treats
/// specially in `KEY=value` (no spaces, quotes, `$`, backticks, `;`, `&`,
/// `|`, redirections, parentheses, backslashes, `#` or `~`).
pub fn shell_safe(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_-.@%+=:,/^*?!".contains(&b))
}

/// Go's `IsValidHostname`: dot-separated labels of 1-63 letters, digits and
/// hyphens, not starting or ending with a hyphen, 255 characters at most.
pub fn is_valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Checks a value for `env_key` and returns it as it is stored. Messages
/// are Go's (`validateConfigValue`).
pub fn normalize(env_key: &str, value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.len() > MAX_VALUE_LEN {
        return Err("configuration value too long, maximum 1024 characters");
    }
    let value = match env_key {
        "ADMIN_USERNAME" => {
            if !(4..=32).contains(&value.len()) {
                return Err("admin username length must be between 4-32");
            }
            if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err("admin username can only contain letters, numbers and underscores");
            }
            value.to_owned()
        }
        "ADMIN_PASSWORD" => {
            if value.len() < 4 {
                return Err("password length must be at least 4 characters");
            }
            value.to_owned()
        }
        "SafePath" => {
            let path = crate::web::normalize_safe_path(value);
            if path.is_empty()
                || path.len() > 64
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(
                    "the security entrance can only contain letters, numbers, underscores and hyphens",
                );
            }
            path.to_owned()
        }
        "BILLIONMAIL_HOSTNAME" => {
            let host = value.trim_end_matches('.').to_ascii_lowercase();
            if !is_valid_hostname(&host) {
                return Err("hostname format is incorrect");
            }
            host
        }
        "IP_WHITELIST_ENABLE" => match value.to_ascii_lowercase().as_str() {
            "true" | "1" => "true".to_owned(),
            "false" | "0" => "false".to_owned(),
            _ => return Err("ip_whitelist_enable can only be true or false"),
        },
        "RETENTION_DAYS" => match value.parse::<u32>() {
            Ok(days) if (1..=3650).contains(&days) => days.to_string(),
            _ => return Err("retention_days must be a number"),
        },
        _ => value.to_owned(),
    };
    if !shell_safe(&value) {
        return Err("configuration value contains illegal characters");
    }
    Ok(value)
}

/// Shown in the audit log instead of the value.
pub fn is_secret(env_key: &str) -> bool {
    matches!(env_key, "ADMIN_PASSWORD" | "DBPASS" | "REDISPASS")
}

/// Settings for the blacklist alert mail (Go: `BlacklistAlertSettings`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AlertSettings {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub sender_email: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_server: String,
    #[serde(default)]
    pub smtp_port: i64,
    #[serde(default)]
    pub recipient_list: Vec<String>,
}

impl AlertSettings {
    /// Trims the fields, drops blank recipients and checks what Go checked
    /// (with Go's messages), plus that addresses and the host are well formed.
    pub fn validated(mut self) -> Result<Self, String> {
        self.name = self.name.trim().to_owned();
        self.sender_email = self.sender_email.trim().to_owned();
        self.smtp_server = self.smtp_server.trim().to_ascii_lowercase();
        self.recipient_list = self
            .recipient_list
            .iter()
            .map(|r| r.trim().to_owned())
            .filter(|r| !r.is_empty())
            .collect();
        if self.smtp_port == 0 {
            self.smtp_port = 587;
        }
        if self.sender_email.is_empty() {
            return Err("sender email is required".into());
        }
        if !crate::contacts::is_valid_email(&self.sender_email) {
            return Err("invalid sender email format".into());
        }
        if self.smtp_server.is_empty() {
            return Err("SMTP server is required".into());
        }
        if !is_valid_hostname(&self.smtp_server)
            && self.smtp_server.parse::<std::net::IpAddr>().is_err()
        {
            return Err("hostname format is incorrect".into());
        }
        if !(1..=65535).contains(&self.smtp_port) {
            return Err("SMTP port must be between 1 and 65535".into());
        }
        if self.smtp_password.is_empty() {
            return Err("SMTP password is required".into());
        }
        if self.recipient_list.is_empty() {
            return Err("at least one recipient is required".into());
        }
        if let Some(bad) = self
            .recipient_list
            .iter()
            .find(|r| !crate::contacts::is_valid_email(r))
        {
            return Err(format!("invalid recipient email format: {bad}"));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(lookup("Safe_Path").map(|k| k.env), Some("SafePath"));
        assert_eq!(lookup("https").map(|k| k.apply), Some(Apply::Host));
        assert!(lookup("nope").is_none());
        assert_eq!(
            KEYS.iter().filter(|k| k.apply == Apply::Live).count(),
            6,
            "the keys the console sends"
        );
    }

    #[test]
    fn values() {
        assert_eq!(
            normalize("ADMIN_USERNAME", " admin_1 ").as_deref(),
            Ok("admin_1")
        );
        assert!(normalize("ADMIN_USERNAME", "ab").is_err());
        assert!(normalize("ADMIN_USERNAME", "bad-name").is_err());
        assert_eq!(
            normalize("ADMIN_PASSWORD", "S3cret!pass").as_deref(),
            Ok("S3cret!pass")
        );
        // Go let these through to `source .env`.
        for evil in [
            "x touch /tmp/p",
            "pass'word",
            "pass\"word",
            "$(id)xx",
            "`id`xx",
            "pass;word",
            "pass#word",
            "~rootpw",
            "pass\\word",
        ] {
            assert_eq!(
                normalize("ADMIN_PASSWORD", evil),
                Err("configuration value contains illegal characters"),
                "{evil}"
            );
        }
        assert_eq!(normalize("SafePath", "/abc-12").as_deref(), Ok("abc-12"));
        assert!(normalize("SafePath", "a/b").is_err());
        assert!(normalize("SafePath", "/").is_err());
        assert_eq!(
            normalize("BILLIONMAIL_HOSTNAME", "Mail.Example.com.").as_deref(),
            Ok("mail.example.com")
        );
        assert!(normalize("BILLIONMAIL_HOSTNAME", "-a.com").is_err());
        assert!(normalize("BILLIONMAIL_HOSTNAME", "a..com").is_err());
        assert_eq!(normalize("IP_WHITELIST_ENABLE", "1").as_deref(), Ok("true"));
        assert!(normalize("IP_WHITELIST_ENABLE", "yes").is_err());
        assert_eq!(normalize("RETENTION_DAYS", "30").as_deref(), Ok("30"));
        assert!(normalize("RETENTION_DAYS", "-1").is_err());
        assert!(normalize("ADMIN_PASSWORD", &"a".repeat(1025)).is_err());
    }

    #[test]
    fn alert_settings() {
        let ok = AlertSettings {
            name: " Alerts ".into(),
            sender_email: "a@x.test".into(),
            smtp_password: "p".into(),
            smtp_server: "smtp.x.test".into(),
            smtp_port: 0,
            recipient_list: vec!["b@x.test".into(), " ".into()],
        }
        .validated()
        .expect("valid");
        assert_eq!((ok.smtp_port, ok.recipient_list.len()), (587, 1));
        let bad = AlertSettings {
            recipient_list: vec!["nope".into()],
            ..ok.clone()
        };
        assert_eq!(
            bad.validated(),
            Err("invalid recipient email format: nope".to_owned())
        );
    }
}
