//! SMTP relays (Go: `service/relay`): what Postfix needs to send a sender
//! domain's mail through another provider, as text for its files.
//!
//! Postfix reads three places: a transport per relay in `master.cf`, the
//! relay maps and SASL password files named in `main.cf`, and two pgsql
//! maps that pick the relay for a sender domain.

use aes::Aes128;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

/// A relay as stored in `bm_relay_config` (`auth_password` encrypted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relay {
    pub id: i64,
    pub relay_host: String,
    pub relay_port: String,
    pub auth_user: String,
    pub auth_method: String,
    pub helo_name: String,
    pub smtp_name: String,
    pub skip_tls_verify: bool,
}

/// Name Go gave relays created without a name of their own.
pub const GENERIC_NAME: &str = "Custom SMTP Relay";
/// Postfix keeps service names short (they become socket paths).
const MAX_SERVICE_NAME: usize = 64;

fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut gap = false;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            gap = false;
        } else if !gap {
            out.push('_');
            gap = true;
        }
    }
    out
}

/// Go's `generateSmtpServiceName`: `smtp_Custom_<name>` for a named relay,
/// else `smtp_Relay_<host>[_<user>]_<id>`; too long names keep a hash and
/// the ID. Unlike Go, a relay without a name is treated as unnamed (Go
/// gave every one of them the same `smtp_Custom_`).
pub fn service_name(relay: &Relay) -> String {
    let name = relay.smtp_name.trim();
    let full = if !name.is_empty() && name != GENERIC_NAME {
        format!("smtp_Custom_{}", clean(name))
    } else {
        let host = clean(&relay.relay_host);
        let user = match relay.auth_user.split_once('@') {
            Some((local, _)) => clean(local),
            None => {
                let head = relay.auth_user.as_bytes();
                clean(&String::from_utf8_lossy(&head[..head.len().min(5)]))
            }
        };
        if user.is_empty() {
            format!("smtp_Relay_{host}_{}", relay.id)
        } else {
            format!("smtp_Relay_{host}_{user}_{}", relay.id)
        }
    };
    truncate(&full)
}

fn truncate(name: &str) -> String {
    if name.len() <= MAX_SERVICE_NAME {
        return name.to_owned();
    }
    let suffix = name
        .rfind('_')
        .filter(|i| *i > 0)
        .map_or("", |i| &name[i..]);
    let hash = hex::encode(Sha256::digest(name.as_bytes()));
    let prefix = if name.starts_with("smtp_Custom_") {
        "smtp_Custom"
    } else if name.starts_with("smtp_Relay_") {
        "smtp_Relay"
    } else {
        "smtp"
    };
    let mut out = format!("{prefix}_{}{suffix}", &hash[..12]);
    out.truncate(MAX_SERVICE_NAME);
    out
}

/// Service names for `relays`, made unique: two relays with the same name
/// would otherwise define one Postfix service twice (Go let that happen).
pub fn service_names(relays: &[Relay]) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(relays.len());
    for relay in relays {
        let mut name = service_name(relay);
        if names.contains(&name) {
            name = truncate(&format!("{name}_{}", relay.id));
        }
        names.push(name);
    }
    names
}

pub const MASTER_BEGIN: &str = "# BEGIN BILLIONMAIL RELAY CONFIG - DO NOT EDIT THIS MARKER";
pub const MASTER_END: &str = "# END BILLIONMAIL RELAY CONFIG - DO NOT EDIT THIS MARKER";
const SMTPS_BEGIN: &str = "# BEGIN BILLIONMAIL SMTPS CONFIG - DO NOT EDIT THIS MARKER";
const SMTPS_END: &str = "# END BILLIONMAIL SMTPS CONFIG - DO NOT EDIT THIS MARKER";
const SMTPS_SERVICE: &str = "smtps     unix  -       -       n       -       -       smtp
    -o smtp_tls_wrappermode=yes
    -o smtp_tls_security_level=encrypt";
pub const MAIN_BEGIN: &str = "# BEGIN RELAY SERVICE CONFIGURATION - DO NOT EDIT THIS MARKER";
pub const MAIN_END: &str = "# END RELAY SERVICE CONFIGURATION - DO NOT EDIT THIS MARKER";

/// The transports block of `master.cf`, one service per relay. Differences
/// from Go: port 25 uses TLS when the relay offers it (Go turned TLS off, so
/// the relay password went out in clear), and each option appears once.
pub fn master_block(relays: &[Relay]) -> String {
    let mut block = format!("{MASTER_BEGIN}\n");
    if relays.is_empty() {
        block.push_str("# No active relay configurations\n");
    }
    for (relay, name) in relays.iter().zip(service_names(relays)) {
        let mut options: Vec<String> = Vec::new();
        if !relay.helo_name.is_empty() {
            options.push(format!("smtp_helo_name={}", relay.helo_name));
        }
        match relay.relay_port.as_str() {
            "465" => options.extend([
                "smtp_tls_wrappermode=yes".to_owned(),
                "smtp_tls_security_level=encrypt".to_owned(),
            ]),
            "587" => options.extend([
                "smtp_tls_security_level=encrypt".to_owned(),
                "smtp_tls_wrappermode=no".to_owned(),
            ]),
            "25" => options.extend([
                "smtp_tls_wrappermode=no".to_owned(),
                "smtp_tls_security_level=may".to_owned(),
            ]),
            _ => {}
        }
        let method = relay.auth_method.to_ascii_uppercase();
        if relay.auth_user.is_empty() || method == "NONE" {
            if !relay.auth_user.is_empty() {
                options.push("smtp_sasl_auth_enable=no".to_owned());
            }
        } else {
            let filter = match method.as_str() {
                "LOGIN" => "login",
                "PLAIN" => "plain",
                "CRAM-MD5" => "cram-md5",
                _ => "login,plain,cram-md5",
            };
            options.extend([
                "smtp_sasl_auth_enable=yes".to_owned(),
                "smtp_sasl_security_options=noanonymous".to_owned(),
                format!("smtp_sasl_mechanism_filter={filter}"),
            ]);
        }
        if relay.skip_tls_verify {
            options.push("smtp_tls_verify_cert_match=no".to_owned());
        }
        block.push_str(&format!("{name} unix - - n - - smtp"));
        for option in options {
            block.push_str(&format!("\n  -o {option}"));
        }
        block.push('\n');
    }
    block.push_str(&format!("{MASTER_END}\n"));
    block
}

/// Replaces the marked block (and the blank line after it) or appends it.
fn put_block(content: &str, begin: &str, end: &str, block: &str) -> String {
    match (content.find(begin), content.find(end)) {
        (Some(b), Some(e)) if b < e => {
            let mut after = e + end.len();
            let bytes = content.as_bytes();
            if after < bytes.len() && (bytes[after] == b'\n' || bytes[after] == b'\r') {
                after += 1;
                if after < bytes.len() && bytes[after] == b'\n' {
                    after += 1;
                }
            }
            format!("{}{block}{}", &content[..b], &content[after..])
        }
        _ => {
            let mut out = content.to_owned();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(block);
            out
        }
    }
}

/// `master.cf` with the relay transports and Go's `smtps` service.
pub fn apply_master(content: &str, relays: &[Relay]) -> String {
    let content = ensure_smtps(content);
    put_block(&content, MASTER_BEGIN, MASTER_END, &master_block(relays))
}

/// Go's `ensureSmtpsConfigInMasterCf`.
fn ensure_smtps(content: &str) -> String {
    let block = format!("{SMTPS_BEGIN}\n{SMTPS_SERVICE}\n{SMTPS_END}\n");
    match (content.find(SMTPS_BEGIN), content.find(SMTPS_END)) {
        (Some(b), Some(e)) if b < e => {
            if content[b..e].contains(SMTPS_SERVICE) {
                return content.to_owned();
            }
            let mut after = e + SMTPS_END.len();
            while after < content.len() && matches!(content.as_bytes()[after], b'\n' | b'\r') {
                after += 1;
            }
            format!("{}{block}{}", &content[..b], &content[after..])
        }
        _ => {
            let mut out = content.to_owned();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
            out.push_str(&block);
            out
        }
    }
}

fn main_block() -> String {
    format!(
        "{MAIN_BEGIN}
sender_dependent_relayhost_maps = hash:/etc/postfix/conf/sender_relay_maps_primary, pgsql:/etc/postfix/sql/pgsql_sender_relay_maps.cf
smtp_sasl_password_maps = hash:/etc/postfix/conf/sasl_passwd_primary, hash:/etc/postfix/conf/sasl_passwd
sender_dependent_default_transport_maps = pgsql:/etc/postfix/sql/pgsql_sender_transport_maps.cf
{MAIN_END}"
    )
}

/// `main.cf` with the relay maps switched on or off (Go's
/// `writePostfixRelayConfig`).
pub fn apply_main(content: &str, enabled: bool) -> String {
    let found = match (content.find(MAIN_BEGIN), content.find(MAIN_END)) {
        (Some(b), Some(e)) if b < e => Some((b, e)),
        _ => None,
    };
    match (enabled, found) {
        (true, None) => {
            let mut out = content.to_owned();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&main_block());
            out.push('\n');
            out
        }
        (false, Some((b, e))) => {
            let out = format!("{}{}", &content[..b], &content[e + MAIN_END.len()..]);
            format!("{}\n", out.trim_end_matches('\n'))
        }
        _ => content.to_owned(),
    }
}

/// Go's one-off migration (`CheckRelayFirstSync`): comments out
/// `sender_dependent_default_transport_maps` lines added by hand outside
/// the managed block, then drops the block so the sync writes it afresh.
pub fn migrate_main(content: &str) -> String {
    let block = match (content.find(MAIN_BEGIN), content.find(MAIN_END)) {
        (Some(b), Some(e)) if b < e => Some((b, e + MAIN_END.len())),
        _ => None,
    };
    let mut out = String::with_capacity(content.len());
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let inside = block.is_some_and(|(b, e)| offset >= b && offset <= e);
        let body = line.trim_end_matches(['\n', '\r']);
        let trimmed = body.trim_start();
        let manual = trimmed.starts_with("sender_dependent_default_transport_maps")
            && trimmed.split_once('=').is_some_and(|(k, v)| {
                k.trim() == "sender_dependent_default_transport_maps"
                    && ["hash:", "pgsql:", "tcp:"]
                        .iter()
                        .any(|t| v.trim_start().starts_with(t))
            });
        if manual && !inside {
            out.push_str(&format!(
                "# {body} # Migrated: replaced by automated config block{}",
                &line[body.len()..]
            ));
        } else {
            out.push_str(line);
        }
        offset += line.len();
    }
    match (out.find(MAIN_BEGIN), out.find(MAIN_END)) {
        (Some(b), Some(e)) if b < e => {
            let mut after = e + MAIN_END.len();
            if out.as_bytes().get(after) == Some(&b'\n') {
                after += 1;
            }
            format!("{}{}", &out[..b], &out[after..])
        }
        _ => out,
    }
}

/// A relay's login for `sasl_passwd`, password in clear.
pub struct Login<'a> {
    pub host: &'a str,
    pub port: &'a str,
    pub user: &'a str,
    pub password: &'a str,
}

/// `conf/sasl_passwd`: `[host]:port user:password` per relay that logs in.
pub fn sasl_passwd(any_active: bool, logins: &[Login<'_>]) -> String {
    if !any_active {
        return "# No active relay configurations\n".to_owned();
    }
    if logins.is_empty() {
        return "# No relay configurations require authentication\n".to_owned();
    }
    logins
        .iter()
        .map(|l| format!("[{}]:{} {}:{}\n", l.host, l.port, l.user, l.password))
        .collect()
}

/// The pgsql maps Postfix queries for a sender's relay and transport.
pub fn sql_maps(user: &str, password: &str, dbname: &str) -> [(&'static str, String); 2] {
    let head =
        format!("user = {user}\npassword = {password}\nhosts = pgsql\ndbname = {dbname}\n\n");
    [
        (
            "pgsql_sender_relay_maps.cf",
            format!(
                "{head}query = SELECT CONCAT('[', rc.relay_host, ']:', rc.relay_port) FROM bm_relay_config rc JOIN bm_relay_domain_mapping rdm ON rc.id = rdm.relay_id WHERE rdm.sender_domain = REPLACE('%s', '@', '') AND rc.active = 1 LIMIT 1"
            ),
        ),
        (
            "pgsql_sender_transport_maps.cf",
            format!(
                "{head}query = SELECT CONCAT(smtp_name, ':') FROM bm_domain_smtp_transport WHERE domain = '%s' LIMIT 1"
            ),
        ),
    ]
}

/// The SPF record a domain needs once it also sends through a relay at
/// `ip` or `include_host` (Go's `GenerateSPFRecord`): the server's own
/// record (`base`) with the relay added before the `all` mechanism.
pub fn spf_with_relay(base: &str, ip: &str, include_host: &str) -> String {
    let base = if base.trim().is_empty() {
        "v=spf1 +a +mx"
    } else {
        base
    };
    let parts: Vec<&str> = base.split_whitespace().collect();
    let mut out: Vec<String> = Vec::new();
    let mut all = None;
    for part in &parts {
        if part.ends_with("all") {
            all = Some(*part);
            continue;
        }
        if !part.starts_with("include:") && !part.starts_with("ip4:") && !part.starts_with("ip6:") {
            out.push((*part).to_owned());
        }
    }
    if !ip.is_empty() {
        let mechanism = if ip.contains(':') {
            format!("+ip6:{ip}")
        } else {
            format!("+ip4:{ip}")
        };
        if !parts.contains(&mechanism.as_str()) {
            out.push(mechanism);
        }
    }
    if !include_host.is_empty() {
        let mechanism = format!("include:{include_host}");
        if !parts.contains(&mechanism.as_str()) {
            out.push(mechanism);
        }
    }
    out.push(all.unwrap_or("~all").to_owned());
    out.join(" ")
}

/// The server's own SPF record (Go's `GetSPFRecord`).
pub fn server_spf(server_ip: Option<std::net::IpAddr>) -> String {
    match server_ip {
        Some(std::net::IpAddr::V6(ip)) => format!("v=spf1 +a +mx +ip6:{ip} -all"),
        Some(ip) => format!("v=spf1 +a +mx +ip4:{ip} -all"),
        None => String::new(),
    }
}

/// Whether a published SPF record authorises the relay (Go checked `ip4:`
/// even for IPv6 relays).
pub fn spf_covers(record: &str, ip: &str, include_host: &str) -> bool {
    if !ip.is_empty() {
        let kind = if ip.contains(':') { "ip6" } else { "ip4" };
        return record.contains(&format!("{kind}:{ip}"));
    }
    !include_host.is_empty() && record.contains(&format!("include:{include_host}"))
}

/// Go's `GetRelayEncryptionKey` key: the first 16 bytes of the hex option.
pub fn password_key(hex_key: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_key.trim()).ok()?;
    bytes.get(..16)?.try_into().ok()
}

/// GoFrame's `gaes` default IV, which Go used for every relay password.
const GO_IV: &[u8; 16] = b"I Love Go Frame!";

/// Encrypts a relay password as Go stored it (AES-128-CBC, hex), so the
/// Go core can still read it while it runs.
pub fn encrypt_password(key: &[u8; 16], password: &str) -> String {
    let encrypted = cbc::Encryptor::<Aes128>::new(key.into(), GO_IV.into())
        .encrypt_padded_vec_mut::<Pkcs7>(password.as_bytes());
    hex::encode(encrypted)
}

pub fn decrypt_password(key: &[u8; 16], stored: &str) -> Option<String> {
    if stored.is_empty() {
        return Some(String::new());
    }
    let bytes = hex::decode(stored.trim()).ok()?;
    let plain = cbc::Decryptor::<Aes128>::new(key.into(), GO_IV.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&bytes)
        .ok()?;
    String::from_utf8(plain).ok()
}

/// A relay host or HELO name: a host name or an IP address. These end up
/// in Postfix files, where Go copied any text (a line break in the HELO
/// name added options to `master.cf`).
pub fn valid_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok() || crate::settings::is_valid_hostname(host)
}

/// A login value for `sasl_passwd`: printable, no spaces in the user name,
/// no `:` in it either (it separates user and password).
pub fn valid_login(user: &str, password: &str) -> bool {
    let printable = |s: &str| s.chars().all(|c| !c.is_control());
    printable(user)
        && printable(password)
        && !user.contains(char::is_whitespace)
        && !user.contains(':')
        && user.len() <= 255
        && password.len() <= 255
}

/// rspamd's `local.d/dkim_signing.conf` for the domains it signs, as Go
/// leaves it (`RepairDKIMSigningConfig`, then `FixRspamdDKIMSigningConfig`
/// adding `use_esld = false`: without it rspamd looks a subdomain's key up
/// under its parent domain, so a hosted subdomain would go unsigned).
pub fn dkim_signing_conf(domains: &[String]) -> String {
    let blocks: String = domains
        .iter()
        .map(|d| {
            format!(
                "
#{d}_DKIM_BEGIN
{d} {{
   selectors [
    {{
      path: \"/var/lib/rspamd/dkim/{d}/default.private\";
      selector: \"default\";
    }},
    {{
      path: \"/var/lib/rspamd/dkim/{d}/short.private\";
      selector: \"short\";
    }}
  ]
}}
#{d}_DKIM_END
"
            )
        })
        .collect();
    format!(
        r#"sign_headers = "from:sender:reply-to:subject:date:message-id:to:cc:mime-version:content-type:content-transfer-encoding:content-language:resent-to:resent-cc:resent-from:resent-sender:resent-message-id:in-reply-to:references:list-id:list-help:list-owner:list-unsubscribe:list-subscribe:list-post:list-unsubscribe-post:disposition-notification-to:disposition-notification-options:original-recipient:openpgp:autocrypt";

use_esld = false;

domain {{
#BT_DOMAIN_DKIM_BEGIN
{blocks}
#BT_DOMAIN_DKIM_END
}}"#
    )
}

/// The domains a `dkim_signing.conf` signs, from its `#<domain>_DKIM_BEGIN`
/// markers.
pub fn dkim_signed_domains(conf: &str) -> Vec<String> {
    let mut domains: Vec<String> = conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix('#')?.strip_suffix("_DKIM_BEGIN"))
        .filter(|d| *d != "BT_DOMAIN")
        .map(str::to_owned)
        .collect();
    domains.sort();
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(id: i64, name: &str, host: &str, port: &str, user: &str) -> Relay {
        Relay {
            id,
            relay_host: host.into(),
            relay_port: port.into(),
            auth_user: user.into(),
            auth_method: "LOGIN".into(),
            smtp_name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn service_names_like_go() {
        assert_eq!(
            service_name(&relay(3, "AWS SES (Tokyo)", "h", "587", "u")),
            "smtp_Custom_AWS_SES_Tokyo_"
        );
        assert_eq!(
            service_name(&relay(
                7,
                GENERIC_NAME,
                "email-smtp.x.com",
                "587",
                "bob@x.com"
            )),
            "smtp_Relay_email_smtp_x_com_bob_7"
        );
        assert_eq!(
            service_name(&relay(8, GENERIC_NAME, "1.2.3.4", "25", "abcdefgh")),
            "smtp_Relay_1_2_3_4_abcde_8"
        );
        let long = service_name(&relay(42, GENERIC_NAME, &"a".repeat(80), "25", ""));
        assert!(long.len() <= 64 && long.starts_with("smtp_Relay_") && long.ends_with("_42"));
        let twins = service_names(&[
            relay(1, "Gmail", "a", "587", ""),
            relay(2, "Gmail", "b", "587", ""),
        ]);
        assert_eq!(twins, ["smtp_Custom_Gmail", "smtp_Custom_Gmail_2"]);
    }

    #[test]
    fn postfix_files() {
        let relays = [
            relay(1, "SES", "email-smtp.x.com", "587", "AKIA"),
            Relay {
                helo_name: "mail.example.com".into(),
                auth_method: String::new(),
                ..relay(2, "Plain", "10.0.0.5", "25", "")
            },
        ];
        let master = apply_master("smtp inet n - n - - smtpd\n", &relays);
        assert!(master.contains(
            "smtp_Custom_SES unix - - n - - smtp\n  -o smtp_tls_security_level=encrypt\n  -o smtp_tls_wrappermode=no\n  -o smtp_sasl_auth_enable=yes\n  -o smtp_sasl_security_options=noanonymous\n  -o smtp_sasl_mechanism_filter=login\n"
        ), "{master}");
        assert!(master.contains(
            "smtp_Custom_Plain unix - - n - - smtp\n  -o smtp_helo_name=mail.example.com\n  -o smtp_tls_wrappermode=no\n  -o smtp_tls_security_level=may\n"
        ));
        assert!(master.contains(SMTPS_SERVICE));
        // Applying again changes nothing; removing every relay keeps the markers.
        assert_eq!(apply_master(&master, &relays), master);
        let none = apply_master(&master, &[]);
        assert!(
            none.contains("# No active relay configurations") && !none.contains("smtp_Custom_SES")
        );
        assert_eq!(none.matches(MASTER_BEGIN).count(), 1);

        let main = apply_main("myhostname = x\n", true);
        assert!(main.ends_with(&format!("{MAIN_END}\n")));
        assert_eq!(apply_main(&main, true), main);
        assert_eq!(apply_main(&main, false), "myhostname = x\n");

        assert_eq!(
            sasl_passwd(
                true,
                &[Login {
                    host: "h",
                    port: "587",
                    user: "u",
                    password: "p:w"
                }]
            ),
            "[h]:587 u:p:w\n"
        );
        assert_eq!(
            sasl_passwd(false, &[]),
            "# No active relay configurations\n"
        );
    }

    #[test]
    fn first_sync_migration() {
        let content = format!(
            "a = 1\nsender_dependent_default_transport_maps = hash:/etc/postfix/old\n#sender_dependent_default_transport_maps = tcp:x\n{MAIN_BEGIN}\nsender_dependent_default_transport_maps = pgsql:/x\n{MAIN_END}\nb = 2\n"
        );
        assert_eq!(
            migrate_main(&content),
            "a = 1\n# sender_dependent_default_transport_maps = hash:/etc/postfix/old # Migrated: replaced by automated config block\n#sender_dependent_default_transport_maps = tcp:x\nb = 2\n"
        );
    }

    #[test]
    fn spf_like_go() {
        let base = server_spf(Some("203.0.113.1".parse().expect("ip")));
        assert_eq!(base, "v=spf1 +a +mx +ip4:203.0.113.1 -all");
        assert_eq!(
            spf_with_relay(&base, "", "amazonses.com"),
            "v=spf1 +a +mx +ip4:203.0.113.1 include:amazonses.com -all"
        );
        assert_eq!(
            spf_with_relay("", "2001:db8::1", ""),
            "v=spf1 +a +mx +ip6:2001:db8::1 ~all"
        );
        assert!(spf_covers("v=spf1 ip6:2001:db8::1 -all", "2001:db8::1", ""));
        assert!(!spf_covers("v=spf1 -all", "", "x.com"));
    }

    #[test]
    fn passwords_like_gaes() {
        let key = password_key("00112233445566778899aabbccddeeff").expect("key");
        let stored = encrypt_password(&key, "s3cret:pw");
        // `openssl enc -aes-128-cbc` with the same key and Go's IV.
        assert_eq!(stored, "8c6caf6a4eab1b0bb98fe56f06a05c80");
        assert_eq!(
            decrypt_password(&key, &stored).as_deref(),
            Some("s3cret:pw")
        );
        assert_eq!(decrypt_password(&key, "zz"), None);
        assert!(password_key("abcd").is_none());
    }

    #[test]
    fn checks() {
        assert!(valid_host("smtp.sendgrid.net") && valid_host("10.0.0.1") && valid_host("::1"));
        assert!(!valid_host("mail.x.com\n  -o content_filter=evil"));
        assert!(!valid_host("a b"));
        assert!(valid_login("apikey", "p@ss word:1"));
        assert!(!valid_login("a:b", "p") && !valid_login("a", "p\nx") && !valid_login("a b", "p"));
    }

    #[test]
    fn dkim_conf() {
        let conf = dkim_signing_conf(&["a.com".to_owned()]);
        assert!(conf.contains("#a.com_DKIM_BEGIN\na.com {"));
        assert!(conf.contains("path: \"/var/lib/rspamd/dkim/a.com/short.private\";"));
        assert!(conf.ends_with("#BT_DOMAIN_DKIM_END\n}"));
        assert!(conf.contains("\";\n\nuse_esld = false;\n\ndomain {\n"));
        let both = dkim_signing_conf(&["b.com".to_owned(), "a.com".to_owned()]);
        assert_eq!(dkim_signed_domains(&both), ["a.com", "b.com"]);
    }
}
