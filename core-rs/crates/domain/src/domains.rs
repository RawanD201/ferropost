//! Sending domains (Go: `service/domains`): what a domain's DNS must say,
//! how to tell it does, and the files rspamd keeps its DKIM keys in.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Mailboxes made with every new domain (Go's list).
pub const SYSTEM_MAILBOXES: [&str; 5] = ["abuse", "postmaster", "admin", "noreply", "support"];
/// Their quota (Go's).
pub const SYSTEM_MAILBOX_QUOTA: i64 = 5_242_880;

/// Defaults of the domain form (Go's `AddDomainReq`).
pub const DEFAULT_MAILBOXES: i64 = 50;
pub const DEFAULT_MAILBOX_QUOTA: i64 = 5_242_880;
pub const DEFAULT_QUOTA: i64 = 10_485_760;
pub const DEFAULT_RATE_LIMIT: i64 = 12;

/// The keys rspamd signs with: selector and RSA size (Go's).
pub const DKIM_SELECTORS: [(&str, usize); 2] = [("default", 2048), ("short", 1024)];

const MAX_URLS: usize = 10;
const MAX_URL_LEN: usize = 2048;

/// One record the console asks for (Go's `DNSRecord`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub kind: String,
    pub host: String,
    pub value: String,
    pub valid: bool,
}

/// Every record of a domain (Go's `DNSRecords`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecords {
    pub spf: DnsRecord,
    pub dkim: DnsRecord,
    pub dkim_short: DnsRecord,
    pub dmarc: DnsRecord,
    pub mx: DnsRecord,
    pub a: DnsRecord,
    pub ptr: DnsRecord,
}

/// What the records are made from.
pub struct Setup<'a> {
    pub domain: &'a str,
    /// Its mail host (`a_record`).
    pub mail_host: &'a str,
    /// The server's public address, when known.
    pub server_ip: Option<IpAddr>,
    /// The domain's dedicated sending address, if it has one.
    pub dedicated_ip: Option<IpAddr>,
    /// TXT values of its DKIM keys (`default`, `short`), when present.
    pub dkim: Option<&'a str>,
    pub dkim_short: Option<&'a str>,
}

impl Setup<'_> {
    /// The address mail for the domain leaves from.
    pub fn sending_ip(&self) -> Option<IpAddr> {
        self.dedicated_ip.or(self.server_ip)
    }
}

fn record(kind: &str, host: &str, value: String) -> DnsRecord {
    DnsRecord {
        kind: kind.to_owned(),
        host: host.to_owned(),
        value,
        valid: false,
    }
}

fn spf_term(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("+ip4:{v4}"),
        IpAddr::V6(v6) => format!("+ip6:{v6}"),
    }
}

/// The records a domain needs, not yet checked. As Go's, except that a
/// dedicated sending address is in the SPF and PTR records too (Go only
/// used it for the A record, so the PTR record it asked for was the shared
/// address's).
pub fn expected(setup: &Setup<'_>) -> DnsRecords {
    let mut spf = String::from("v=spf1 +a +mx");
    for ip in [setup.server_ip, setup.dedicated_ip]
        .into_iter()
        .flatten()
        .fold(Vec::new(), |mut seen: Vec<IpAddr>, ip| {
            if !seen.contains(&ip) {
                seen.push(ip);
            }
            seen
        })
    {
        spf.push(' ');
        spf.push_str(&spf_term(ip));
    }
    spf.push_str(" -all");
    let sending = setup.sending_ip();
    let address_kind = match sending {
        Some(IpAddr::V6(_)) => "AAAA",
        _ => "A",
    };
    DnsRecords {
        spf: record("TXT", "@", spf),
        dkim: record(
            "TXT",
            "default._domainkey",
            setup.dkim.unwrap_or_default().to_owned(),
        ),
        dkim_short: record(
            "TXT",
            "short._domainkey",
            setup.dkim_short.unwrap_or_default().to_owned(),
        ),
        dmarc: record(
            "TXT",
            "_dmarc",
            format!("v=DMARC1;p=quarantine;rua=mailto:admin@{}", setup.domain),
        ),
        mx: record("MX", "@", setup.mail_host.to_owned()),
        a: record(
            address_kind,
            setup.mail_host,
            sending.map(|ip| ip.to_string()).unwrap_or_default(),
        ),
        ptr: record(
            "PTR",
            &sending.map(|ip| ip.to_string()).unwrap_or_default(),
            setup.mail_host.to_owned(),
        ),
    }
}

/// Whether two host names are the same (case and a final dot aside; Go
/// compared them as text).
pub fn same_host(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// `tag=value` pairs of a DKIM or DMARC record, tags lower-cased.
fn tags(record: &str) -> Vec<(String, String)> {
    record
        .split(';')
        .filter_map(|part| {
            let (tag, value) = part.split_once('=')?;
            Some((tag.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}

fn tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(t, _)| t == name)
        .map(|(_, v)| v.as_str())
}

fn without_spaces(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Whether a published TXT record carries the expected DKIM key. Tags are
/// compared, not text: Go wanted the exact text, so a record written with
/// other spacing, without `v=`, or with extra tags looked missing.
pub fn dkim_published(records: &[String], expected: &str) -> bool {
    let wanted = tags(expected);
    let Some(key) = tag(&wanted, "p")
        .map(without_spaces)
        .filter(|k| !k.is_empty())
    else {
        return false;
    };
    let kind = tag(&wanted, "k").unwrap_or("rsa");
    records.iter().any(|published| {
        let found = tags(published);
        tag(&found, "v").is_none_or(|v| v.eq_ignore_ascii_case("DKIM1"))
            && tag(&found, "k").unwrap_or("rsa").eq_ignore_ascii_case(kind)
            && tag(&found, "p").map(without_spaces).as_deref() == Some(key.as_str())
    })
}

/// Whether the domain publishes one usable DMARC policy. Go accepted any
/// record starting with `v=DMARC1` (it tested the expected value, not the
/// published one), even two of them, which leaves a domain without DMARC.
pub fn dmarc_published(records: &[String]) -> bool {
    let policies: Vec<Vec<(String, String)>> = records
        .iter()
        .map(|r| tags(r))
        .filter(|t| {
            t.first()
                .is_some_and(|(tag, v)| tag == "v" && v.eq_ignore_ascii_case("DMARC1"))
        })
        .collect();
    match policies.as_slice() {
        [one] => tag(one, "p").is_some_and(|p| {
            ["none", "quarantine", "reject"]
                .iter()
                .any(|known| p.eq_ignore_ascii_case(known))
        }),
        _ => false,
    }
}

/// The TXT value of a DKIM key (`v=DKIM1; k=rsa; p=...`).
pub fn dkim_value(public_key_b64: &str) -> String {
    format!("v=DKIM1; k=rsa; p={public_key_b64}")
}

/// A `.pub` file as `rspamadm dkim_keygen` writes it (a zone-file record
/// split into quoted strings), which Go read back.
pub fn dkim_pub_file(selector: &str, public_key_b64: &str) -> String {
    let mut out = format!("{selector}._domainkey IN TXT ( \"v=DKIM1; k=rsa; \"\n");
    let mut rest = format!("p={public_key_b64}");
    while !rest.is_empty() {
        let cut = rest.len().min(250);
        out.push_str(&format!("\t\"{}\"\n", &rest[..cut]));
        rest.drain(..cut);
    }
    out.push_str(") ;\n");
    out
}

/// The TXT value in a `.pub` file: rspamadm's quoted strings joined, or a
/// PEM public key (both of which Go read).
pub fn dkim_value_from_pub(content: &str) -> Option<String> {
    if content.contains('"') {
        let mut joined = String::new();
        let mut parts = content.split('"');
        parts.next();
        while let Some(inside) = parts.next() {
            if !inside.contains(['\r', '\n']) {
                joined.push_str(inside);
            }
            parts.next();
        }
        let joined = joined.trim().to_owned();
        return tag(&tags(&joined), "p")
            .is_some_and(|p| !p.is_empty())
            .then_some(joined);
    }
    if content.contains("BEGIN PUBLIC KEY") {
        let key: String = content
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.trim().chars())
            .collect();
        return (!key.is_empty()).then(|| dkim_value(&key));
    }
    let line = content.trim();
    tag(&tags(line), "p")
        .is_some_and(|p| !p.is_empty())
        .then(|| line.to_owned())
}

/// A domain name as the console accepts it (GoFrame's `domain` rule): two
/// or more labels, the last one letters (or an IDN `xn--` label).
pub fn is_domain_name(name: &str) -> bool {
    crate::settings::is_valid_hostname(name)
        && name.contains('.')
        && name.rsplit('.').next().is_some_and(|tld| {
            tld.len() >= 2
                && (tld.bytes().all(|b| b.is_ascii_alphabetic())
                    || (tld.starts_with("xn--")
                        && tld.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')))
        })
}

/// The brand URLs of a domain: blank entries and a lone scheme (what the
/// form starts with) dropped; the rest must be `http`/`https` links.
pub fn clean_urls(urls: &[String]) -> Result<Vec<String>, String> {
    let mut cleaned = Vec::new();
    for url in urls {
        let url = url.trim();
        let lower = url.to_ascii_lowercase();
        let rest = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"));
        match rest {
            _ if url.is_empty() => continue,
            Some("") => continue,
            Some(rest)
                if url.len() <= MAX_URL_LEN
                    && !rest.starts_with('/')
                    && !url.chars().any(|c| c.is_whitespace() || c.is_control()) =>
            {
                if !cleaned.iter().any(|u| u == url) {
                    cleaned.push(url.to_owned());
                }
            }
            _ => return Err(format!("`{url}` is not an http or https link")),
        }
    }
    if cleaned.len() > MAX_URLS {
        return Err(format!("at most {MAX_URLS} links are allowed"));
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup<'a>(dedicated: Option<&str>) -> Setup<'a> {
        Setup {
            domain: "ex.test",
            mail_host: "mail.ex.test",
            server_ip: Some("198.51.100.1".parse().expect("ip")),
            dedicated_ip: dedicated.map(|d| d.parse().expect("ip")),
            dkim: Some("v=DKIM1; k=rsa; p=AAAA"),
            dkim_short: None,
        }
    }

    #[test]
    fn expected_records() {
        let r = expected(&setup(None));
        assert_eq!(r.spf.value, "v=spf1 +a +mx +ip4:198.51.100.1 -all");
        assert_eq!(
            (r.a.kind.as_str(), r.a.host.as_str(), r.a.value.as_str()),
            ("A", "mail.ex.test", "198.51.100.1")
        );
        assert_eq!(
            (r.mx.host.as_str(), r.mx.value.as_str()),
            ("@", "mail.ex.test")
        );
        assert_eq!(
            r.dmarc.value,
            "v=DMARC1;p=quarantine;rua=mailto:admin@ex.test"
        );
        assert_eq!(
            (r.ptr.host.as_str(), r.ptr.value.as_str()),
            ("198.51.100.1", "mail.ex.test")
        );
        assert_eq!(r.dkim.host, "default._domainkey");
        assert_eq!(r.dkim.value, "v=DKIM1; k=rsa; p=AAAA");
        assert_eq!(
            (r.dkim_short.host.as_str(), r.dkim_short.value.as_str()),
            ("short._domainkey", "")
        );
        assert!(!r.spf.valid);

        let d = expected(&setup(Some("203.0.113.7")));
        assert_eq!(
            d.spf.value,
            "v=spf1 +a +mx +ip4:198.51.100.1 +ip4:203.0.113.7 -all"
        );
        assert_eq!(d.a.value, "203.0.113.7");
        assert_eq!(d.ptr.host, "203.0.113.7");
        let same = expected(&setup(Some("198.51.100.1")));
        assert_eq!(same.spf.value, "v=spf1 +a +mx +ip4:198.51.100.1 -all");

        let v6 = expected(&Setup {
            server_ip: Some("2001:db8::1".parse().expect("ip")),
            ..setup(None)
        });
        assert_eq!(v6.spf.value, "v=spf1 +a +mx +ip6:2001:db8::1 -all");
        assert_eq!(v6.a.kind, "AAAA");

        let json = serde_json::to_value(&r).expect("json");
        assert_eq!(json["dkim_short"]["type"], "TXT");
        assert_eq!(json["a"]["valid"], false);
    }

    #[test]
    fn dkim_and_dmarc_checks() {
        let expected = "v=DKIM1; k=rsa; p=MIIBIjAN BgkqhkiG";
        let found = |r: &str| dkim_published(&[r.to_owned()], expected);
        assert!(found("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG"));
        assert!(
            found("v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG"),
            "spacing (Go: exact text)"
        );
        assert!(found("p=MIIBIjANBgkqhkiG"), "v and k are optional");
        assert!(found("v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG; t=s"));
        assert!(!found("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiH"));
        assert!(!found("v=DKIM1; k=ed25519; p=MIIBIjANBgkqhkiG"));
        assert!(!found("v=DKIM1; k=rsa; p="), "a revoked key");
        assert!(!dkim_published(&["p=x".to_owned()], "v=DKIM1; k=rsa; p="));

        let dmarc =
            |rs: &[&str]| dmarc_published(&rs.iter().map(|r| (*r).to_owned()).collect::<Vec<_>>());
        assert!(dmarc(&["v=DMARC1; p=none; rua=mailto:a@ex.test"]));
        assert!(dmarc(&["v=DMARC1;p=reject"]));
        assert!(!dmarc(&[]));
        assert!(!dmarc(&["v=DMARC1; rua=mailto:a@ex.test"]), "no policy");
        assert!(!dmarc(&["v=DMARC1; p=maybe"]));
        assert!(!dmarc(&["p=reject; v=DMARC1"]), "v must come first");
        assert!(
            !dmarc(&["v=DMARC1; p=reject", "v=DMARC1; p=none"]),
            "two policies leave the domain without DMARC (Go passed them)"
        );
        assert!(dmarc(&["v=DMARC1; p=quarantine", "some-verification=1"]));
        assert!(same_host("Mail.Ex.Test.", "mail.ex.test"));
        assert!(!same_host("mail.ex.test", "mx.ex.test"));
    }

    #[test]
    fn pub_files() {
        let key = "M".repeat(392);
        let file = dkim_pub_file("default", &key);
        assert!(file.starts_with("default._domainkey IN TXT ( \"v=DKIM1; k=rsa; \"\n\t\"p=MMM"));
        assert!(file.lines().all(|l| l.len() < 256));
        assert_eq!(
            dkim_value_from_pub(&file).as_deref(),
            Some(dkim_value(&key).as_str())
        );

        let rspamadm = "short._domainkey IN TXT ( \"v=DKIM1; k=rsa; \"\n\t\"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ\" ) ; \n";
        assert_eq!(
            dkim_value_from_pub(rspamadm).as_deref(),
            Some("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ")
        );
        let pem = "-----BEGIN PUBLIC KEY-----\nMIIBIj\nANBgk\n-----END PUBLIC KEY-----\n";
        assert_eq!(
            dkim_value_from_pub(pem).as_deref(),
            Some("v=DKIM1; k=rsa; p=MIIBIjANBgk")
        );
        assert_eq!(
            dkim_value_from_pub("v=DKIM1; k=rsa; p=QQ\n").as_deref(),
            Some("v=DKIM1; k=rsa; p=QQ")
        );
        assert_eq!(dkim_value_from_pub("garbage"), None);
        assert_eq!(dkim_value_from_pub("\"v=DKIM1; k=rsa; \""), None);
    }

    #[test]
    fn names_and_urls() {
        assert!(is_domain_name("example.com"));
        assert!(is_domain_name("mail.example.co.uk"));
        assert!(is_domain_name("example.xn--p1ai"));
        assert!(!is_domain_name("localhost"));
        assert!(!is_domain_name("192.0.2.1"));
        assert!(!is_domain_name("ex..com"));
        assert!(!is_domain_name("../etc"));
        assert!(!is_domain_name("-ex.com"));

        let urls = |u: &[&str]| clean_urls(&u.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert_eq!(
            urls(&["https://", " ", "https://ex.test"]).expect("ok"),
            ["https://ex.test"]
        );
        assert_eq!(
            urls(&["http://ex.test/a", "http://ex.test/a"]).expect("ok"),
            ["http://ex.test/a"]
        );
        assert!(urls(&["javascript:alert(1)"]).is_err());
        assert!(urls(&["https:///x"]).is_err());
        assert!(urls(&["https://ex.test/a b"]).is_err());
        let many: Vec<String> = (0..11).map(|i| format!("https://ex{i}.test")).collect();
        assert!(clean_urls(&many).is_err());
    }
}
