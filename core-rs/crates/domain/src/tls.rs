//! Mail host certificates in Postfix's and Dovecot's configuration (Go:
//! `mail_service/certificate.go`), and when to renew them.

/// Postfix's SNI table (`conf/vmail_ssl.map`): `<host> <key> <chain>` per
/// mail host. The line for `host` is replaced (Go matched any line that
/// merely started with the host name, so `mail.example.com` also replaced
/// `mail.example.com.au`), others are kept.
pub fn sni_map_put(content: &str, host: &str, key_path: &str, cert_path: &str) -> String {
    let entry = format!("{host} {key_path} {cert_path}");
    let mut found = false;
    let mut lines: Vec<String> = Vec::new();
    for line in content.lines() {
        if line.split_whitespace().next() == Some(host) {
            if !found {
                lines.push(entry.clone());
                found = true;
            }
        } else if !line.trim().is_empty() {
            lines.push(line.to_owned());
        }
    }
    if !found {
        lines.push(entry);
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

const BEGIN: &str = "#DOMAIN_SSL_BEGIN_";
const END: &str = "#DOMAIN_SSL_END_";

/// Dovecot's SNI block for `host` in `conf.d/10-ssl.conf`, replaced in
/// place or appended (Go's regular expression was greedy and unescaped,
/// and each update added blank lines).
pub fn dovecot_sni_put(content: &str, host: &str, cert_path: &str, key_path: &str) -> String {
    let block = format!(
        "{BEGIN}{host}\nlocal_name {host} {{\n    ssl_cert = < {cert_path}\n    ssl_key = < {key_path}\n}}\n{END}{host}\n"
    );
    let begin = format!("{BEGIN}{host}");
    let end = format!("{END}{host}");
    let mut out = String::with_capacity(content.len() + block.len());
    let mut inside = false;
    let mut placed = false;
    for line in content.split_inclusive('\n') {
        let text = line.trim();
        if !inside && text == begin {
            inside = true;
            if !placed {
                out.push_str(&block);
                placed = true;
            }
            continue;
        }
        if inside {
            if text == end {
                inside = false;
            }
            continue;
        }
        out.push_str(line);
    }
    if !placed {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&block);
    }
    out
}

/// Go's `FixDovecotSSLConfig`: the per-host blocks go after every global
/// setting (Dovecot reads `local_name` sections last anyway, but a global
/// `ssl_cert` after them would be taken for the last host).
pub fn fix_dovecot_ssl(content: &str) -> String {
    let mut main: Vec<&str> = Vec::new();
    let mut blocks: Vec<&str> = vec!["\n"];
    let mut inside = false;
    for row in content.split_inclusive('\n') {
        let text = row.trim();
        if text.starts_with(END) {
            inside = false;
            blocks.push(row);
            continue;
        }
        if inside || text.starts_with(BEGIN) {
            inside = true;
            blocks.push(row);
            continue;
        }
        main.push(row);
    }
    while main.last().is_some_and(|r| r.trim().is_empty()) && main.len() > 1 {
        main.pop();
    }
    let mut out: String = main.concat();
    if blocks.len() > 1 {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&blocks.concat());
    }
    out
}

/// Whether a certificate is due for renewal. One this server obtained is
/// renewed with a third of its lifetime left (30 days for a 90-day
/// certificate, as Let's Encrypt advises; Go waited until 3 days); one
/// uploaded by hand is only replaced in its last week, so a bought
/// certificate is not swapped early.
pub fn needs_renewal(not_before: i64, not_after: i64, issued_here: bool, now: i64) -> bool {
    let remaining = not_after - now;
    if issued_here {
        remaining < (not_after - not_before).max(0) / 3
    } else {
        remaining < 7 * 86_400
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postfix_sni_map() {
        let map = "mail.example.com.au /k1 /c1\nmail.example.com /old /old\n";
        assert_eq!(
            sni_map_put(map, "mail.example.com", "/k2", "/c2"),
            "mail.example.com.au /k1 /c1\nmail.example.com /k2 /c2\n"
        );
        assert_eq!(
            sni_map_put("", "mail.a.test", "/k", "/c"),
            "mail.a.test /k /c\n"
        );
    }

    #[test]
    fn dovecot_blocks() {
        let base = "ssl = required\nssl_cert = </etc/ssl/mail/cert.pem\n";
        let one = dovecot_sni_put(base, "mail.a.test", "/a/full.pem", "/a/key.pem");
        assert_eq!(
            one,
            "ssl = required\nssl_cert = </etc/ssl/mail/cert.pem\n\n#DOMAIN_SSL_BEGIN_mail.a.test\nlocal_name mail.a.test {\n    ssl_cert = < /a/full.pem\n    ssl_key = < /a/key.pem\n}\n#DOMAIN_SSL_END_mail.a.test\n"
        );
        let two = dovecot_sni_put(&one, "mail.b.test", "/b/full.pem", "/b/key.pem");
        let again = dovecot_sni_put(&two, "mail.a.test", "/a/new.pem", "/a/key.pem");
        assert_eq!(again.matches("#DOMAIN_SSL_BEGIN_").count(), 2);
        assert!(again.contains("ssl_cert = < /a/new.pem") && !again.contains("/a/full.pem"));
        assert_eq!(
            again.len(),
            two.len() + "new".len() - "full".len(),
            "no blank lines added"
        );
    }

    #[test]
    fn dovecot_fix_like_go() {
        let mixed = "a = 1\n#DOMAIN_SSL_BEGIN_x\nlocal_name x {\n}\n#DOMAIN_SSL_END_x\n\nb = 2\n\n";
        let fixed = fix_dovecot_ssl(mixed);
        assert_eq!(
            fixed,
            "a = 1\n\nb = 2\n\n#DOMAIN_SSL_BEGIN_x\nlocal_name x {\n}\n#DOMAIN_SSL_END_x\n"
        );
        assert_eq!(fix_dovecot_ssl(&fixed), fixed, "idempotent");
        assert_eq!(fix_dovecot_ssl("a = 1\n"), "a = 1\n");
    }

    #[test]
    fn renewal() {
        let day = 86_400;
        let (from, to) = (0, 90 * day);
        assert!(!needs_renewal(from, to, true, 59 * day));
        assert!(needs_renewal(from, to, true, 61 * day), "30 days left");
        let bought = 365 * day;
        assert!(!needs_renewal(0, bought, false, bought - 30 * day));
        assert!(needs_renewal(0, bought, false, bought - 6 * day));
    }
}
