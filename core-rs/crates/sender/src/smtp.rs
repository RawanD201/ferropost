//! Building and submitting messages to the local Postfix (Go:
//! `mail_service/sending.go`).
//!
//! Differences from Go: headers go through lettre, which encodes them and
//! rejects line breaks (Go wrote them raw, so a display name containing a
//! newline could inject headers); every message gets a plain-text part next
//! to the HTML (Go sent HTML only, which spam filters penalise); and the
//! session upgrades to TLS when Postfix offers it, so mailbox passwords are
//! not sent in clear text inside the Docker network.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::PoolConfig;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// A message ready to send.
#[derive(Debug, Clone, Default)]
pub struct Outgoing {
    pub from_email: String,
    /// Display name; Go defaulted to the address's local part.
    pub from_name: Option<String>,
    pub to: Vec<String>,
    pub subject: String,
    pub html: String,
    /// Extra headers such as `List-Unsubscribe`.
    pub headers: Vec<(String, String)>,
    pub message_id: String,
}

/// `<unix-millis.32-hex@sender-domain>`, Go's Message-ID format.
pub fn message_id(from_email: &str) -> String {
    use rand::RngCore;
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let domain = from_email.split_once('@').map_or("billionmail", |(_, d)| d);
    format!("<{}.{hex}@{domain}>", chrono::Utc::now().timestamp_millis())
}

/// Builds the MIME message.
pub fn build(mail: &Outgoing) -> Result<Message> {
    let name = mail
        .from_name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| {
            mail.from_email
                .split('@')
                .next()
                .unwrap_or_default()
                .to_owned()
        });
    let from = Mailbox::new(
        Some(name),
        mail.from_email.parse().context("invalid sender address")?,
    );
    let mut builder = Message::builder()
        .from(from)
        .subject(&mail.subject)
        .message_id(Some(mail.message_id.clone()))
        .date_now()
        .raw_header(HeaderValue::new(
            HeaderName::new_from_ascii_str("X-Mailer"),
            "Ferropost".to_owned(),
        ));
    if mail.to.is_empty() {
        bail!("no recipients");
    }
    for to in &mail.to {
        builder = builder.to(to
            .parse()
            .with_context(|| format!("invalid recipient {to:?}"))?);
    }
    for (name, value) in &mail.headers {
        if value.contains(['\r', '\n'])
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("refusing unsafe header {name:?}");
        }
        let name = HeaderName::new_from_ascii(name.clone()).context("invalid header name")?;
        builder = builder.raw_header(HeaderValue::new(name, value.clone()));
    }
    Ok(builder.multipart(MultiPart::alternative_plain_html(
        html_to_text(&mail.html),
        mail.html.clone(),
    ))?)
}

/// A plain-text rendering of the HTML for the `text/plain` part.
pub fn html_to_text(html: &str) -> String {
    use std::sync::LazyLock;
    static HIDDEN: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?is)<(style|script|head)[^>]*>.*?</(style|script|head)>")
            .expect("pattern")
    });
    static LINK: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?is)<a\s[^>]*href\s*=\s*"([^"]+)"[^>]*>(.*?)</a>"#).expect("pattern")
    });
    static BREAK: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)<br\s*/?>|</(p|div|tr|h[1-6]|li|table)>").expect("pattern")
    });
    static TAG: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"<[^>]*>").expect("pattern"));

    let text = HIDDEN.replace_all(html, "");
    let text = LINK.replace_all(&text, |c: &regex::Captures| {
        let label = TAG.replace_all(&c[2], "").trim().to_owned();
        if label.is_empty() || label == c[1].trim() {
            c[1].to_owned()
        } else {
            format!("{label} ({})", &c[1])
        }
    });
    let text = BREAK.replace_all(&text, "\n");
    let text = TAG.replace_all(&text, "");
    let text = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    let mut out = Vec::new();
    for line in text
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
    {
        if !(line.is_empty() && out.last().is_some_and(String::is_empty)) {
            out.push(line);
        }
    }
    out.join("\n").trim().to_owned()
}

/// Credentials for a new mailbox, stored the way Go stores them: a Dovecot
/// MD5-CRYPT hash (`$1$...`) and the reversible hex-of-base64 copy.
pub fn mailbox_credentials(password: &str) -> Result<(String, String)> {
    use base64::Engine;
    // Weak, but it is Dovecot's configured `default_pass_scheme` and what
    // Go and Roundcube write; moving every mailbox to SHA512-CRYPT is part
    // of the mailbox work (step 5).
    #[allow(deprecated)]
    let hash = pwhash::md5_crypt::hash(password).context("md5-crypt")?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(password)
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((hash, encoded))
}

/// A random 16-character password (Go: `grand.S(16)`).
pub fn random_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rngs::OsRng;
    (0..16)
        .map(|_| char::from(CHARS[rng.gen_range(0..CHARS.len())]))
        .collect()
}

/// Go stored mailbox passwords as hex of base64 of the password, so the
/// core can log in as the mailbox (not a hash; see the README).
pub fn decode_mailbox_password(encoded: &str) -> Result<String> {
    use base64::Engine;
    let raw = (0..encoded.len())
        .step_by(2)
        .map(|i| {
            encoded
                .get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .context("password is not hex")?;
    let plain = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .context("password is not base64")?;
    String::from_utf8(plain).context("password is not UTF-8")
}

/// Where and as whom to submit.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// A pooled SMTP connection to Postfix for one sender mailbox.
#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl Mailer {
    pub fn new(config: &SmtpConfig) -> Result<Self> {
        Self::with_connections(config, 2)
    }

    /// A mailer keeping up to `connections` sessions open, for concurrent
    /// sending (Go opened a new session for every message).
    pub fn with_connections(config: &SmtpConfig, connections: u32) -> Result<Self> {
        // The internal host name never matches Postfix's certificate; TLS
        // here protects the password on the Docker network only.
        let tls = TlsParameters::builder(config.host.clone())
            .dangerous_accept_invalid_certs(true)
            .dangerous_accept_invalid_hostnames(true)
            .build_rustls()?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
            .port(config.port)
            .tls(Tls::Opportunistic(tls))
            .credentials(Credentials::new(
                config.username.clone(),
                config.password.clone(),
            ))
            .authentication(vec![Mechanism::Plain, Mechanism::Login])
            .timeout(Some(Duration::from_secs(60)))
            .pool_config(PoolConfig::new().max_size(connections.max(1)))
            .build();
        Ok(Self { transport })
    }

    pub async fn send(&self, mail: &Outgoing) -> Result<()> {
        let message = build(mail)?;
        self.transport
            .send(message)
            .await
            .context("SMTP submission failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail() -> Outgoing {
        Outgoing {
            from_email: "news@ex.com".into(),
            from_name: Some("Acmé News".into()),
            to: vec!["a@x.com".into()],
            subject: "Hello ✓".into(),
            html: "<html><head><style>p{}</style></head><body><p>Hi &amp; welcome</p>\
                   <a href=\"https://x.com/s\">Shop now</a><br>bye</body></html>"
                .into(),
            headers: vec![("List-Unsubscribe".into(), "<https://u.example/1>".into())],
            message_id: "<1.abc@ex.com>".into(),
        }
    }

    #[test]
    fn builds_multipart_with_encoded_headers() {
        let raw = String::from_utf8(build(&mail()).expect("message").formatted()).expect("utf8");
        assert!(raw.contains("Message-ID: <1.abc@ex.com>"));
        assert!(raw.contains("List-Unsubscribe: <https://u.example/1>"));
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("text/plain") && raw.contains("text/html"));
        // RFC 2047 encoding of the non-ASCII words.
        assert!(raw.contains("Subject: Hello =?utf-8?b?4pyT?="), "{raw}");
        assert!(
            raw.contains("From: =?utf-8?b?QWNtw6kgTmV3cw==?= <news@ex.com>"),
            "{raw}"
        );
        assert!(raw.contains("<news@ex.com>"));
    }

    #[test]
    fn refuses_header_injection() {
        let mut bad = mail();
        bad.headers = vec![("X-Note".into(), "a\r\nBcc: victim@x.com".into())];
        assert!(build(&bad).is_err());
        let mut bad = mail();
        bad.to = vec!["not an address".into()];
        assert!(build(&bad).is_err());
    }

    #[test]
    fn plain_text_part() {
        assert_eq!(
            html_to_text(&mail().html),
            "Hi & welcome\nShop now (https://x.com/s)\nbye"
        );
    }

    #[test]
    fn message_ids_and_passwords() {
        let id = message_id("news@ex.com");
        assert!(id.starts_with('<') && id.ends_with("@ex.com>"));
        assert_ne!(id, message_id("news@ex.com"));
        // hex(base64("s3cret!"))
        assert_eq!(
            decode_mailbox_password("637a4e6a636d563049513d3d").expect("decode"),
            "s3cret!"
        );
        assert!(decode_mailbox_password("zz").is_err());

        let (hash, encoded) = mailbox_credentials("s3cret!").expect("credentials");
        assert!(hash.starts_with("$1$"));
        assert!(pwhash::md5_crypt::verify("s3cret!", &hash));
        assert_eq!(encoded, "637a4e6a636d563049513d3d");
        assert_eq!(
            decode_mailbox_password(&encoded).expect("roundtrip"),
            "s3cret!"
        );
        assert_eq!(random_password().len(), 16);
    }
}
