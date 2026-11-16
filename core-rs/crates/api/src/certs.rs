//! Reading PEM certificates for the console (Go: `crypto/x509` in
//! `controller/settings` and `service/domains/ssl.go`).
//!
//! Unlike Go, a key is only accepted together with the certificate it
//! belongs to: Go saved any parseable PEM block as the key, and the console
//! then served a certificate the server could not use.

use anyhow::{Context, Result, anyhow, bail};
use rustls::crypto::ring;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use x509_parser::prelude::*;

/// What the console shows about a certificate, named as in Go's
/// `SSLConfig`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CertInfo {
    #[serde(rename = "notAfter")]
    pub not_after: String,
    #[serde(rename = "notBefore")]
    pub not_before: String,
    pub issuer: String,
    pub subject: String,
    pub dns_names: Vec<String>,
    pub serial_number: String,
    pub is_ca: bool,
    pub issuer_common_name: String,
    pub subject_common_name: String,
    pub version: u32,
    /// Valid right now.
    #[serde(skip)]
    pub current: bool,
    /// `notAfter` as a Unix time.
    #[serde(skip)]
    pub expires_at: i64,
}

/// The certificates in a PEM bundle, leaf first.
pub fn chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("{e}"))?;
    if chain.is_empty() {
        bail!("no certificate found");
    }
    Ok(chain)
}

/// Details of the first certificate in `pem`.
pub fn info(pem: &[u8], now: i64) -> Result<CertInfo> {
    let chain = chain(pem)?;
    let (_, cert) = X509Certificate::from_der(chain[0].as_ref()).map_err(|e| anyhow!("{e}"))?;
    let validity = cert.validity();
    let (from, until) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    let dns_names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(name) => Some((*name).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(CertInfo {
        not_after: rfc3339(until),
        not_before: rfc3339(from),
        issuer: go_name(cert.issuer()),
        subject: go_name(cert.subject()),
        dns_names,
        serial_number: cert.serial.to_string(),
        is_ca: cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|b| b.value.ca),
        issuer_common_name: common_name(cert.issuer()),
        subject_common_name: common_name(cert.subject()),
        version: cert.version().0 + 1,
        current: from <= now && now <= until,
        expires_at: until,
    })
}

/// Checks that `key_pem` is the private key of the first certificate in
/// `cert_pem`.
pub fn check_pair(cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
    let chain = chain(cert_pem).context("certificate")?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| anyhow!("private key: {e}"))?;
    CertifiedKey::from_der(chain, key, &ring::default_provider())
        .map_err(|e| anyhow!("{e}"))
        .context("the private key does not belong to the certificate")?;
    Ok(())
}

fn rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Go's `Name.CommonName`: the last CN.
fn common_name(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .last()
        .unwrap_or_default()
        .to_owned()
}

/// Attributes Go names, in the order its `Name.String()` prints them.
const GO_ORDER: [(&str, &str); 9] = [
    ("2.5.4.5", "SERIALNUMBER"),
    ("2.5.4.3", "CN"),
    ("2.5.4.11", "OU"),
    ("2.5.4.10", "O"),
    ("2.5.4.17", "POSTALCODE"),
    ("2.5.4.9", "STREET"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.6", "C"),
];

/// Go's `pkix.Name.String()`: the attributes it knows in its fixed order
/// (several values of one type joined with `+`), then any others, last
/// seen first, as `oid=#<DER hex>`.
fn go_name(name: &X509Name<'_>) -> String {
    let attributes: Vec<_> = name.iter_attributes().collect();
    let mut parts: Vec<String> = Vec::new();
    for (oid, label) in GO_ORDER {
        let values: Vec<String> = attributes
            .iter()
            .filter(|a| a.attr_type().to_id_string() == oid)
            .map(|a| format!("{label}={}", escape(a.as_str().unwrap_or_default())))
            .collect();
        if !values.is_empty() {
            parts.push(values.join("+"));
        }
    }
    let others = attributes
        .iter()
        .rev()
        .filter(|a| {
            let oid = a.attr_type().to_id_string();
            !GO_ORDER.iter().any(|(known, _)| *known == oid)
        })
        .map(|a| {
            format!(
                "{}=#{}",
                a.attr_type().to_id_string(),
                hex::encode(go_der(a))
            )
        });
    parts.extend(others);
    parts.join(",")
}

/// The value as Go's `asn1.Marshal` writes it back: strings become a
/// PrintableString when they fit its alphabet, a UTF8String otherwise.
fn go_der(attr: &AttributeTypeAndValue<'_>) -> Vec<u8> {
    let (tag, data): (u8, Vec<u8>) = match attr.as_str() {
        Ok(text) => {
            let printable = text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b));
            (
                if printable { 0x13 } else { 0x0c },
                text.as_bytes().to_vec(),
            )
        }
        Err(_) => (
            attr.attr_value().tag().0 as u8,
            attr.attr_value().data.to_vec(),
        ),
    };
    let mut der = vec![tag];
    match data.len() {
        n if n < 0x80 => der.push(n as u8),
        n if n <= 0xff => der.extend([0x81, n as u8]),
        n => der.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    der.extend(data);
    der
}

/// Go's escaping of attribute values in `RDNSequence.String()`.
fn escape(value: &str) -> String {
    let last = value.chars().count().saturating_sub(1);
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        let needs = match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => true,
            ' ' => i == 0 || i == last,
            '#' => i == 0,
            _ => false,
        };
        if needs {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate(cn: &str, ca: bool) -> (String, String) {
        let mut params =
            rcgen::CertificateParams::new(vec!["mail.example.com".to_owned()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CountryName, "US");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Acme, Inc.");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        if ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("cert");
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn reads_like_go() {
        let (cert, key) = generate("mail.example.com", false);
        let info = info(cert.as_bytes(), chrono::Utc::now().timestamp()).expect("info");
        assert_eq!(
            info.subject, "CN=mail.example.com,O=Acme\\, Inc.,C=US",
            "Go's order and escaping"
        );
        assert_eq!(info.issuer, info.subject, "self-signed");
        assert_eq!(info.subject_common_name, "mail.example.com");
        assert_eq!(info.dns_names, ["mail.example.com"]);
        assert_eq!(info.version, 3);
        assert!(!info.is_ca && info.current);
        assert!(info.not_after.ends_with('Z'));
        assert!(info.serial_number.bytes().all(|b| b.is_ascii_digit()));
        check_pair(cert.as_bytes(), key.as_bytes()).expect("pair");

        let (other_cert, other_key) = generate("other", true);
        assert!(info_is_ca(&other_cert));
        let err = check_pair(cert.as_bytes(), other_key.as_bytes()).expect_err("mismatch");
        assert!(format!("{err:#}").contains("does not belong"), "{err:#}");
        assert!(check_pair(other_cert.as_bytes(), b"junk").is_err());
        assert!(super::info(b"junk", 0).is_err());
    }

    fn info_is_ca(pem: &str) -> bool {
        info(pem.as_bytes(), 0).expect("info").is_ca
    }

    #[test]
    fn escaping() {
        assert_eq!(escape(" a,b+c "), "\\ a\\,b\\+c\\ ");
        assert_eq!(escape("#x#"), "\\#x#");
    }
}
