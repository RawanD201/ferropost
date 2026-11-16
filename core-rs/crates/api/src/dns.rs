//! DNS lookups (Go used the standard library resolver).

use std::sync::LazyLock;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::proto::op::ResponseCode;

static RESOLVER: LazyLock<TokioAsyncResolver> = LazyLock::new(|| {
    TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    })
});

/// Whether a domain can receive mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailDomain {
    Reachable,
    /// It cannot: the reason.
    Unreachable(String),
    /// The lookup failed (timeout, server failure): nothing is known.
    Unknown(String),
}

/// MX records, falling back to an address record as RFC 5321 allows; a
/// null MX (RFC 7505) means no mail. Go treated a domain without MX as
/// invalid and a failed lookup the same as a missing record, so a DNS
/// hiccup could get a whole domain's contacts blocked or deleted.
pub async fn mail_domain(domain: &str) -> MailDomain {
    let name = format!("{}.", domain.trim_end_matches('.'));
    match RESOLVER.mx_lookup(name.as_str()).await {
        Ok(mx) => {
            if mx.iter().any(|r| !r.exchange().is_root()) {
                MailDomain::Reachable
            } else {
                MailDomain::Unreachable("null MX: the domain accepts no mail".to_owned())
            }
        }
        Err(err) => match err.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                if *response_code == ResponseCode::NXDomain {
                    return MailDomain::Unreachable("the domain does not exist".to_owned());
                }
                match RESOLVER.lookup_ip(name.as_str()).await {
                    Ok(ips) if ips.iter().next().is_some() => MailDomain::Reachable,
                    Ok(_) => MailDomain::Unreachable("no MX or address record".to_owned()),
                    Err(e) => match e.kind() {
                        ResolveErrorKind::NoRecordsFound { .. } => {
                            MailDomain::Unreachable("no MX or address record".to_owned())
                        }
                        _ => MailDomain::Unknown(format!("DNS lookup failed: {e}")),
                    },
                }
            }
            _ => MailDomain::Unknown(format!("DNS lookup failed: {err}")),
        },
    }
}

/// The domain's published SPF record (`v=spf1 ...`), if any. A failed
/// lookup counts as none; callers only use it for advice.
pub async fn spf_record(domain: &str) -> Option<String> {
    let name = format!("{}.", domain.trim_end_matches('.'));
    let lookup = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        RESOLVER.txt_lookup(name.as_str()),
    )
    .await
    .ok()?
    .ok()?;
    lookup
        .iter()
        .map(|txt| {
            txt.txt_data()
                .iter()
                .map(|part| String::from_utf8_lossy(part))
                .collect::<String>()
        })
        .find(|text| text.trim_start().to_ascii_lowercase().starts_with("v=spf1"))
}
