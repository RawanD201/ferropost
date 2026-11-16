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

/// A blocklist query: no record means not listed. Uses the system resolver
/// (Go asked Google's, whose queries Spamhaus refuses).
pub async fn dnsbl(name: &str) -> ferropost_domain::blocklist::Answer {
    use ferropost_domain::blocklist::Answer;
    let fqdn = format!("{}.", name.trim_end_matches('.'));
    match tokio::time::timeout(
        std::time::Duration::from_secs(8),
        RESOLVER.ipv4_lookup(fqdn.as_str()),
    )
    .await
    {
        Ok(Ok(found)) => found
            .iter()
            .next()
            .map_or(Answer::NotListed, |a| Answer::Address(a.0)),
        Ok(Err(err)) => match err.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => Answer::NotListed,
            _ => Answer::Failed,
        },
        Err(_) => Answer::Failed,
    }
}

/// A host's first IPv4 address.
pub async fn first_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    let fqdn = format!("{}.", host.trim_end_matches('.'));
    let found = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        RESOLVER.ipv4_lookup(fqdn.as_str()),
    )
    .await
    .ok()?
    .ok()?;
    found.iter().next().map(|a| a.0)
}

/// How long one record check may wait for DNS.
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

/// An answer for the record checks: no such name or record is an empty
/// answer; a timeout or server failure is `TempFail`.
async fn answer<T, L, F>(
    lookup: F,
    read: impl FnOnce(L) -> Vec<T>,
) -> Result<Vec<T>, ferropost_domain::spf::TempFail>
where
    F: std::future::Future<Output = Result<L, hickory_resolver::error::ResolveError>>,
{
    use ferropost_domain::spf::TempFail;
    match tokio::time::timeout(CHECK_TIMEOUT, lookup).await {
        Ok(Ok(found)) => Ok(read(found)),
        Ok(Err(err)) => match err.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => Ok(Vec::new()),
            _ => Err(TempFail),
        },
        Err(_) => Err(TempFail),
    }
}

/// TXT records of `name`, each one's strings joined.
pub async fn txt(name: &str) -> Result<Vec<String>, ferropost_domain::spf::TempFail> {
    answer(RESOLVER.txt_lookup(fqdn(name)), |found| {
        found
            .iter()
            .map(|txt| {
                txt.txt_data()
                    .iter()
                    .map(|part| String::from_utf8_lossy(part))
                    .collect::<String>()
            })
            .collect()
    })
    .await
}

/// A and AAAA records of `name`.
pub async fn addresses(
    name: &str,
) -> Result<Vec<std::net::IpAddr>, ferropost_domain::spf::TempFail> {
    let name = fqdn(name);
    let (v4, v6) = tokio::join!(
        answer(RESOLVER.ipv4_lookup(name.as_str()), |found| {
            found.iter().map(|a| std::net::IpAddr::V4(a.0)).collect()
        }),
        answer(RESOLVER.ipv6_lookup(name.as_str()), |found| {
            found.iter().map(|a| std::net::IpAddr::V6(a.0)).collect()
        }),
    );
    match (v4, v6) {
        (Err(err), Err(_)) => Err(err),
        (v4, v6) => Ok(v4
            .unwrap_or_default()
            .into_iter()
            .chain(v6.unwrap_or_default())
            .collect()),
    }
}

/// The exchanges of `name`'s MX records, without the final dot.
pub async fn mx_hosts(name: &str) -> Result<Vec<String>, ferropost_domain::spf::TempFail> {
    answer(RESOLVER.mx_lookup(fqdn(name)), |found| {
        found
            .iter()
            .map(|mx| mx.exchange().to_ascii().trim_end_matches('.').to_owned())
            .collect()
    })
    .await
}

/// The PTR names of `ip`, without the final dot.
pub async fn ptr_names(
    ip: std::net::IpAddr,
) -> Result<Vec<String>, ferropost_domain::spf::TempFail> {
    answer(RESOLVER.reverse_lookup(ip), |found| {
        found
            .iter()
            .map(|ptr| ptr.to_string().trim_end_matches('.').to_owned())
            .collect()
    })
    .await
}

/// The system resolver, for SPF evaluation.
pub struct Dns;

impl ferropost_domain::spf::Resolver for Dns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, ferropost_domain::spf::TempFail> {
        txt(name).await
    }

    async fn addresses(
        &self,
        name: &str,
    ) -> Result<Vec<std::net::IpAddr>, ferropost_domain::spf::TempFail> {
        addresses(name).await
    }

    async fn mx(&self, name: &str) -> Result<Vec<String>, ferropost_domain::spf::TempFail> {
        mx_hosts(name).await
    }
}
