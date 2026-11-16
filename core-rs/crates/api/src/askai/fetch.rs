//! Fetching pages for users (brand sites; the chat's `http_request`
//! tool, whose URLs a model chooses): public addresses only, never this
//! server or its containers, with size and time limits. Go relayed these
//! requests through BillionMail's own service (`cdn.billionmail.com/bot`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::state::AppState;

const MAX_REDIRECTS: usize = 5;

/// A request this server will not make, or an answer trying again will
/// not change.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// Whether trying again is pointless.
pub fn is_refused(err: &anyhow::Error) -> bool {
    err.chain().any(|e| e.is::<Refused>())
}

/// Which addresses may be fetched.
#[derive(Debug, Clone)]
pub struct Guard {
    blocked: Vec<IpNet>,
    allow_private: bool,
}

impl Guard {
    pub fn new(state: &AppState) -> Self {
        let mut blocked: Vec<IpNet> = vec!["172.66.0.0/16".parse().expect("network")];
        let main = ferropost_domain::multi_ip::main_prefix(
            state.config.env.get("IPV4_NETWORK").as_deref(),
        )
        .to_owned();
        if let Ok(net) = format!("{main}.0/24").parse() {
            blocked.push(net);
        }
        Self {
            blocked,
            allow_private: state.config.fetch_private,
        }
    }

    pub fn allowed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.allow_private
            || (ferropost_domain::askai::is_public_ip(ip)
                && !self.blocked.iter().any(|net| net.contains(&ip)))
    }
}

/// Resolves names to the allowed addresses only, so a host name cannot
/// point the request (or a redirect) at the containers.
struct GuardedResolver(Arc<Guard>);

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let guard = self.0.clone();
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let allowed: Vec<SocketAddr> = found.filter(|a| guard.allowed(a.ip())).collect();
            if allowed.is_empty() {
                return Err(
                    Box::new(Refused(format!("{} has no public address", name.as_str())))
                        as Box<dyn std::error::Error + Send + Sync>,
                );
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

fn check_url(guard: &Guard, url: &Url) -> Result<(), Refused> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Refused(
            "only http and https links can be fetched".to_owned(),
        ));
    }
    let ip = match url.host() {
        None => return Err(Refused("the link has no host".to_owned())),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        Some(url::Host::Domain(_)) => return Ok(()),
    };
    if guard.allowed(ip) {
        Ok(())
    } else {
        Err(Refused(format!("{ip} is not a public address")))
    }
}

/// A fetched page.
#[derive(Debug, Clone)]
pub struct Page {
    /// Where it was found, after redirects.
    pub url: Url,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Page {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Fetches `url` for a user, keeping at most `max_bytes` of the body.
pub async fn get(state: &AppState, url: &str, max_bytes: usize) -> Result<Page> {
    let guard = Arc::new(Guard::new(state));
    let url = Url::parse(url.trim()).context("not a link")?;
    check_url(&guard, &url)?;
    let redirect_guard = guard.clone();
    let client = reqwest::Client::builder()
        .dns_resolver(Arc::new(GuardedResolver(guard)))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if let Err(err) = check_url(&redirect_guard, attempt.url()) {
                attempt.error(err)
            } else {
                attempt.follow()
            }
        }))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(25))
        .user_agent(concat!(
            "Ferropost/",
            env!("CARGO_PKG_VERSION"),
            " (brand info)"
        ))
        .build()?;
    let mut response = client
        .get(url)
        .header(
            "accept",
            "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
        )
        .send()
        .await?;
    let status = response.status();
    if status.is_client_error() {
        return Err(Refused(format!("the site answered {status}")).into());
    }
    if !status.is_success() {
        bail!("the site answered {status}");
    }
    let final_url = response.url().clone();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = max_bytes.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if body.len() >= max_bytes {
            break;
        }
    }
    Ok(Page {
        url: final_url,
        content_type,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard() {
        let guard = Guard {
            blocked: vec![
                "172.66.0.0/16".parse().expect("net"),
                "10.9.8.0/24".parse().expect("net"),
            ],
            allow_private: false,
        };
        assert!(guard.allowed("93.184.216.34".parse().expect("ip")));
        assert!(
            !guard.allowed("172.66.1.5".parse().expect("ip")),
            "the containers"
        );
        assert!(!guard.allowed("127.0.0.1".parse().expect("ip")));
        assert!(!guard.allowed("::ffff:172.66.1.5".parse().expect("ip")));
        let check = |u: &str| check_url(&guard, &Url::parse(u).expect("url"));
        assert!(check("https://example.com/x").is_ok());
        assert!(check("http://127.0.0.1:8181/api").is_err());
        assert!(check("http://[::1]/").is_err());
        assert!(check("file:///etc/passwd").is_err());
        assert!(check("http://169.254.169.254/latest/meta-data").is_err());
    }
}
