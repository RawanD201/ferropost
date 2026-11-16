//! SPF evaluation (RFC 7208) of one address: does a domain's published
//! policy let this server send for it? DNS answers come from the caller
//! ([`Resolver`]), so the rules are tested without a network.
//!
//! Go compared the expected record with the published one as text (each
//! `ip4:`/`include:` of the expected record had to appear somewhere in it),
//! so a policy that covers the server through `mx`, `a` or an include
//! looked wrong, `ip4:1.2.3.45` passed for `1.2.3.4`, and two SPF records
//! (which break SPF for everyone) passed as long as one of them matched.
//!
//! Not evaluated: macros (a term whose domain uses `%` does not match) and
//! the deprecated `ptr` mechanism (it does not match either).

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// The result of `check_host()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    /// The domain publishes no SPF record.
    None,
    TempError,
    PermError,
}

/// A DNS failure other than "no such record" (timeout, server failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TempFail;

/// The DNS lookups SPF needs. "No such name" and "no records" are empty
/// answers, not errors.
pub trait Resolver: Sync {
    /// TXT records of `name`, each one's strings joined.
    fn txt(&self, name: &str) -> impl Future<Output = Result<Vec<String>, TempFail>> + Send;
    /// A and AAAA records of `name`.
    fn addresses(&self, name: &str) -> impl Future<Output = Result<Vec<IpAddr>, TempFail>> + Send;
    /// The exchanges of `name`'s MX records.
    fn mx(&self, name: &str) -> impl Future<Output = Result<Vec<String>, TempFail>> + Send;
}

/// Terms that query DNS, per evaluation (RFC 7208 4.6.4).
const MAX_LOOKUPS: u32 = 10;
/// MX records looked at for one `mx` term.
const MAX_MX: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl Qualifier {
    fn result(self) -> SpfResult {
        match self {
            Self::Pass => SpfResult::Pass,
            Self::Fail => SpfResult::Fail,
            Self::SoftFail => SpfResult::SoftFail,
            Self::Neutral => SpfResult::Neutral,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mechanism {
    All,
    Include(String),
    A {
        domain: Option<String>,
        v4: u8,
        v6: u8,
    },
    Mx {
        domain: Option<String>,
        v4: u8,
        v6: u8,
    },
    Ptr,
    Ip(IpAddr, u8),
    Exists(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    Mechanism(Qualifier, Mechanism),
    Redirect(String),
    /// A modifier with no effect here (`exp=`, unknown ones).
    Other,
}

/// Whether a TXT record is an SPF record (`v=spf1`, then a space or the
/// end).
pub fn is_spf(record: &str) -> bool {
    let record = record.trim_start();
    record
        .get(..6)
        .is_some_and(|v| v.eq_ignore_ascii_case("v=spf1"))
        && record.as_bytes().get(6).is_none_or(|b| *b == b' ')
}

fn cidr(raw: &str, max: u8) -> Result<u8, ()> {
    let bits: u8 = raw.parse().map_err(|_| ())?;
    if bits > max || raw.starts_with('+') || (raw.len() > 1 && raw.starts_with('0')) {
        return Err(());
    }
    Ok(bits)
}

/// `/24`, `//64` or `/24//64` after `a` or `mx`.
fn dual_cidr(raw: &str) -> Result<(u8, u8), ()> {
    if raw.is_empty() {
        return Ok((32, 128));
    }
    let (v4, v6) = match raw.split_once("//") {
        Some((v4, v6)) => (v4, Some(v6)),
        None => (raw, None),
    };
    let v4 = match v4 {
        "" => 32,
        v4 => cidr(v4.strip_prefix('/').ok_or(())?, 32)?,
    };
    let v6 = match v6 {
        None => 128,
        Some(v6) => cidr(v6, 128)?,
    };
    Ok((v4, v6))
}

/// `[":" domain] [cidr]` after `a` or `mx`.
fn target_and_cidr(rest: &str) -> Result<(Option<String>, u8, u8), ()> {
    let (domain, cidrs) = match rest.strip_prefix(':') {
        Some(spec) => {
            let end = spec.find('/').unwrap_or(spec.len());
            if end == 0 {
                return Err(());
            }
            (Some(spec[..end].to_owned()), &spec[end..])
        }
        None if rest.is_empty() || rest.starts_with('/') => (None, rest),
        None => return Err(()),
    };
    let (v4, v6) = dual_cidr(cidrs)?;
    Ok((domain, v4, v6))
}

fn domain_arg(rest: &str) -> Result<String, ()> {
    match rest.strip_prefix(':') {
        Some(spec) if !spec.is_empty() && !spec.contains('/') => Ok(spec.to_owned()),
        _ => Err(()),
    }
}

fn network(rest: &str, v6: bool) -> Result<Mechanism, ()> {
    let spec = rest.strip_prefix(':').ok_or(())?;
    let (addr, bits) = match spec.split_once('/') {
        Some((addr, bits)) => (addr, Some(bits)),
        None => (spec, None),
    };
    let ip: IpAddr = if v6 {
        IpAddr::V6(addr.parse().map_err(|_| ())?)
    } else {
        IpAddr::V4(addr.parse().map_err(|_| ())?)
    };
    let max = if v6 { 128 } else { 32 };
    let bits = match bits {
        Some(b) => cidr(b, max)?,
        None => max,
    };
    Ok(Mechanism::Ip(ip, bits))
}

fn parse_term(raw: &str) -> Result<Term, ()> {
    let term = raw.to_ascii_lowercase();
    // A modifier's name ends at `=`; a mechanism's at `:`, `/` or the end.
    let name_end = term.find([':', '/', '=']).unwrap_or(term.len());
    if term[name_end..].starts_with('=') {
        let (name, value) = (&term[..name_end], &term[name_end + 1..]);
        let valid_name = name.starts_with(|c: char| c.is_ascii_alphabetic())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !valid_name {
            return Err(());
        }
        return Ok(match name {
            "redirect" if !value.is_empty() => Term::Redirect(value.to_owned()),
            "redirect" => return Err(()),
            _ => Term::Other,
        });
    }
    let (qualifier, body) = match term.as_bytes().first() {
        Some(b'+') => (Qualifier::Pass, &term[1..]),
        Some(b'-') => (Qualifier::Fail, &term[1..]),
        Some(b'~') => (Qualifier::SoftFail, &term[1..]),
        Some(b'?') => (Qualifier::Neutral, &term[1..]),
        _ => (Qualifier::Pass, term.as_str()),
    };
    let end = body.find([':', '/']).unwrap_or(body.len());
    let (name, rest) = body.split_at(end);
    let mechanism = match name {
        "all" if rest.is_empty() => Mechanism::All,
        "include" => Mechanism::Include(domain_arg(rest)?),
        "exists" => Mechanism::Exists(domain_arg(rest)?),
        "a" => {
            let (domain, v4, v6) = target_and_cidr(rest)?;
            Mechanism::A { domain, v4, v6 }
        }
        "mx" => {
            let (domain, v4, v6) = target_and_cidr(rest)?;
            Mechanism::Mx { domain, v4, v6 }
        }
        "ptr" if rest.is_empty() || rest.starts_with(':') => Mechanism::Ptr,
        "ip4" => network(rest, false)?,
        "ip6" => network(rest, true)?,
        _ => return Err(()),
    };
    Ok(Term::Mechanism(qualifier, mechanism))
}

fn parse(record: &str) -> Result<Vec<Term>, ()> {
    record.split_whitespace().skip(1).map(parse_term).collect()
}

/// Whether `ip` is in `net/bits` (same family only).
fn in_network(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip.to_canonical(), net.to_canonical()) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

fn any_in(ip: IpAddr, addresses: &[IpAddr], v4: u8, v6: u8) -> bool {
    let bits = if ip.to_canonical().is_ipv4() { v4 } else { v6 };
    addresses.iter().any(|a| in_network(ip, *a, bits))
}

fn count(lookups: &mut u32) -> Result<(), SpfResult> {
    *lookups += 1;
    if *lookups > MAX_LOOKUPS {
        return Err(SpfResult::PermError);
    }
    Ok(())
}

/// A domain from a record: `None` when it uses macros, which are not
/// expanded.
fn plain(domain: &str) -> Option<String> {
    (!domain.contains('%')).then(|| domain.trim_end_matches('.').to_owned())
}

/// `check_host(ip, domain)` (RFC 7208 section 4).
pub async fn check_host<R: Resolver>(resolver: &R, ip: IpAddr, domain: &str) -> SpfResult {
    let mut lookups = 0;
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    evaluate(resolver, ip.to_canonical(), domain, &mut lookups).await
}

fn evaluate<'a, R: Resolver>(
    resolver: &'a R,
    ip: IpAddr,
    domain: String,
    lookups: &'a mut u32,
) -> Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>> {
    Box::pin(async move {
        let Ok(records) = resolver.txt(&domain).await else {
            return SpfResult::TempError;
        };
        let mut spf = records.iter().filter(|r| is_spf(r));
        let record = match (spf.next(), spf.next()) {
            (None, _) => return SpfResult::None,
            (Some(one), None) => one,
            (Some(_), Some(_)) => return SpfResult::PermError,
        };
        let Ok(terms) = parse(record) else {
            return SpfResult::PermError;
        };
        let mut redirect = None;
        for term in terms {
            match term {
                Term::Redirect(target) => redirect = Some(target),
                Term::Other => {}
                Term::Mechanism(qualifier, mechanism) => {
                    match matches(resolver, ip, &domain, &mechanism, lookups).await {
                        Ok(true) => return qualifier.result(),
                        Ok(false) => {}
                        Err(result) => return result,
                    }
                }
            }
        }
        let Some(target) = redirect else {
            return SpfResult::Neutral;
        };
        if let Err(result) = count(lookups) {
            return result;
        }
        let Some(target) = plain(&target) else {
            return SpfResult::Neutral;
        };
        match evaluate(resolver, ip, target, lookups).await {
            SpfResult::None => SpfResult::PermError,
            other => other,
        }
    })
}

async fn matches<R: Resolver>(
    resolver: &R,
    ip: IpAddr,
    domain: &str,
    mechanism: &Mechanism,
    lookups: &mut u32,
) -> Result<bool, SpfResult> {
    match mechanism {
        Mechanism::All => Ok(true),
        Mechanism::Ip(net, bits) => Ok(in_network(ip, *net, *bits)),
        Mechanism::Ptr => {
            count(lookups)?;
            Ok(false)
        }
        Mechanism::A {
            domain: target,
            v4,
            v6,
        } => {
            count(lookups)?;
            let Some(name) = target.as_deref().map_or(Some(domain.to_owned()), plain) else {
                return Ok(false);
            };
            let found = resolver
                .addresses(&name)
                .await
                .map_err(|_| SpfResult::TempError)?;
            Ok(any_in(ip, &found, *v4, *v6))
        }
        Mechanism::Mx {
            domain: target,
            v4,
            v6,
        } => {
            count(lookups)?;
            let Some(name) = target.as_deref().map_or(Some(domain.to_owned()), plain) else {
                return Ok(false);
            };
            let exchanges = resolver.mx(&name).await.map_err(|_| SpfResult::TempError)?;
            if exchanges.len() > MAX_MX {
                return Err(SpfResult::PermError);
            }
            for exchange in exchanges {
                // An exchange that does not resolve only fails to match.
                if let Ok(found) = resolver.addresses(exchange.trim_end_matches('.')).await
                    && any_in(ip, &found, *v4, *v6)
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Mechanism::Include(target) => {
            count(lookups)?;
            let Some(target) = plain(target) else {
                return Ok(false);
            };
            match evaluate(resolver, ip, target, lookups).await {
                SpfResult::Pass => Ok(true),
                SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => Ok(false),
                SpfResult::TempError => Err(SpfResult::TempError),
                SpfResult::PermError | SpfResult::None => Err(SpfResult::PermError),
            }
        }
        Mechanism::Exists(target) => {
            count(lookups)?;
            let Some(target) = plain(target) else {
                return Ok(false);
            };
            let found = resolver
                .addresses(&target)
                .await
                .map_err(|_| SpfResult::TempError)?;
            Ok(found.iter().any(IpAddr::is_ipv4))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct Zone {
        txt: HashMap<String, Vec<String>>,
        addresses: HashMap<String, Vec<IpAddr>>,
        mx: HashMap<String, Vec<String>>,
        failing: Vec<String>,
    }

    impl Zone {
        fn txt(mut self, name: &str, record: &str) -> Self {
            self.txt
                .entry(name.to_owned())
                .or_default()
                .push(record.to_owned());
            self
        }
        fn addr(mut self, name: &str, ip: &str) -> Self {
            self.addresses
                .entry(name.to_owned())
                .or_default()
                .push(ip.parse().expect("ip"));
            self
        }
        fn mx(mut self, name: &str, exchange: &str) -> Self {
            self.mx
                .entry(name.to_owned())
                .or_default()
                .push(exchange.to_owned());
            self
        }
        fn failing(mut self, name: &str) -> Self {
            self.failing.push(name.to_owned());
            self
        }
        fn answer<T: Clone>(
            &self,
            map: &HashMap<String, Vec<T>>,
            name: &str,
        ) -> Result<Vec<T>, TempFail> {
            if self.failing.iter().any(|f| f == name) {
                return Err(TempFail);
            }
            Ok(map.get(name).cloned().unwrap_or_default())
        }
    }

    impl Resolver for Zone {
        async fn txt(&self, name: &str) -> Result<Vec<String>, TempFail> {
            self.answer(&self.txt, name)
        }
        async fn addresses(&self, name: &str) -> Result<Vec<IpAddr>, TempFail> {
            self.answer(&self.addresses, name)
        }
        async fn mx(&self, name: &str) -> Result<Vec<String>, TempFail> {
            self.answer(&self.mx, name)
        }
    }

    fn check(zone: &Zone, ip: &str, domain: &str) -> SpfResult {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(check_host(zone, ip.parse().expect("ip"), domain))
    }

    #[test]
    fn records() {
        assert!(is_spf("v=spf1 -all"));
        assert!(is_spf("V=SPF1"));
        assert!(!is_spf("v=spf10 -all"));
        assert!(!is_spf("google-site-verification=x"));
        let none = Zone::default().txt("ex.test", "something else");
        assert_eq!(check(&none, "192.0.2.1", "ex.test"), SpfResult::None);
        let two = Zone::default()
            .txt("ex.test", "v=spf1 ip4:192.0.2.1 -all")
            .txt("ex.test", "v=spf1 mx -all");
        assert_eq!(
            check(&two, "192.0.2.1", "ex.test"),
            SpfResult::PermError,
            "two SPF records break SPF (Go passed them)"
        );
        let bad = Zone::default().txt("ex.test", "v=spf1 ip4:300.1.1.1 -all");
        assert_eq!(check(&bad, "192.0.2.1", "ex.test"), SpfResult::PermError);
        let unknown = Zone::default().txt("ex.test", "v=spf1 foo -all");
        assert_eq!(
            check(&unknown, "192.0.2.1", "ex.test"),
            SpfResult::PermError
        );
        let failing = Zone::default().failing("ex.test");
        assert_eq!(
            check(&failing, "192.0.2.1", "ex.test"),
            SpfResult::TempError
        );
    }

    #[test]
    fn networks() {
        let zone = Zone::default().txt(
            "ex.test",
            "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all exp=explain.ex.test",
        );
        assert_eq!(check(&zone, "192.0.2.77", "ex.test"), SpfResult::Pass);
        assert_eq!(check(&zone, "2001:db8::5", "ex.test"), SpfResult::Pass);
        assert_eq!(check(&zone, "198.51.100.1", "ex.test"), SpfResult::SoftFail);
        let exact = Zone::default().txt("ex.test", "v=spf1 +ip4:1.2.3.45 -all");
        assert_eq!(
            check(&exact, "1.2.3.4", "ex.test"),
            SpfResult::Fail,
            "Go's text match took ip4:1.2.3.45 for 1.2.3.4"
        );
        assert_eq!(
            check(&exact, "::ffff:1.2.3.45", "ex.test"),
            SpfResult::Pass,
            "IPv4-mapped addresses are IPv4"
        );
        let neutral = Zone::default().txt("ex.test", "v=spf1 ip4:10.0.0.1");
        assert_eq!(check(&neutral, "192.0.2.1", "ex.test"), SpfResult::Neutral);
        let zero = Zone::default().txt("ex.test", "v=spf1 ip4:0.0.0.0/0 -all");
        assert_eq!(check(&zero, "192.0.2.1", "ex.test"), SpfResult::Pass);
    }

    #[test]
    fn a_mx_and_includes() {
        let zone = Zone::default()
            .txt("ex.test", "v=spf1 a mx include:_spf.provider.test -all")
            .addr("ex.test", "203.0.113.1")
            .mx("ex.test", "mail.ex.test.")
            .addr("mail.ex.test", "192.0.2.10")
            .txt("_spf.provider.test", "v=spf1 ip4:198.51.100.0/24 -all");
        assert_eq!(check(&zone, "203.0.113.1", "ex.test"), SpfResult::Pass);
        assert_eq!(
            check(&zone, "192.0.2.10", "Ex.Test."),
            SpfResult::Pass,
            "the mail host is covered by `mx` (Go wanted it spelled out)"
        );
        assert_eq!(check(&zone, "198.51.100.9", "ex.test"), SpfResult::Pass);
        assert_eq!(check(&zone, "192.0.2.11", "ex.test"), SpfResult::Fail);

        let cidr = Zone::default()
            .txt("ex.test", "v=spf1 a:hosts.ex.test/28 mx//64 -all")
            .addr("hosts.ex.test", "192.0.2.16")
            .mx("ex.test", "mx.ex.test")
            .addr("mx.ex.test", "2001:db8::1");
        assert_eq!(check(&cidr, "192.0.2.31", "ex.test"), SpfResult::Pass);
        assert_eq!(check(&cidr, "192.0.2.32", "ex.test"), SpfResult::Fail);
        assert_eq!(check(&cidr, "2001:db8::abcd", "ex.test"), SpfResult::Pass);

        let missing = Zone::default().txt("ex.test", "v=spf1 include:gone.test -all");
        assert_eq!(
            check(&missing, "192.0.2.1", "ex.test"),
            SpfResult::PermError
        );
        let broken = Zone::default()
            .txt("ex.test", "v=spf1 include:down.test -all")
            .failing("down.test");
        assert_eq!(check(&broken, "192.0.2.1", "ex.test"), SpfResult::TempError);
    }

    #[test]
    fn redirects_limits_and_macros() {
        let zone = Zone::default()
            .txt("ex.test", "v=spf1 redirect=_spf.ex.test")
            .txt("_spf.ex.test", "v=spf1 ip4:192.0.2.1 -all");
        assert_eq!(check(&zone, "192.0.2.1", "ex.test"), SpfResult::Pass);
        assert_eq!(check(&zone, "192.0.2.2", "ex.test"), SpfResult::Fail);
        let to_nothing = Zone::default().txt("ex.test", "v=spf1 redirect=none.test");
        assert_eq!(
            check(&to_nothing, "192.0.2.1", "ex.test"),
            SpfResult::PermError
        );
        let ignored = Zone::default().txt("ex.test", "v=spf1 ip4:192.0.2.1 ?all redirect=x.test");
        assert_eq!(check(&ignored, "192.0.2.9", "ex.test"), SpfResult::Neutral);

        let mut chain = Zone::default();
        for i in 0..12 {
            chain = chain.txt(
                &format!("l{i}.test"),
                &format!("v=spf1 include:l{}.test -all", i + 1),
            );
        }
        chain = chain.txt("l12.test", "v=spf1 +all");
        assert_eq!(
            check(&chain, "192.0.2.1", "l0.test"),
            SpfResult::PermError,
            "more than ten DNS-querying terms"
        );

        let macros = Zone::default().txt(
            "ex.test",
            "v=spf1 exists:%{i}.bl.test include:%{d}.test ip4:192.0.2.1 -all",
        );
        assert_eq!(check(&macros, "192.0.2.1", "ex.test"), SpfResult::Pass);
        assert_eq!(check(&macros, "192.0.2.2", "ex.test"), SpfResult::Fail);
    }
}
