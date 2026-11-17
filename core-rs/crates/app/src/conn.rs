//! Connection metadata and client IP resolution.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Inserted into every request by the listener.
#[derive(Debug, Clone, Copy)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    pub tls: bool,
}

/// The client address after trusted-proxy resolution, inserted by the edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Resolves the real client address.
///
/// Go used the first `X-Forwarded-For` entry from anyone, so any client could
/// claim to be `127.0.0.1` and pass the IP whitelist. Here forwarding headers
/// are honoured only when the TCP peer is a configured trusted proxy, and the
/// chain is read right to left, stopping at the first untrusted hop.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    if !is_trusted(peer, trusted) {
        return peer;
    }

    let chain: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .collect();

    chain
        .iter()
        .rev()
        .find(|ip| !is_trusted(**ip, trusted))
        .or(chain.first())
        .copied()
        .unwrap_or(peer)
}

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_str(xff).expect("header"),
        );
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let got = client_ip(ip("203.0.113.9"), &headers("127.0.0.1"), &[]);
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn trusted_proxy_chain_is_read_right_to_left() {
        let trusted = vec!["10.0.0.0/8".parse().expect("net")];
        let got = client_ip(
            ip("10.0.0.2"),
            &headers("127.0.0.1, 198.51.100.7, 10.0.0.5"),
            &trusted,
        );
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn trusted_proxy_without_header_is_the_client() {
        let trusted = vec!["10.0.0.0/8".parse().expect("net")];
        assert_eq!(
            client_ip(ip("10.0.0.2"), &HeaderMap::new(), &trusted),
            ip("10.0.0.2")
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_canonicalised() {
        let got = client_ip(ip("::ffff:192.0.2.1"), &HeaderMap::new(), &[]);
        assert_eq!(got, ip("192.0.2.1"));
    }
}
