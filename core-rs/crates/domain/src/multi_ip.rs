//! Dedicated sending IPs per domain (Go: `service/multi_ip_domain`).
//!
//! Each domain with its own IP gets a Docker network (`172.66.N.0/24`)
//! that Postfix joins at `172.66.N.100`, a Postfix transport binding to
//! that address, and a host SNAT rule from the subnet to the IP. The
//! console writes `docker-compose_addnetwork.yml`; `bm.sh multi_ip` on the
//! host swaps it in and recreates the containers.

use std::net::Ipv4Addr;

/// A configuration row (`bm_multi_ip_domain`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DedicatedIp {
    pub domain: String,
    pub outbound_ip: String,
    pub network_name: String,
    pub subnet: String,
    pub postfix_ip: String,
    pub aliases: String,
    pub smtp_server_name: String,
}

/// Go's names for a new configuration, from the time it is added.
pub fn names(domain: &str, outbound_ip: &str, stamp: &str) -> (String, String, String) {
    (
        format!("smtp_bind_ip_{}_{stamp}", outbound_ip.replace('.', "_")),
        format!("billionmail-net-{stamp}"),
        format!("aliases-{}", domain.replace('.', "-")),
    )
}

/// The first free `172.66.N.0/24` (N from 2) and Postfix's address in it,
/// skipping the main network's own subnet.
pub fn next_subnet(used: &[String], main_prefix: &str) -> Option<(String, String)> {
    (2..=254u8).find_map(|n| {
        let subnet = format!("172.66.{n}.0/24");
        let taken = used.iter().any(|u| u == &subnet) || main_prefix == format!("172.66.{n}");
        (!taken).then(|| (subnet, format!("172.66.{n}.100")))
    })
}

/// Postfix's address on the main network: `<IPV4_NETWORK>.100` (Go wrote
/// `172.66.1.100` whatever `IPV4_NETWORK` said, which broke `docker
/// compose up` on a custom network).
pub fn main_postfix_ip(ipv4_network: Option<&str>) -> String {
    let prefix = ipv4_network
        .map(str::trim)
        .filter(|p| {
            let parts: Vec<&str> = p.split('.').collect();
            parts.len() == 3 && parts.iter().all(|o| o.parse::<u8>().is_ok())
        })
        .unwrap_or("172.66.1");
    format!("{prefix}.100")
}

fn indent_of(line: &str) -> &str {
    &line[..line.len() - line.trim_start_matches([' ', '\t']).len()]
}

fn gateway(subnet: &str) -> Option<String> {
    let (net, _) = subnet.split_once('/')?;
    let ip: Ipv4Addr = net.parse().ok()?;
    Some(Ipv4Addr::from(u32::from(ip) + 1).to_string())
}

/// Go's `addCustomNetworksText`: keeps the top-level `networks:` section's
/// `billionmail-network` and adds one network per configuration (earlier
/// ones are regenerated).
fn with_networks(lines: &[&str], configs: &[DedicatedIp]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let start = lines.iter().position(|l| l.starts_with("networks:"));
    let end = start.and_then(|s| {
        lines[s + 1..]
            .iter()
            .position(|l| l.starts_with("services:"))
            .map(|p| s + 1 + p)
    });
    let mut base = "  ".to_owned();
    match start {
        None => {
            out.extend(lines.iter().map(|l| (*l).to_owned()));
            out.push(String::new());
            out.push("networks:".to_owned());
        }
        Some(s) => {
            out.extend(lines[..=s].iter().map(|l| (*l).to_owned()));
            let mut inside = false;
            for line in &lines[s + 1..end.unwrap_or(lines.len())] {
                if line.contains("billionmail-network:") && !inside {
                    inside = true;
                    base = indent_of(line).to_owned();
                    out.push((*line).to_owned());
                } else if inside {
                    if line.trim().is_empty() || indent_of(line).len() > base.len() {
                        out.push((*line).to_owned());
                    } else {
                        break;
                    }
                }
            }
            while out.last().is_some_and(|l| l.trim().is_empty()) {
                out.pop();
            }
        }
    }
    let item = format!("{base}  ");
    for cfg in configs {
        out.push(format!("{base}{}:", cfg.network_name));
        out.push(format!("{item}driver: bridge"));
        out.push(format!("{item}ipam:"));
        out.push(format!("{item}  config:"));
        match gateway(&cfg.subnet) {
            Some(gw) => {
                out.push(format!("{item}    - gateway: {gw}"));
                out.push(format!("{item}      subnet: {}", cfg.subnet));
            }
            None => out.push(format!("{item}    - subnet: {}", cfg.subnet)),
        }
        out.push(format!("{item}  driver: default"));
    }
    if let Some(e) = end {
        out.push(String::new());
        out.extend(lines[e..].iter().map(|l| (*l).to_owned()));
    }
    out
}

/// Go's `modifyPostfixNetworksText`: Postfix's networks become the main
/// network at a fixed address plus one per configuration.
fn with_postfix_networks(
    lines: &[String],
    configs: &[DedicatedIp],
    main_ip: &str,
) -> Result<Vec<String>, &'static str> {
    let service = lines
        .iter()
        .position(|l| l.trim_end().ends_with("postfix-billionmail:"))
        .ok_or("postfix-billionmail service not found")?;
    let service_indent = indent_of(&lines[service]).len();
    let networks = lines[service + 1..]
        .iter()
        .take_while(|l| l.trim().is_empty() || indent_of(l).len() > service_indent)
        .position(|l| l.trim() == "networks:")
        .map(|p| service + 1 + p)
        .ok_or("postfix-billionmail networks section not found")?;
    let key_indent = indent_of(&lines[networks]).len();
    let end = lines[networks + 1..]
        .iter()
        .position(|l| !l.trim().is_empty() && indent_of(l).len() <= key_indent)
        .map(|p| networks + 1 + p);
    let pad = " ".repeat(key_indent + 2);
    let mut out: Vec<String> = lines[..=networks].to_vec();
    let entry = |name: &str, alias: &str, ip: &str| {
        vec![
            format!("{pad}{name}:"),
            format!("{pad}  aliases:"),
            format!("{pad}    - {alias}"),
            format!("{pad}  ipv4_address: {ip}"),
        ]
    };
    out.extend(entry("billionmail-network", "postfix", main_ip));
    for cfg in configs {
        out.extend(entry(&cfg.network_name, &cfg.aliases, &cfg.postfix_ip));
    }
    if let Some(e) = end {
        // Keep the blank lines between services (Go dropped them).
        let blanks = lines[networks + 1..e]
            .iter()
            .rev()
            .take_while(|l| l.trim().is_empty())
            .count();
        out.extend(std::iter::repeat_n(String::new(), blanks));
        out.extend(lines[e..].iter().cloned());
    }
    Ok(out)
}

/// `docker-compose_addnetwork.yml` for `configs`.
pub fn compose_with_networks(
    original: &str,
    configs: &[DedicatedIp],
    main_ip: &str,
) -> Result<String, &'static str> {
    let lines: Vec<&str> = original.split('\n').collect();
    let networks = with_networks(&lines, configs);
    Ok(with_postfix_networks(&networks, configs, main_ip)?.join("\n"))
}

pub const MASTER_BEGIN: &str = "# BEGIN BILLIONMAIL multi-ip services";
pub const MASTER_END: &str = "# END BILLIONMAIL multi-ip services";

/// `master.cf` with one transport per configuration, bound to Postfix's
/// address on that domain's network.
pub fn apply_master(content: &str, configs: &[DedicatedIp]) -> String {
    let mut block = format!("{MASTER_BEGIN}\n");
    for cfg in configs {
        block.push_str(&format!(
            "{:<10} unix  -       -       n       -       -       smtp\n    -o smtp_bind_address={}\n",
            cfg.smtp_server_name, cfg.postfix_ip
        ));
    }
    block.push_str(MASTER_END);
    match (content.find(MASTER_BEGIN), content.find(MASTER_END)) {
        (Some(b), Some(e)) if b < e => format!(
            "{}{block}{}",
            &content[..b],
            &content[e + MASTER_END.len()..]
        ),
        _ => format!("{content}\n{block}"),
    }
}

const RELAY_MAP: &str = "pgsql:/etc/postfix/sql/pgsql_sender_relay_maps.cf";

/// Go's `updateMainCf`: a default `smtp_bind_address` and the relay map
/// the dedicated transports rely on.
pub fn apply_main(content: &str, main_ip: &str) -> String {
    let values = crate::postfix::main_cf_values(content);
    let mut changes: Vec<(&str, String)> = Vec::new();
    if values
        .get("smtp_bind_address")
        .is_none_or(|v| v.trim().is_empty())
    {
        changes.push(("smtp_bind_address", main_ip.to_owned()));
    }
    match values.get("sender_dependent_relayhost_maps") {
        Some(v) if v.contains(RELAY_MAP) => {}
        Some(v) if !v.trim().is_empty() => {
            changes.push((
                "sender_dependent_relayhost_maps",
                format!("{RELAY_MAP}, {v}"),
            ));
        }
        _ => changes.push(("sender_dependent_relayhost_maps", RELAY_MAP.to_owned())),
    }
    let refs: Vec<(&str, &str)> = changes.iter().map(|(k, v)| (*k, v.as_str())).collect();
    if refs.is_empty() {
        content.to_owned()
    } else {
        crate::postfix::set_main_cf(content, &refs)
    }
}

/// Replaces this platform's SNAT rules on the host in one run. The rules
/// come as `<subnet> <ip>` argument pairs, never parsed by the shell (Go
/// pasted them into a `sh -c` string for each rule), and old rules are
/// deleted by their specification (Go deleted by line number, which moves
/// when Docker changes the chain meanwhile).
pub const IPTABLES_SCRIPT: &str = r#"set -u
iptables -t nat -S POSTROUTING | grep -- '--comment billionmail-outbound' | sed 's/^-A /-D /' |
while read -r rule; do
  iptables -t nat $rule || echo "failed to delete: $rule" >&2
done
rc=0
while [ $# -ge 2 ]; do
  iptables -t nat -I POSTROUTING -s "$1" -j SNAT --to-source "$2" -m comment --comment billionmail-outbound || rc=1
  shift 2
done
exit $rc"#;

/// The script's arguments for the configurations that parse as an IPv4
/// subnet and address.
pub fn snat_args(configs: &[(String, String)]) -> Vec<String> {
    configs
        .iter()
        .filter(|(subnet, ip)| {
            subnet.parse::<ipnet::Ipv4Net>().is_ok() && ip.parse::<Ipv4Addr>().is_ok()
        })
        .flat_map(|(subnet, ip)| [subnet.clone(), ip.clone()])
        .collect()
}

/// Go's SPF advice for a dedicated IP: `None` when the record authorises
/// it.
pub fn spf_advice(
    record: Option<&str>,
    outbound_ip: &str,
    domain: &str,
    mail_host: &str,
) -> Option<String> {
    let Some(record) = record else {
        return Some(format!("SPF record not found for domain '{domain}'"));
    };
    let spf = record.trim().trim_matches('"').to_ascii_lowercase();
    if !spf.starts_with("v=spf1") {
        return Some(format!(
            "SPF record is malformed: does not start with 'v=spf1': {record}"
        ));
    }
    if !spf.ends_with("~all") && !spf.ends_with("-all") {
        return Some(format!(
            "SPF record should end with '~all' or '-all' for proper policy enforcement: {record}"
        ));
    }
    let terms: Vec<&str> = spf.split_whitespace().collect();
    let authorised = terms.iter().any(|t| {
        let t = t.trim_start_matches(['+', '?', '~']);
        t == format!("ip4:{outbound_ip}")
            || t == "a"
            || t.starts_with("a:")
            || t.starts_with("a/")
            || *t == format!("include:{domain}")
            || *t == format!("include:{mail_host}")
    });
    (!authorised).then(|| {
        format!(
            "It is recommended to add 'a', 'ip4:{outbound_ip}', or 'include:{domain}' in the SPF record to ensure proper authorization of this IP for sending emails."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(n: u8, domain: &str) -> DedicatedIp {
        DedicatedIp {
            domain: domain.into(),
            outbound_ip: format!("203.0.113.{n}"),
            network_name: format!("billionmail-net-{n}"),
            subnet: format!("172.66.{n}.0/24"),
            postfix_ip: format!("172.66.{n}.100"),
            aliases: format!("aliases-{}", domain.replace('.', "-")),
            smtp_server_name: format!("smtp_bind_ip_{n}"),
        }
    }

    #[test]
    fn subnets_and_names() {
        assert_eq!(
            next_subnet(&["172.66.2.0/24".into()], "172.66.1"),
            Some(("172.66.3.0/24".into(), "172.66.3.100".into()))
        );
        assert_eq!(
            next_subnet(&[], "172.66.2").map(|s| s.0).as_deref(),
            Some("172.66.3.0/24")
        );
        assert_eq!(main_postfix_ip(Some("172.70.1")), "172.70.1.100");
        assert_eq!(main_postfix_ip(Some("bad")), "172.66.1.100");
        assert_eq!(
            names("ex.test", "1.2.3.4", "20260101000000"),
            (
                "smtp_bind_ip_1_2_3_4_20260101000000".into(),
                "billionmail-net-20260101000000".into(),
                "aliases-ex-test".into()
            )
        );
    }

    #[test]
    fn rewrites_the_shipped_compose_file() {
        let shipped = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docker-compose.yml"),
        )
        .expect("docker-compose.yml");
        let configs = [config(2, "a.test"), config(3, "b.test")];
        let out = compose_with_networks(&shipped, &configs, "172.66.1.100").expect("compose");
        assert!(out.contains(
            "        billionmail-network:\n          aliases:\n            - postfix\n          ipv4_address: 172.66.1.100\n        billionmail-net-2:\n          aliases:\n            - aliases-a-test\n          ipv4_address: 172.66.2.100\n"
        ), "{out}");
        assert!(out.contains(
            "  billionmail-net-3:\n    driver: bridge\n    ipam:\n      config:\n        - gateway: 172.66.3.1\n          subnet: 172.66.3.0/24\n      driver: default"
        ));
        assert!(out.contains("            - aliases-b-test\n          ipv4_address: 172.66.3.100\n\n\n    webmail-billionmail:"), "blank lines kept");
        assert!(
            out.contains("com.docker.network.bridge.name: br-billionmail"),
            "main network kept"
        );
        // Applying again regenerates rather than piling up.
        let again = compose_with_networks(&out, &configs, "172.66.1.100").expect("again");
        assert_eq!(again, out);
        let none = compose_with_networks(&out, &[], "172.66.1.100").expect("none");
        assert!(!none.contains("billionmail-net-"));
    }

    #[test]
    fn postfix_files() {
        let master = apply_master("smtp inet n - n - - smtpd\n", &[config(2, "a.test")]);
        assert!(master.ends_with(
            "\n# BEGIN BILLIONMAIL multi-ip services\nsmtp_bind_ip_2 unix  -       -       n       -       -       smtp\n    -o smtp_bind_address=172.66.2.100\n# END BILLIONMAIL multi-ip services"
        ), "{master}");
        assert_eq!(apply_master(&master, &[config(2, "a.test")]), master);
        let main = apply_main("myhostname = x\n", "172.66.1.100");
        assert_eq!(
            main,
            "myhostname = x\nsmtp_bind_address = 172.66.1.100\nsender_dependent_relayhost_maps = pgsql:/etc/postfix/sql/pgsql_sender_relay_maps.cf\n"
        );
        assert_eq!(apply_main(&main, "172.66.1.100"), main);
    }

    #[test]
    fn snat_and_spf() {
        assert_eq!(
            snat_args(&[
                ("172.66.2.0/24".into(), "203.0.113.2".into()),
                ("172.66.3.0/24; reboot".into(), "1.2.3.4".into()),
            ]),
            ["172.66.2.0/24", "203.0.113.2"]
        );
        assert_eq!(
            spf_advice(
                Some("v=spf1 ip4:1.2.3.4 -all"),
                "1.2.3.4",
                "a.test",
                "mail.a.test"
            ),
            None
        );
        assert_eq!(
            spf_advice(
                Some("\"v=spf1 +a ~all\""),
                "1.2.3.4",
                "a.test",
                "mail.a.test"
            ),
            None
        );
        assert!(spf_advice(Some("v=spf1 ip4:9.9.9.9 -all"), "1.2.3.4", "a.test", "m").is_some());
        assert!(spf_advice(Some("v=spf1 ip4:1.2.3.4"), "1.2.3.4", "a.test", "m").is_some());
        assert!(spf_advice(None, "1.2.3.4", "a.test", "m").is_some());
    }
}
