//! DNS blocklist checks of a mail host's address (Go:
//! `domains/blacklist.go`).

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// The blocklists queried: Go's list without its duplicates and without the
/// domain lists (SURBL, URIBL), which list domains, not addresses.
pub const ZONES: &[&str] = &[
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "http.dnsbl.sorbs.net",
    "misc.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "web.dnsbl.sorbs.net",
    "rbl.spamlab.com",
    "cbl.anti-spam.org.cn",
    "httpbl.abuse.ch",
    "virbl.bit.nl",
    "dsn.rfc-ignorant.org",
    "opm.tornevall.org",
    "relays.mail-abuse.org",
    "rbl-plus.mail-abuse.org",
    "rbl.interserver.net",
    "dul.dnsbl.sorbs.net",
    "smtp.dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "zombie.dnsbl.sorbs.net",
    "drone.abuse.ch",
    "rbl.suresupport.com",
    "spamguard.leadmon.net",
    "netblock.pedantic.org",
    "blackholes.mail-abuse.org",
    "dnsbl.dronebl.org",
    "query.senderbase.org",
    "csi.cloudmark.com",
    "0spam-killlist.fusionzero.com",
    "access.redhawk.org",
    "all.rbl.jp",
    "all.spam-rbl.fr",
    "all.spamrats.com",
    "aspews.ext.sorbs.net",
    "b.barracudacentral.org",
    "backscatter.spameatingmonkey.net",
    "badnets.spameatingmonkey.net",
    "bb.barracudacentral.org",
    "bl.drmx.org",
    "bl.konstant.no",
    "bl.nszones.com",
    "bl.spamcannibal.org",
    "bl.spameatingmonkey.net",
    "bl.spamstinks.com",
    "black.junkemailfilter.com",
    "blackholes.five-ten-sg.com",
    "blacklist.sci.kun.nl",
    "blacklist.woody.ch",
    "bogons.cymru.com",
    "bsb.empty.us",
    "bsb.spamlookup.net",
    "cart00ney.surriel.com",
    "cbl.abuseat.org",
    "cblless.anti-spam.org.cn",
    "cblplus.anti-spam.org.cn",
    "cdl.anti-spam.org.cn",
    "cidr.bl.mcafee.com",
    "combined.rbl.msrbl.net",
    "db.wpbl.info",
    "dev.null.dk",
    "dialups.visi.com",
    "dnsbl-0.uceprotect.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.anticaptcha.net",
    "dnsbl.aspnet.hu",
    "dnsbl.inps.de",
    "dnsbl.justspam.org",
    "dnsbl.kempt.net",
    "dnsbl.madavi.de",
    "dnsbl.rizon.net",
    "dnsbl.rv-soft.info",
    "dnsbl.rymsho.ru",
    "dnsbl.zapbl.net",
    "dnsrbl.swinog.ch",
    "dul.pacifier.net",
    "dyn.nszones.com",
    "dyna.spamrats.com",
    "fnrbl.fast.net",
    "fresh.spameatingmonkey.net",
    "hostkarma.junkemailfilter.com",
    "images.rbl.msrbl.net",
    "ips.backscatterer.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "l2.bbfh.ext.sorbs.net",
    "l3.bbfh.ext.sorbs.net",
    "l4.bbfh.ext.sorbs.net",
    "list.bbfh.org",
    "list.blogspambl.com",
    "mail-abuse.blacklist.jippg.org",
    "netbl.spameatingmonkey.net",
    "netscan.rbl.blockedservers.com",
    "no-more-funn.moensted.dk",
    "noptr.spamrats.com",
    "orvedb.aupads.org",
    "pbl.spamhaus.org",
    "phishing.rbl.msrbl.net",
    "pofon.foobar.hu",
    "psbl.surriel.com",
    "rbl.abuse.ro",
    "rbl.blockedservers.com",
    "rbl.dns-servicios.com",
    "rbl.efnet.org",
    "rbl.efnetrbl.org",
    "rbl.iprange.net",
    "rbl.schulte.org",
    "rbl.talkactive.net",
    "rbl2.triumf.ca",
    "rsbl.aupads.org",
    "sbl-xbl.spamhaus.org",
    "sbl.nszones.com",
    "sbl.spamhaus.org",
    "short.rbl.jp",
    "spam.dnsbl.anonmails.de",
    "spam.pedantic.org",
    "spam.rbl.blockedservers.com",
    "spam.rbl.msrbl.net",
    "spam.spamrats.com",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "st.technovision.dk",
    "tor.dan.me.uk",
    "tor.dnsbl.sectoor.de",
    "tor.efnet.org",
    "torexit.dan.me.uk",
    "truncate.gbudb.net",
    "ubl.unsubscore.com",
    "virbl.dnsbl.bit.nl",
    "virus.rbl.jp",
    "virus.rbl.msrbl.net",
    "vote.drbl.caravan.ru",
    "vote.drbl.gremlin.ru",
    "web.rbl.msrbl.net",
    "work.drbl.caravan.ru",
    "work.drbl.gremlin.ru",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "zen.spamhaus.org",
];

/// What a blocklist said about an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// No record: not listed.
    NotListed,
    Address(Ipv4Addr),
    /// No usable answer (timeout, server failure).
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clear,
    Listed,
    Invalid,
}

/// Go's reading of a blocklist's answer, except that `127.255.255.x`
/// counts as unusable: it is how Spamhaus refuses a query (for instance one
/// relayed by a public resolver), which Go counted as passed.
pub fn classify(answer: &Answer) -> Verdict {
    match answer {
        Answer::NotListed => Verdict::Clear,
        Answer::Failed => Verdict::Invalid,
        Answer::Address(ip) => {
            let [a, b, c, d] = ip.octets();
            if a != 127 || (b == 255 && c == 255) {
                Verdict::Invalid
            } else if matches!((b, c, d), (0, 0, 1) | (0, 1, 1) | (0, 0, 7)) {
                Verdict::Clear
            } else if b == 0 && c == 0 {
                Verdict::Listed
            } else {
                Verdict::Clear
            }
        }
    }
}

/// The DNS name to query for `ip` on `zone`.
pub fn query_name(ip: Ipv4Addr, zone: &str) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.{zone}")
}

/// One listing (Go's `BlacklistDetail`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub blacklist: String,
    pub response: String,
    pub time: i64,
}

/// A check's outcome, as Go stored it in `blcheck_count.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub time: i64,
    #[serde(default)]
    pub tested: i64,
    #[serde(default)]
    pub passed: i64,
    #[serde(default)]
    pub invalid: i64,
    #[serde(default)]
    pub blacklisted: i64,
    #[serde(default)]
    pub black_list: Vec<Listing>,
}

/// A log line in Go's format.
pub fn log_line(date: &str, zone: &str, answer: &Answer, verdict: Verdict) -> String {
    let response = match answer {
        Answer::Address(ip) => Some(ip.to_string()),
        _ => None,
    };
    match (verdict, response) {
        (Verdict::Clear, None) => format!("{date}: {zone} -----------------------------  √\n"),
        (Verdict::Clear, Some(r)) => {
            format!("{date}: {zone} ----------------------------- √ ({r})\n")
        }
        (Verdict::Listed, r) => format!(
            "{date}: {zone} ----------------------------- x   blacklisted ({})\n",
            r.unwrap_or_default()
        ),
        (Verdict::Invalid, _) => format!("{date}: {zone} ----------------------------- Invalid\n"),
    }
}

/// The closing lines of a check's log, in Go's format.
pub fn log_summary(date: &str, result: &CheckResult) -> String {
    format!(
        "---------------------------------------------------------------------------------------  \n\
         Results for {}: \nIp: {} \nTested: {} \nPassed: {} \nInvalid: {} \nBlacklisted: {} \n\
         ---------------------------------------------------------------------------------------   \n\
         {date}:  Check finished\n",
        result.domain, result.ip, result.tested, result.passed, result.invalid, result.blacklisted
    )
}

/// The name of a host's check log (`<host>_blcheck.txt`).
pub fn log_file(host: &str) -> String {
    format!("{host}_blcheck.txt")
}

/// The host a log file name belongs to, for names this module writes only.
pub fn host_of_log(name: &str) -> Option<&str> {
    let host = name.strip_suffix("_blcheck.txt")?;
    crate::settings::is_valid_hostname(host).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        let addr = |s: &str| Answer::Address(s.parse().expect("ip"));
        assert_eq!(classify(&Answer::NotListed), Verdict::Clear);
        assert_eq!(classify(&Answer::Failed), Verdict::Invalid);
        assert_eq!(classify(&addr("127.0.0.2")), Verdict::Listed);
        assert_eq!(classify(&addr("127.0.0.11")), Verdict::Listed);
        assert_eq!(classify(&addr("127.0.0.1")), Verdict::Clear);
        assert_eq!(classify(&addr("127.0.1.2")), Verdict::Clear);
        assert_eq!(
            classify(&addr("127.255.255.254")),
            Verdict::Invalid,
            "Spamhaus refusing a public resolver is not a pass"
        );
        assert_eq!(classify(&addr("10.0.0.1")), Verdict::Invalid);
        assert_eq!(
            query_name("203.0.113.9".parse().expect("ip"), "zen.spamhaus.org"),
            "9.113.0.203.zen.spamhaus.org"
        );
    }

    #[test]
    fn list_and_logs() {
        let mut unique = ZONES.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ZONES.len(), "no duplicates");
        assert!(
            !ZONES
                .iter()
                .any(|z| z.contains("surbl") || z.contains("uribl"))
        );
        assert_eq!(
            log_line("D", "z.test", &Answer::NotListed, Verdict::Clear),
            "D: z.test -----------------------------  √\n"
        );
        assert_eq!(
            host_of_log("mail.ex.test_blcheck.txt"),
            Some("mail.ex.test")
        );
        assert_eq!(host_of_log("../../etc/passwd"), None);
        assert_eq!(host_of_log("../x_blcheck.txt"), None);
    }
}
