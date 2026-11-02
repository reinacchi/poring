//! Client IP resolution behind trusted reverse proxies.
//!
//! By default the client IP is the address of the TCP peer and `X-Forwarded-For` is
//! ignored, because any client can send that header. When the peer is one of the
//! configured trusted proxies, the header is read from right to left: trusted hops are
//! skipped and the first untrusted address is the client. A client can therefore only
//! prepend entries that are never reached, and cannot choose its own rate-limit identity.

use std::net::IpAddr;
use std::str::FromStr;

use http::HeaderMap;

use super::rate_limit::canonical_ip;

/// An IP network in CIDR notation (`10.0.0.0/8`, `2001:db8::/32`) or a single address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Whether `ip` is inside the network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, canonical_ip(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let rest = prefix % 8;
    if a[..full] != b[..full] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    (a[full] & mask) == (b[full] & mask)
}

impl FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{s}` is not an IP address or CIDR network"))?;
        let addr = canonical_ip(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("`{s}` has an invalid prefix length (0..={max})"))?,
        };
        if prefix == 0 {
            return Err(format!(
                "`{s}` would trust every address; list the proxies' own addresses instead"
            ));
        }
        Ok(IpNet { addr, prefix })
    }
}

/// The proxies whose `X-Forwarded-For` entries are believed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    /// Parses addresses and CIDR networks. Fails on any invalid entry.
    pub fn parse<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let nets = entries
            .into_iter()
            .map(|e| e.as_ref().parse())
            .collect::<Result<Vec<IpNet>, String>>()?;
        Ok(TrustedProxies { nets })
    }

    /// Whether no proxy is trusted (the peer address is always the client).
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Whether `ip` is a trusted proxy.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }

    /// The client address for a request received from `peer`.
    ///
    /// Malformed `X-Forwarded-For` entries end the walk at the last trusted hop, so the
    /// request is attributed to that proxy rather than to an attacker-chosen address.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let mut client = canonical_ip(peer);
        if !self.contains(client) {
            return client;
        }
        let hops = headers
            .get_all(http::header::HeaderName::from_static("x-forwarded-for"))
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect::<Vec<_>>();
        for hop in hops.iter().rev() {
            let Ok(ip) = hop.parse::<IpAddr>() else { break };
            client = canonical_ip(ip);
            if !self.contains(client) {
                break;
            }
        }
        client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in xff {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn networks() {
        let n: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(n.contains(ip("10.1.2.3")) && !n.contains(ip("11.0.0.1")));
        assert!(
            n.contains(ip("::ffff:10.0.0.1")),
            "IPv4-mapped addresses match IPv4 networks"
        );
        let v6: IpNet = "2001:db8::/33".parse().unwrap();
        assert!(v6.contains(ip("2001:db8:7fff::1")) && !v6.contains(ip("2001:db8:8000::1")));
        for bad in ["10.0.0.0/33", "0.0.0.0/0", "::/0", "proxy", "10.0.0.0/x"] {
            assert!(bad.parse::<IpNet>().is_err(), "{bad}");
        }
    }

    #[test]
    fn untrusted_peers_cannot_spoof() {
        let none = TrustedProxies::default();
        let h = headers(&["1.1.1.1"]);
        assert_eq!(none.client_ip(ip("203.0.113.9"), &h), ip("203.0.113.9"));
        let lb = TrustedProxies::parse(["10.0.0.0/8"]).unwrap();
        assert_eq!(
            lb.client_ip(ip("203.0.113.9"), &h),
            ip("203.0.113.9"),
            "peer is not a proxy"
        );
    }

    #[test]
    fn trusted_chains_are_read_from_the_right() {
        let lb = TrustedProxies::parse(["10.0.0.0/8", "192.168.0.1"]).unwrap();
        // The client prepended a fake address; the load balancer appended the real one.
        let h = headers(&["6.6.6.6, 198.51.100.7", "192.168.0.1"]);
        assert_eq!(lb.client_ip(ip("10.0.0.2"), &h), ip("198.51.100.7"));
        assert_eq!(lb.client_ip(ip("10.0.0.2"), &headers(&[])), ip("10.0.0.2"));
        assert_eq!(
            lb.client_ip(ip("10.0.0.2"), &headers(&["10.0.0.3"])),
            ip("10.0.0.3")
        );
        assert_eq!(
            lb.client_ip(ip("10.0.0.2"), &headers(&["198.51.100.7, garbage"])),
            ip("10.0.0.2"),
            "a malformed hop stops at the last trusted proxy"
        );
        assert_eq!(
            lb.client_ip(ip("10.0.0.2"), &headers(&["::ffff:198.51.100.7"])),
            ip("198.51.100.7")
        );
    }
}
