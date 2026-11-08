//! Connect-time destination scope enforcement (Max-Parity Sprint 2.3,
//! issues #6 and #8).
//!
//! Target admission (`policy.rs`) gates *which hosts* may be scanned, but a
//! hostname is resolved to an address only when the scan connects — DNS
//! rebinding can swap an approved name for a disallowed address, and HTTP
//! redirects can walk a probe off-target. This module provides the shared
//! connect-time checks:
//!
//! * [`classify_ip`] — the full address taxonomy (v4-mapped unwrap, ULA,
//!   link-local, cloud metadata, loopback, private v4, documentation,
//!   unspecified, global unicast).
//! * [`OutboundPolicy`] — deployment-configurable destination policy
//!   (`SECUSCAN_OUTBOUND_ALLOW_PRIVATE` for authorized lab scanning,
//!   `SECUSCAN_OUTBOUND_ALLOWED_CIDRS` for explicit lab ranges).
//! * [`resolve_and_check`] — resolve a host and validate **every** answer;
//!   callers connect only to the returned (pinned) addresses.
//!
//! Deterministic, network-free classification is fully unit-tested; the
//! DNS-touching helpers reuse the same classification.

use std::net::{IpAddr, SocketAddr};

/// Coarse scope of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScope {
    Loopback,
    /// RFC 1918 (10/8, 172.16/12, 192.168/16) and IPv6 ULA (fc00::/7).
    Private,
    /// Link-local (169.254/16, fe80::/10) — includes cloud metadata
    /// endpoints (169.254.169.254), flagged separately for clarity.
    LinkLocal,
    /// Cloud metadata service addresses.
    Metadata,
    /// RFC 3849 documentation ranges (192.0.2/24, 198.51.100/24,
    /// 203.0.113/24, 2001:db8::/32).
    Documentation,
    Unspecified,
    Global,
}

/// Classify an address. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unwrapped
/// and classified as its embedded IPv4 — `::ffff:127.0.0.1` is loopback.
pub fn classify_ip(ip: IpAddr) -> IpScope {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped / v4-translated forms first.
            if let Some(v4) = to_ipv4_mapped(v6) {
                return classify_v4(v4);
            }
            let seg = v6.octets();
            if v6.is_loopback() {
                IpScope::Loopback
            } else if v6.is_unspecified() {
                IpScope::Unspecified
            } else if (seg[0] & 0xfe) == 0xfc {
                IpScope::Private // unique-local fc00::/7
            } else if (seg[0] & 0xff) == 0xfe && (seg[1] & 0xc0) == 0x80 {
                IpScope::LinkLocal // fe80::/10
            } else if seg[0] == 0x20 && seg[1] == 0x01 && seg[2] == 0x0d && seg[3] == 0xb8 {
                IpScope::Documentation // 2001:db8::/32
            } else {
                IpScope::Global
            }
        }
    }
}

fn classify_v4(v4: std::net::Ipv4Addr) -> IpScope {
    let o = v4.octets();
    if v4.is_loopback() {
        IpScope::Loopback
    } else if v4.is_unspecified() {
        IpScope::Unspecified
    } else if o[0] == 169 && o[1] == 254 {
        if o[2] == 169 && o[3] == 254 {
            IpScope::Metadata // 169.254.169.254 cloud metadata
        } else {
            IpScope::LinkLocal
        }
    } else if v4.is_private() {
        IpScope::Private
    } else if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        IpScope::Documentation
    } else {
        IpScope::Global
    }
}

/// Unwrap `::ffff:a.b.c.d` (and the NAT64-form `64:ff9b::a.b.c.d`).
fn to_ipv4_mapped(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let seg = v6.octets();
    if seg[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        Some(std::net::Ipv4Addr::new(seg[12], seg[13], seg[14], seg[15]))
    } else if seg[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0xff] {
        Some(std::net::Ipv4Addr::new(seg[12], seg[13], seg[14], seg[15]))
    } else {
        None
    }
}

/// Deployment-configurable outbound destination policy (issues #6/#8).
///
/// Defaults to deny-private: webhook receivers and scanner destinations that
/// resolve to loopback/private/link-local/metadata addresses are rejected
/// unless the operator explicitly authorizes them — which is how authorized
/// internal-lab scanning opts in, without weakening the default.
#[derive(Debug, Clone)]
pub struct OutboundPolicy {
    pub allow_private: bool,
    pub allowed_cidrs: Vec<IpNet>,
}

/// Public wrapper over policy.rs's network matcher so net_scope can reuse it.
#[derive(Debug, Clone)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn parse(s: &str) -> Option<Self> {
        s.trim().parse::<IpAddr>().ok().map(|addr| match addr {
            IpAddr::V4(_) => IpNet { addr, prefix: 32 },
            IpAddr::V6(_) => IpNet { addr, prefix: 128 },
        })
        .or_else(|| {
            // a.b.c.d/len form
            let (a, p) = s.split_once('/')?;
            let addr: IpAddr = a.trim().parse().ok()?;
            let max = match addr {
                IpAddr::V4(_) => 32u8,
                IpAddr::V6(_) => 128,
            };
            let prefix = p.trim().parse::<u8>().ok().filter(|p| *p <= max)?;
            Some(IpNet { addr, prefix })
        })
    }

    pub fn contains(&self, other: &IpAddr) -> bool {
        match (self.addr, other) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                (u128::from_be_bytes(net.octets()) & mask)
                    == (u128::from_be_bytes(ip.octets()) & mask)
            }
            _ => false,
        }
    }
}

impl OutboundPolicy {
    pub fn from_env() -> Self {
        let allow_private =
            std::env::var("SECUSCAN_OUTBOUND_ALLOW_PRIVATE").ok().as_deref() == Some("true");
        let allowed_cidrs = std::env::var("SECUSCAN_OUTBOUND_ALLOWED_CIDRS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .filter_map(IpNet::parse)
                    .collect()
            })
            .unwrap_or_default();
        OutboundPolicy {
            allow_private,
            allowed_cidrs,
        }
    }

    /// Is this address connectable under the policy? Note: explicitly
    /// allow-listed CIDRs override everything, including the metadata
    /// endpoint (an operator may genuinely want to probe it in a lab).
    pub fn check(&self, ip: IpAddr) -> Result<(), String> {
        let scope = classify_ip(ip);
        if scope == IpScope::Global {
            return Ok(());
        }
        if self.allowed_cidrs.iter().any(|c| c.contains(&ip)) {
            return Ok(());
        }
        if self.allow_private
            && matches!(
                scope,
                IpScope::Loopback | IpScope::Private | IpScope::LinkLocal
            )
        {
            return Ok(());
        }
        if scope == IpScope::Metadata {
            return Err(format!(
                "{ip} is a cloud metadata endpoint — blocked by outbound policy"
            ));
        }
        Err(format!(
            "{ip} resolves to a non-global address ({scope:?}) and the outbound \
             policy does not allow private destinations; set \
             SECUSCAN_OUTBOUND_ALLOW_PRIVATE or SECUSCAN_OUTBOUND_ALLOWED_CIDRS \
             for authorized lab scanning"
        ))
    }

    /// Resolve `host` and validate **every** DNS answer (issue #6: a single
    /// passing answer must not let the rest of a rebinding set through).
    /// Blocking DNS — call from a blocking context or `spawn_blocking`.
    pub fn resolve_and_check(&self, host: &str) -> Result<Vec<SocketAddr>, String> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = format!("{host}:0")
            .to_socket_addrs()
            .map_err(|e| format!("resolve {host}: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("resolve {host}: no addresses"));
        }
        // Deduplicate by IP (ports are all 0 here).
        let mut seen = Vec::new();
        for sa in addrs {
            self.check(sa.ip())?;
            if !seen.contains(&sa.ip()) {
                seen.push(sa.ip());
            }
        }
        Ok(seen
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 0))
            .collect())
    }
}

/// True when a redirect stays on the same target host (string comparison of
/// the host component, case-insensitive, trailing dot stripped). Redirects
/// to a different host are rejected by the scanners' redirect policy — the
/// off-target walk is the issue #6 escape hatch this closes.
pub fn same_host(from: &str, to_host: &str) -> bool {
    let norm = |h: &str| h.trim_end_matches('.').to_ascii_lowercase();
    norm(from) == norm(to_host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn c(s: &str) -> IpScope {
        classify_ip(s.parse::<IpAddr>().unwrap())
    }

    #[test]
    fn classification_matrix() {
        assert_eq!(c("127.0.0.1"), IpScope::Loopback);
        assert_eq!(c("10.0.0.5"), IpScope::Private);
        assert_eq!(c("172.16.1.1"), IpScope::Private);
        assert_eq!(c("192.168.1.1"), IpScope::Private);
        assert_eq!(c("169.254.1.1"), IpScope::LinkLocal);
        assert_eq!(c("169.254.169.254"), IpScope::Metadata);
        assert_eq!(c("8.8.8.8"), IpScope::Global);
        assert_eq!(c("1.1.1.1"), IpScope::Global);
        assert_eq!(c("192.0.2.9"), IpScope::Documentation);
        assert_eq!(c("0.0.0.0"), IpScope::Unspecified);
        // v6
        assert_eq!(c("::1"), IpScope::Loopback);
        assert_eq!(c("::"), IpScope::Unspecified);
        assert_eq!(c("fd00::1"), IpScope::Private, "ULA");
        assert_eq!(c("fe80::1"), IpScope::LinkLocal);
        assert_eq!(c("2001:db8::1"), IpScope::Documentation);
        assert_eq!(c("2606:4700::1"), IpScope::Global);
        // v4-mapped v6 unwraps to the embedded v4
        assert_eq!(c("::ffff:127.0.0.1"), IpScope::Loopback);
        assert_eq!(c("::ffff:10.0.0.1"), IpScope::Private);
        assert_eq!(c("::ffff:8.8.8.8"), IpScope::Global);
        // NAT64 translation form
        assert_eq!(c("64:ff9b::808:808"), IpScope::Global); // 8.8.8.8
    }

    #[test]
    fn default_policy_blocks_private_allows_global() {
        let p = OutboundPolicy {
            allow_private: false,
            allowed_cidrs: vec![],
        };
        assert!(p.check("8.8.8.8".parse().unwrap()).is_ok());
        assert!(p.check("10.0.0.1".parse().unwrap()).is_err());
        assert!(p.check("127.0.0.1".parse().unwrap()).is_err());
        assert!(p.check("169.254.169.254".parse().unwrap()).is_err());
        assert!(p.check("::ffff:127.0.0.1".parse().unwrap()).is_err(), "mapped loopback blocked");
    }

    #[test]
    fn allow_private_flag_and_cidr_overrides() {
        let p = OutboundPolicy {
            allow_private: true,
            allowed_cidrs: vec![],
        };
        assert!(p.check("10.0.0.1".parse().unwrap()).is_ok(), "lab scanning authorized");
        assert!(p.check("127.0.0.1".parse().unwrap()).is_ok());
        // Metadata stays blocked even under allow_private — explicit CIDR required.
        assert!(p.check("169.254.169.254".parse().unwrap()).is_err());

        let cidr = OutboundPolicy {
            allow_private: false,
            allowed_cidrs: vec![IpNet::parse("10.0.0.0/8").unwrap()],
        };
        assert!(cidr.check("10.1.2.3".parse().unwrap()).is_ok(), "explicit lab CIDR");
        assert!(cidr.check("192.168.0.1".parse().unwrap()).is_err(), "outside CIDR still blocked");
        // Explicit CIDR overrides metadata (operator intent).
        let meta = OutboundPolicy {
            allow_private: false,
            allowed_cidrs: vec![IpNet::parse("169.254.169.254/32").unwrap()],
        };
        assert!(meta.check("169.254.169.254".parse().unwrap()).is_ok());
    }

    #[test]
    fn cidr_parse_v4_and_v6() {
        assert!(IpNet::parse("10.0.0.0/8").is_some());
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("2001:db8::/32").is_some());
        assert!(IpNet::parse("2001:db8::1").is_some(), "bare v6 = /128");
        let net = IpNet::parse("2001:db8::/32").unwrap();
        assert!(net.contains(&"2001:db8:1::1".parse().unwrap()));
        assert!(!net.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn same_host_comparison_normalizes() {
        assert!(same_host("example.com", "example.com"));
        assert!(same_host("Example.COM", "example.com."));
        assert!(same_host("example.com", "EXAMPLE.com"));
        assert!(!same_host("example.com", "evil.example.net"));
        assert!(!same_host("example.com", "127.0.0.1"));
    }
}
