//! Target / network policy engine.
//!
//! Three layers are applied to every task's target, in order:
//! 1. **global deny-list** — a matching target is always refused;
//! 2. **global allow-list** (if non-empty) — the target must match;
//! 3. **plugin `allowed_targets`** (if non-empty) — the target must match.
//!
//! Patterns support globs (`*`, `?`, case-insensitive) and CIDR blocks
//! (`10.0.0.0/8`). A bare IP is also accepted as an implicit `/32`.

use crate::models::now_iso;
use std::net::IpAddr;

/// Global network policy (admin-managed, persisted by the API layer).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NetworkPolicy {
    /// If non-empty, a target must match at least one pattern.
    #[serde(default)]
    pub allow: Vec<String>,
    /// A target matching any pattern is always refused.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Outcome of a target policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum TargetVerdict {
    Allowed,
    Denied {
        reason: String,
        layer: DenyLayer,
        pattern: String,
    },
    /// The task declared no target field value to check.
    NoTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyLayer {
    GlobalDeny,
    GlobalAllow,
    Plugin,
}

impl DenyLayer {
    pub fn label(&self) -> &'static str {
        match self {
            DenyLayer::GlobalDeny => "global_deny",
            DenyLayer::GlobalAllow => "global_allow",
            DenyLayer::Plugin => "plugin",
        }
    }
}

/// One row of the network audit log (persistence handled by the DB layer).
#[derive(Debug, Clone)]
pub struct PolicyAuditEntry {
    pub ts: String,
    pub target: String,
    pub plugin_id: String,
    pub user: String,
    pub verdict: String,
    pub layer: String,
    pub pattern: String,
    pub reason: String,
}

impl PolicyAuditEntry {
    pub fn denied(
        target: &str,
        plugin_id: &str,
        user: &str,
        reason: &str,
        layer: DenyLayer,
        pattern: &str,
    ) -> Self {
        PolicyAuditEntry {
            ts: now_iso(),
            target: target.to_string(),
            plugin_id: plugin_id.to_string(),
            user: user.to_string(),
            verdict: "denied".into(),
            layer: layer.label().into(),
            pattern: pattern.to_string(),
            reason: reason.to_string(),
        }
    }
}

/// Evaluate whether `target` may be scanned.
///
/// `target` may be a hostname, IP, URL, or CIDR — the host portion is
/// extracted first.
pub fn evaluate_target(
    target: Option<&str>,
    plugin_allowed: &[String],
    global: &NetworkPolicy,
) -> TargetVerdict {
    let Some(raw) = target.map(str::trim).filter(|t| !t.is_empty()) else {
        return TargetVerdict::NoTarget;
    };
    let host = extract_host(raw);
    if host.is_empty() {
        return TargetVerdict::Denied {
            reason: "target could not be parsed".into(),
            layer: DenyLayer::GlobalDeny,
            pattern: String::new(),
        };
    }

    for pat in &global.deny {
        if matches_target(&host, pat) {
            return TargetVerdict::Denied {
                reason: format!("target matches global deny pattern `{pat}`"),
                layer: DenyLayer::GlobalDeny,
                pattern: pat.clone(),
            };
        }
    }

    if !global.allow.is_empty() {
        let ok = global.allow.iter().any(|pat| matches_target(&host, pat));
        if !ok {
            return TargetVerdict::Denied {
                reason: "target does not match any global allow pattern".into(),
                layer: DenyLayer::GlobalAllow,
                pattern: global.allow.join(","),
            };
        }
    }

    if !plugin_allowed.is_empty() {
        let ok = plugin_allowed.iter().any(|pat| matches_target(&host, pat));
        if !ok {
            return TargetVerdict::Denied {
                reason: format!(
                    "target is outside the plugin's allowed targets ({})",
                    plugin_allowed.join(", ")
                ),
                layer: DenyLayer::Plugin,
                pattern: plugin_allowed.join(","),
            };
        }
    }

    TargetVerdict::Allowed
}

/// Extract the host portion from a URL, `host:port`, bare host, or CIDR.
pub fn extract_host(raw: &str) -> String {
    let s = raw.trim();
    // scheme://...
    if let Some(idx) = s.find("://") {
        let rest = &s[idx + 3..];
        return host_from_authority(rest);
    }
    // bare CIDR
    if s.contains('/') && IpNet::parse(s).is_some() {
        return s.to_string();
    }
    host_from_authority(s)
}

fn host_from_authority(s: &str) -> String {
    let end = s
        .find(['/', '?', '#'])
        .unwrap_or(s.len());
    let auth = &s[..end];
    // strip userinfo
    let host_port = match auth.rfind('@') {
        Some(i) => &auth[i + 1..],
        None => auth,
    };
    // strip port (but not for IPv6 literals)
    if host_port.starts_with('[') {
        if let Some(close) = host_port.find(']') {
            return host_port[1..close].to_string();
        }
        return host_port.to_string();
    }
    match host_port.rfind(':') {
        Some(i) if host_port[i + 1..].chars().all(|c| c.is_ascii_digit()) && !host_port[i + 1..].is_empty() => {
            host_port[..i].to_string()
        }
        _ => host_port.to_string(),
    }
}

/// Parsed IP network (accepts `a.b.c.d/len`, bare IP = /32 or /128).
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn parse(s: &str) -> Option<Self> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((a, p)) => (a, p),
            None => (s, ""),
        };
        let addr: IpAddr = addr_str.trim().parse().ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = if prefix_str.is_empty() {
            max
        } else {
            prefix_str.trim().parse::<u8>().ok().filter(|p| *p <= max)?
        };
        Some(IpNet { addr, prefix })
    }

    fn contains(&self, other: &IpAddr) -> bool {
        match (self.addr, other) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                let net = u128::from_be_bytes(net.octets());
                let ip = u128::from_be_bytes(ip.octets());
                (net & mask) == (ip & mask)
            }
            _ => false,
        }
    }
}

/// Does `host` (a bare hostname/IP/CIDR) match `pattern` (glob or CIDR)?
pub fn matches_target(host: &str, pattern: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let pattern = pattern.trim().to_ascii_lowercase();
    if host.is_empty() || pattern.is_empty() {
        return false;
    }
    // CIDR: if both sides parse as networks/IPs, compare numerically.
    if let (Some(net), Some(ip)) = (IpNet::parse(&pattern), host.parse::<IpAddr>().ok()) {
        return net.contains(&ip);
    }
    // Host may itself be a CIDR (scan target `10.0.0.0/24`): require the
    // pattern to be a CIDR that fully covers it — compare network addresses
    // via a representative IP plus prefix equality.
    if let (Some(pnet), Some(hnet)) = (IpNet::parse(&pattern), IpNet::parse(&host)) {
        if std::mem::discriminant(&pnet.addr) == std::mem::discriminant(&hnet.addr) {
            let rep = hnet.addr;
            return pnet.contains(&rep) && pnet.prefix <= hnet.prefix;
        }
        return false;
    }
    glob_match(&pattern, &host)
}

/// Case-insensitive glob with `*` (any run) and `?` (single char).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_rec(&p, 0, &t, 0)
}

fn glob_rec(p: &[char], pi: usize, t: &[char], ti: usize) -> bool {
    if pi == p.len() {
        return ti == t.len();
    }
    match p[pi] {
        '*' => {
            // collapse consecutive stars
            let mut next = pi;
            while next < p.len() && p[next] == '*' {
                next += 1;
            }
            for k in ti..=t.len() {
                if glob_rec(p, next, t, k) {
                    return true;
                }
            }
            false
        }
        '?' => ti < t.len() && glob_rec(p, pi + 1, t, ti + 1),
        c => ti < t.len() && t[ti] == c && glob_rec(p, pi + 1, t, ti + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("192.168.*.*", "192.168.1.10"));
        assert!(glob_match("10.*.*.*", "10.1.2.3"));
        assert!(!glob_match("10.*.*.*", "192.168.1.1"));
        assert!(glob_match("*.example.com", "www.example.com"));
        assert!(!glob_match("*.example.com", "example.org"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("h?st", "host"));
        assert!(!glob_match("h?st", "hoost"));
    }

    #[test]
    fn cidr_matching() {
        assert!(matches_target("10.0.0.5", "10.0.0.0/8"));
        assert!(!matches_target("11.0.0.5", "10.0.0.0/8"));
        assert!(matches_target("127.0.0.1", "127.0.0.1"));
        assert!(matches_target("2001:db8::1", "2001:db8::/32"));
        assert!(!matches_target("2001:db9::1", "2001:db8::/32"));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(extract_host("https://example.com/a?b=1"), "example.com");
        assert_eq!(extract_host("http://10.0.0.1:8080/x"), "10.0.0.1");
        assert_eq!(extract_host("example.com:443"), "example.com");
        assert_eq!(extract_host("user@example.com"), "example.com");
        assert_eq!(extract_host("10.0.0.0/24"), "10.0.0.0/24");
        assert_eq!(extract_host("[::1]:8080"), "::1");
        assert_eq!(extract_host("example.com"), "example.com");
    }

    #[test]
    fn policy_layers() {
        let global = NetworkPolicy {
            allow: vec![],
            deny: vec!["169.254.*.*".into()],
        };
        assert!(matches!(
            evaluate_target(Some("169.254.1.1"), &[], &global),
            TargetVerdict::Denied { layer: DenyLayer::GlobalDeny, .. }
        ));
        assert_eq!(evaluate_target(Some("8.8.8.8"), &[], &global), TargetVerdict::Allowed);

        let global_allow = NetworkPolicy {
            allow: vec!["127.0.0.1".into(), "192.168.*.*".into()],
            deny: vec![],
        };
        assert!(matches!(
            evaluate_target(Some("8.8.8.8"), &[], &global_allow),
            TargetVerdict::Denied { layer: DenyLayer::GlobalAllow, .. }
        ));
        assert_eq!(evaluate_target(Some("192.168.0.9"), &[], &global_allow), TargetVerdict::Allowed);

        let plugin = vec!["127.0.0.1".to_string()];
        assert!(matches!(
            evaluate_target(Some("8.8.8.8"), &plugin, &NetworkPolicy::default()),
            TargetVerdict::Denied { layer: DenyLayer::Plugin, .. }
        ));
        assert_eq!(evaluate_target(Some("127.0.0.1"), &plugin, &NetworkPolicy::default()), TargetVerdict::Allowed);
    }

    #[test]
    fn no_target_is_reported() {
        assert_eq!(evaluate_target(None, &[], &NetworkPolicy::default()), TargetVerdict::NoTarget);
        assert_eq!(
            evaluate_target(Some("   "), &[], &NetworkPolicy::default()),
            TargetVerdict::NoTarget
        );
    }

    #[test]
    fn deny_wins_over_allow() {
        let global = NetworkPolicy {
            allow: vec!["10.*.*.*".into()],
            deny: vec!["10.66.6.6".into()],
        };
        assert!(matches!(
            evaluate_target(Some("10.66.6.6"), &[], &global),
            TargetVerdict::Denied { layer: DenyLayer::GlobalDeny, .. }
        ));
        assert_eq!(evaluate_target(Some("10.1.1.1"), &[], &global), TargetVerdict::Allowed);
    }
}
