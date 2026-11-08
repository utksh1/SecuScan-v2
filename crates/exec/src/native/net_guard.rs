//! Connect-time destination guard (Max-Parity Sprint 2.3, issue #6).
//!
//! Admission (`secuscan_core::policy`) approves *host names*; DNS answers
//! can still change between admission and connection. This guard runs at
//! scan start: resolve the target host, validate every answer, and hand the
//! approved addresses back so HTTP clients can **pin** them (`reqwest`
//! `resolve()`) — a mid-scan DNS flip can no longer walk the scan onto a
//! different address.
//!
//! Policy (issue #6: explicit deployment policy, not blanket prohibition):
//! * Cloud metadata endpoints (169.254.169.254 and friends) are **always**
//!   blocked — nothing legitimate scans them by name.
//! * Loopback/private/link-local are allowed by default: this is a
//!   local-first scanner whose whole product is scanning private nets and
//!   itself (verify suites, lab targets). A name that was admitted as a
//!   *private literal* is unchanged by resolution.
//! * `SECUSCAN_OUTBOUND_STRICT=true` opts into the hard mode: hostname
//!   targets must resolve to global addresses (private/metadata rejected)
//!   unless `SECUSCAN_OUTBOUND_ALLOW_PRIVATE=true` or the IP falls inside
//!   `SECUSCAN_OUTBOUND_ALLOWED_CIDRS` — for multi-tenant deployments where
//!   the operator cannot vouch for every tenant's target names.

use secuscan_core::net_scope::{self, IpScope, OutboundPolicy};

/// Outcome of a target check: the pinned addresses for HTTP clients.
pub struct TargetScope {
    pub host: String,
    /// All validated addresses (empty when the target is a literal IP or
    /// resolution is not applicable).
    pub pinned: Vec<std::net::IpAddr>,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).ok().as_deref() == Some("true")
}

/// Extract the host component of a target (URL or bare host/IP).
fn host_of(target: &str) -> String {
    if let Ok(url) = url::Url::parse(target) {
        if let Some(h) = url.host_str() {
            return h.trim_end_matches('.').to_string();
        }
    }
    // Bare host/IP (strip an optional :port).
    target
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target)
        .trim_end_matches('.')
        .to_string()
}

/// Resolve + validate the target's scope, returning pinned addresses for
/// HTTP clients. Never rejects loopback/private by default (local-first
/// product); metadata endpoints are always refused.
pub async fn check_target_scope(target: &str) -> Result<TargetScope, String> {
    let host = host_of(target);
    if host.is_empty() {
        return Err("target has no host component".into());
    }

    // IP-literal targets: classified directly, no DNS.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let scope = net_scope::classify_ip(ip);
        if scope == IpScope::Metadata {
            return Err(format!(
                "{ip} is a cloud metadata endpoint — refusing to scan it"
            ));
        }
        return Ok(TargetScope {
            host,
            pinned: vec![ip],
        });
    }

    // Hostname: resolve on a blocking thread, then classify every answer.
    // Resolution FAILURE is not a security property — an NXDOMAIN target
    // proceeds and fails in the scanner's own honest way. Only the
    // classification verdicts (metadata, strict-mode private) are hard
    // refusals.
    let h = host.clone();
    let addrs = match tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        format!("{h}:0")
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(|e| format!("target resolution join failed: {e}"))?
    {
        Ok(a) if !a.is_empty() => a,
        _ => {
            return Ok(TargetScope {
                host,
                pinned: vec![],
            });
        }
    };

    if env_flag("SECUSCAN_OUTBOUND_STRICT") {
        let policy = OutboundPolicy::from_env();
        for ip in &addrs {
            policy
                .check(*ip)
                .map_err(|e| format!("target {host} failed outbound policy: {e}"))?;
        }
    } else {
        // Default: metadata endpoints are always refused; everything else is
        // the operator's admission decision.
        for ip in &addrs {
            if net_scope::classify_ip(*ip) == IpScope::Metadata {
                return Err(format!(
                    "target {host} resolves to cloud metadata endpoint {ip} — refusing"
                ));
            }
        }
    }

    let pinned: Vec<std::net::IpAddr> = {
        let mut seen = Vec::new();
        for ip in addrs {
            if !seen.contains(&ip) {
                seen.push(ip);
            }
        }
        seen
    };
    Ok(TargetScope { host, pinned })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ip_literal_targets_bypass_dns() {
        let t = check_target_scope("10.0.0.5").await.unwrap();
        assert_eq!(t.pinned, vec!["10.0.0.5".parse::<std::net::IpAddr>().unwrap()]);
        // Metadata literal: always refused.
        assert!(check_target_scope("169.254.169.254").await.is_err());
        // Loopback literal: fine (self-scanning is the product).
        assert!(check_target_scope("http://127.0.0.1:8080/").await.is_ok());
    }

    #[test]
    fn host_extraction_handles_urls_and_bare_names() {
        assert_eq!(host_of("http://Example.COM./a?b"), "example.com");
        assert_eq!(host_of("example.com:8080"), "example.com");
        assert_eq!(host_of("10.0.0.5"), "10.0.0.5");
    }
}
