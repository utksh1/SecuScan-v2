//! Native TCP connect port scanner.
//!
//! Fields (see `plugins/port-scanner.toml`):
//! - `target` (string, required) — hostname, IP, or CIDR
//! - `ports` (string, optional) — e.g. `80,443,8000-8005`; overrides presets
//! - `top_ports` (select: 10 | 100 | 1000, default 100)
//! - `concurrency` (integer, 1..=1024, default 128)
//! - `timeout_ms` (integer, 50..=10000, default 800)

use super::{get_i64_or, get_str, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Upper bound on total probes per task (protects accidental /16 scans).
const MAX_PROBES: u64 = 16_384;

/// Curated top-100 TCP ports (nmap-style ordering, most common first).
const TOP_100: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8443, 1723, 111, 995, 5900,
    5432, 993, 587, 5985, 8080, 1025, 49152, 1433, 1521, 6379, 8000, 8081, 8888, 7001, 49153, 1720,
    3000, 5631, 2000, 593, 6666, 5800, 5222, 902, 2001, 32768, 5555, 1110, 64623, 10000, 8082,
    2222, 137, 514, 138, 366, 10001, 1026, 1027, 1028, 1029, 1030, 6000, 1031, 1038, 1032, 6001,
    1035, 5104, 1036, 5000, 1033, 5010, 1037, 1039, 54321, 33354, 1034, 8651, 8652, 8653, 8654,
    2100, 3689, 9050, 5225, 5226, 7777, 26214, 26257, 31119, 5223, 8444, 1045, 1046, 1047, 1048,
    1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1060, 1068, 35000,
];

const HIGH_RISK: &[u16] = &[
    21, 22, 23, 25, 109, 110, 135, 139, 143, 389, 445, 512, 513, 514, 873, 993, 995, 1433, 1521,
    2049, 2181, 2375, 2376, 3268, 3306, 3389, 5432, 5900, 5984, 6379, 6667, 9200, 11211, 27017,
];

pub struct PortScanner;

#[async_trait]
impl NativeScanner for PortScanner {
    fn id(&self) -> &'static str {
        "port_scanner"
    }

    fn name(&self) -> &'static str {
        "TCP Port Scanner"
    }

    fn description(&self) -> &'static str {
        "Asynchronous TCP connect scan across a host or CIDR range with \
         curated top-port presets, live progress and high-risk port flagging."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = get_str(inputs, "target")?;
        let ports = parse_ports(get_str_or(inputs, "ports", ""))?;
        let ports = if ports.is_empty() {
            match get_str_or(inputs, "top_ports", "100") {
                "10" => TOP_100[..10].to_vec(),
                "1000" => well_known_ports(),
                _ => TOP_100.to_vec(),
            }
        } else {
            ports
        };
        let concurrency = get_i64_or(inputs, "concurrency", 128).clamp(1, 1024) as usize;
        let timeout =
            Duration::from_millis(get_i64_or(inputs, "timeout_ms", 800).clamp(50, 10_000) as u64);

        let host_names = expand_hosts(target)?;
        // Resolve every unique host up front (async, off the workers) so the
        // probe futures never perform blocking DNS.
        let mut resolved: std::collections::HashMap<String, Option<IpAddr>> =
            std::collections::HashMap::new();
        for h in &host_names {
            if resolved.contains_key(h) {
                continue;
            }
            let ip = if let Ok(ip) = h.parse::<IpAddr>() {
                Some(ip)
            } else {
                tokio::net::lookup_host(format!("{h}:0"))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .map(|sa| sa.ip())
            };
            if ip.is_none() {
                ctx.sink
                    .emit(crate::events::TaskEvent::Warn(format!(
                        "cannot resolve host `{h}` — skipping"
                    )))
                    .await;
            }
            resolved.insert(h.clone(), ip);
        }
        let hosts: Vec<String> = resolved
            .iter()
            .filter_map(|(h, ip)| ip.map(|_| h.clone()))
            .collect();
        let total = (hosts.len() as u64) * (ports.len() as u64);
        if total == 0 {
            return Err("nothing to scan: no hosts or ports".into());
        }
        if total > MAX_PROBES {
            return Err(format!(
                "scan scope too large: {total} probes (host×port) exceeds the {MAX_PROBES} limit; narrow the target or port set"
            ));
        }
        ctx.sink
            .emit(crate::events::TaskEvent::Info(format!(
                "scanning {} host(s) × {} port(s) = {total} probes (concurrency {concurrency})",
                hosts.len(),
                ports.len()
            )))
            .await;

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let probes: Vec<(Probe, IpAddr)> = hosts
            .iter()
            .filter_map(|h| resolved.get(h).copied().flatten().map(|ip| (h.clone(), ip)))
            .flat_map(|(h, ip)| {
                ports.iter().map(move |p| {
                    (
                        Probe {
                            host: h.clone(),
                            port: *p,
                        },
                        ip,
                    )
                })
            })
            .collect();

        let mut stream: FuturesUnordered<_> = probes
            .into_iter()
            .map(|(probe, ip)| {
                let sem = sem.clone();
                async move {
                    let _permit = sem.acquire_owned().await;
                    let addr = SocketAddr::new(ip, probe.port);
                    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await
                    {
                        Ok(Ok(_)) => (probe, ProbeResult::Open),
                        Ok(Err(e)) => {
                            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                (probe, ProbeResult::Refused)
                            } else {
                                (probe, ProbeResult::Filtered)
                            }
                        }
                        Err(_) => (probe, ProbeResult::Filtered),
                    }
                }
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<FuturesUnordered<_>>();

        let mut open: Vec<Probe> = Vec::new();
        let mut refused = 0u64;
        let mut filtered = 0u64;
        let mut done = 0u64;
        while let Some((probe, result)) = stream.next().await {
            if ctx.cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            match result {
                ProbeResult::Open => open.push(probe),
                ProbeResult::Refused => refused += 1,
                ProbeResult::Filtered => filtered += 1,
            }
            done += 1;
            if done.is_multiple_of(256) {
                ctx.sink
                    .emit(crate::events::TaskEvent::Progress {
                        done,
                        total,
                        message: format!("{done}/{total} probes"),
                    })
                    .await;
            }
        }

        let mut findings: Vec<Finding> = open
            .iter()
            .map(|p| {
                let high = HIGH_RISK.contains(&p.port);
                let mut f = Finding::new(
                    format!("Open port: {}/tcp on {}", p.port, p.host),
                    "Network Service",
                    if high { Severity::Low } else { Severity::Info },
                    FindingKind::Observation,
                );
                f.description = format!("TCP port {} is open on {}.", p.port, p.host);
                f.remediation = format!(
                    "Verify whether the service on port {} should be exposed, and ensure it is \
                     patched, configured securely, and protected by a firewall rule if not needed.",
                    p.port
                );
                f.proof = format!("TCP connect to {}:{} succeeded", p.host, p.port);
                f.metadata = json!({ "host": p.host, "port": p.port, "protocol": "tcp" });
                f
            })
            .collect();

        // Host liveness observation when nothing was open.
        if findings.is_empty() {
            let mut f = Finding::new(
                format!("No open ports found on {target}"),
                "Network Service",
                Severity::Info,
                FindingKind::Observation,
            );
            if refused > 0 {
                f.description = format!(
                    "All {total} probed ports are closed, but the host answered with TCP resets \
                     ({refused} refused), so it is reachable."
                );
            } else {
                f.description = format!(
                    "All {total} probed ports timed out or were unreachable; the host may be \
                     down, firewalled, or filtering probes."
                );
            }
            f.proof = format!("open=0 refused={refused} filtered={filtered}");
            f.metadata = json!({ "refused": refused, "filtered": filtered, "probed": total });
            findings.push(f);
        }

        Ok(findings)
    }
}

#[derive(Debug, Clone)]
struct Probe {
    host: String,
    port: u16,
}

enum ProbeResult {
    Open,
    Refused,
    Filtered,
}

fn expand_hosts(target: &str) -> Result<Vec<String>, String> {
    let t = target.trim();
    if let Some((base, prefix)) = t.split_once('/') {
        let base_ip: IpAddr = base
            .trim()
            .parse()
            .map_err(|_| format!("invalid CIDR base `{base}`"))?;
        let prefix: u32 = prefix
            .trim()
            .parse()
            .map_err(|_| format!("invalid CIDR prefix `{prefix}`"))?;
        let hosts = match base_ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return Err(format!("invalid IPv4 prefix /{prefix}"));
                }
                let count: u64 = 1u64 << (32 - prefix);
                if count > 1024 {
                    return Err(format!(
                        "CIDR /{prefix} covers {count} hosts; the limit is 1024 per scan"
                    ));
                }
                let base = u32::from(v4) & subnet_mask(prefix);
                (0..count)
                    .map(|i| Ipv4AddrStr(base + i as u32).to_string())
                    .collect()
            }
            IpAddr::V6(_) => return Err("IPv6 CIDR ranges are not supported yet".into()),
        };
        return Ok(hosts);
    }
    Ok(vec![t.to_string()])
}

struct Ipv4AddrStr(u32);

impl std::fmt::Display for Ipv4AddrStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            (self.0 >> 24) & 0xff,
            (self.0 >> 16) & 0xff,
            (self.0 >> 8) & 0xff,
            self.0 & 0xff
        )
    }
}

fn subnet_mask(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// Parse `80,443,8000-8005` (whitespace tolerant, deduplicated, sorted).
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = std::collections::BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a.trim().parse().map_err(|_| format!("bad port `{a}`"))?;
            let hi: u16 = b.trim().parse().map_err(|_| format!("bad port `{b}`"))?;
            if lo == 0 || hi == 0 || lo > hi {
                return Err(format!("invalid port range `{part}`"));
            }
            if (hi as u32 - lo as u32 + 1) > 4096 {
                return Err(format!("port range `{part}` too wide (max 4096)"));
            }
            for p in lo..=hi {
                out.insert(p);
            }
        } else {
            let p: u16 = part.parse().map_err(|_| format!("bad port `{part}`"))?;
            if p == 0 {
                return Err("port 0 is not valid".into());
            }
            out.insert(p);
        }
    }
    Ok(out.into_iter().collect())
}

fn well_known_ports() -> Vec<u16> {
    let mut set = std::collections::BTreeSet::new();
    set.extend(TOP_100.iter().copied());
    for p in 1..=1024u16 {
        set.insert(p);
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_parsing() {
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports(" 80 , 443 ").unwrap(), vec![80, 443]);
        assert_eq!(
            parse_ports("8000-8002,80").unwrap(),
            vec![80, 8000, 8001, 8002]
        );
        assert_eq!(parse_ports("").unwrap(), Vec::<u16>::new());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("10-5").is_err());
        assert!(parse_ports("1-9999").is_err()); // > 4096 wide
    }

    #[test]
    fn host_expansion() {
        assert_eq!(expand_hosts("127.0.0.1").unwrap(), vec!["127.0.0.1"]);
        assert_eq!(expand_hosts("scanme.local").unwrap(), vec!["scanme.local"]);
        let hosts = expand_hosts("127.0.0.0/30").unwrap();
        assert_eq!(
            hosts,
            vec!["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"]
        );
        assert!(expand_hosts("10.0.0.0/8").is_err()); // > 1024 hosts
    }

    #[tokio::test]
    async fn finds_open_port_and_reports_liveness() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let ctx = NativeCtx {
            sink: crate::events::EventSink::new(uuid::Uuid::new_v4(), tx),
            cancel: tokio_util::sync::CancellationToken::new(),
            timeout: std::time::Duration::from_secs(10),
            auth: None,
            oob: None,
        };
        let inputs: BTreeMap<String, serde_json::Value> = [
            ("target".to_string(), json!("127.0.0.1")),
            ("ports".to_string(), json!(format!("{port},{}", port + 1))),
        ]
        .into_iter()
        .collect();

        let findings = PortScanner.run(&inputs, &ctx).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains(&format!("{port}/tcp")));
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn scope_cap_enforced() {
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let ctx = NativeCtx {
            sink: crate::events::EventSink::new(uuid::Uuid::new_v4(), tx),
            cancel: tokio_util::sync::CancellationToken::new(),
            timeout: std::time::Duration::from_secs(5),
            auth: None,
            oob: None,
        };
        let inputs: BTreeMap<String, serde_json::Value> = [
            ("target".to_string(), json!("127.0.0.0/24")),
            ("top_ports".to_string(), json!("1000")),
        ]
        .into_iter()
        .collect();
        let err = PortScanner.run(&inputs, &ctx).await.unwrap_err();
        assert!(err.contains("scope too large"), "{err}");
    }

    #[tokio::test]
    async fn unreachable_host_reports_down_observation() {
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let ctx = NativeCtx {
            sink: crate::events::EventSink::new(uuid::Uuid::new_v4(), tx),
            cancel: tokio_util::sync::CancellationToken::new(),
            timeout: std::time::Duration::from_secs(5),
            auth: None,
            oob: None,
        };
        // TEST-NET-1 is guaranteed non-routable (RFC 5737).
        let inputs: BTreeMap<String, serde_json::Value> = [
            ("target".to_string(), json!("192.0.2.1")),
            ("ports".to_string(), json!("59998,59999")),
            ("timeout_ms".to_string(), json!(200)),
        ]
        .into_iter()
        .collect();
        let findings = PortScanner.run(&inputs, &ctx).await.unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("down, firewalled")
                    || f.title.to_ascii_lowercase().contains("unreachable")
                    || f.title.to_ascii_lowercase().contains("down")),
            "expected a host-down observation, got {findings:?}"
        );
    }
}
