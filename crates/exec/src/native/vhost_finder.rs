//! Native virtual-host (vhost) discovery scanner.
//!
//! Fields (see `plugins/vhost-finder.toml`):
//! - `target` (string, required) — base URL whose IP serves multiple vhosts
//! - `wordlist` (string, optional) — custom vhost-name wordlist
//! - `max_labels` (integer, default 300)
//! - `timeout_ms` (integer, default 8000)
//!
//! Sends requests to the target with different `Host:` headers and flags
//! responses whose status or body size differs from the baseline.

use super::http_headers::build_client;
use super::{get_i64_or, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

const DEFAULT_VHOSTS: &str = include_str!("subdomain_wordlist.txt");

pub struct VhostFinderScanner;

#[async_trait]
impl NativeScanner for VhostFinderScanner {
    fn id(&self) -> &'static str {
        "vhost_finder"
    }

    fn name(&self) -> &'static str {
        "Virtual Host Finder"
    }

    fn description(&self) -> &'static str {
        "Discover virtual hosts served by the same web server: sends requests \
         with varied Host headers and flags responses that differ from the \
         default site (status or body size)."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = super::http_headers::normalize_url(get_str_or(inputs, "target", ""))?;
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 8_000).clamp(500, 30_000) as u64,
        );
        let max_labels = get_i64_or(inputs, "max_labels", 300).clamp(1, 5000) as usize;

        let url = reqwest::Url::parse(&target).map_err(|e| format!("bad URL: {e}"))?;
        let port = url.port_or_known_default();
        let host = url.host_str().ok_or("target URL has no host")?.to_string();
        let base_ip = resolve_host(&host, timeout)
            .await
            .ok_or_else(|| format!("cannot resolve `{host}`"))?;
        // Build a raw-IP URL: requests MUST go to the server IP while the
        // Host header carries the vhost candidate.
        let ip_url = rebuild_url_with_ip(&target, &base_ip.to_string(), port)?;

        let base_host_header = url.host_str().unwrap().to_string();
        let wordlist = get_str_or(inputs, "wordlist", "");
        let labels = load_labels(wordlist, max_labels)?;

        let client = build_client(false, timeout)?;

        // ---- baseline: the real site as the server knows it --------------------
        let baseline = probe(&client, &target, &base_host_header, port).await?;

        // ---- probe candidates ---------------------------------------------------
        ctx.sink
            .emit(crate::events::TaskEvent::Info(format!(
                "probing {} vhost candidates against {} (Host header fuzz)",
                labels.len(),
                base_ip
            )))
            .await;

        let mut results: Vec<(String, u16, usize)> = Vec::new();
        let mut set = tokio::task::JoinSet::new();
        for label in &labels {
            let ip_url = ip_url.clone();
            let client = client.clone();
            let base = baseline.clone();
            let host_header = format!("{label}.{base_host_header}");
            set.spawn(async move {
                let probe = probe(&client, &ip_url, &host_header, port).await.ok()?;
                differs(&base, &probe).then_some((host_header, probe.0, probe.1))
            });
        }
        while let Some(item) = set.join_next().await {
            if ctx.cancel.is_cancelled() {
                set.abort_all();
                break;
            }
            if let Ok(Some(r)) = item {
                results.push(r);
            }
        }

        Ok(vhost_findings(&baseline, &results))
    }
}

type Probe = (u16, usize); // (status, body_len)

async fn probe(
    client: &reqwest::Client,
    url: &str,
    host_header: &str,
    _port: Option<u16>,
) -> Result<Probe, String> {
    let resp = client
        .get(url)
        .header("host", host_header)
        .header("user-agent", "SecuScan-2.0 (vhost-finder)")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status().as_u16();
    let len = resp.bytes().await.map(|b| b.len()).unwrap_or(0);
    Ok((status, len))
}

/// Pure: baseline vs candidate — a "different" vhost differs in status AND body size.
fn differs(base: &Probe, candidate: &Probe) -> bool {
    let (bs, bl) = *base;
    let (cs, cl) = *candidate;
    cs != bs && (cl.abs_diff(bl) as f64 / bl.max(1) as f64) > 0.25
}

async fn resolve_host(host: &str, timeout: Duration) -> Option<IpAddr> {
    let fut = tokio::net::lookup_host((host, 80u16));
    let iter = tokio::time::timeout(timeout, fut).await.ok()?; // Result<Iter>
    let mut iter = iter.ok()?; // io::Error
    iter.next().map(|a| a.ip())
}

/// Replace the hostname in the URL with the resolved IP (scheme/path kept).
fn rebuild_url_with_ip(target: &str, ip: &str, port: Option<u16>) -> Result<String, String> {
    let mut u = reqwest::Url::parse(target).map_err(|e| format!("bad URL: {e}"))?;
    let parsed: IpAddr = ip.parse().map_err(|_| format!("invalid ip `{ip}`"))?;
    let host_str = match parsed {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    u.set_host(Some(&host_str))
        .map_err(|e| format!("cannot set host: {e}"))?;
    if let Some(p) = port {
        if !matches!((u.scheme(), p), ("http", 80) | ("https", 443)) {
            // url::Url::set_port errors with () — map to a message
            u.set_port(Some(p))
                .map_err(|_| "cannot set port".to_string())?;
        } else {
            let _ = u.set_port(None);
        }
    }
    Ok(u.to_string())
}

fn load_labels(path: &str, max_labels: usize) -> Result<Vec<String>, String> {
    let raw: &str = if path.is_empty() {
        DEFAULT_VHOSTS
    } else {
        &std::fs::read_to_string(path).map_err(|e| format!("cannot read wordlist `{path}`: {e}"))?
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        out.push(l.to_ascii_lowercase());
        if out.len() >= max_labels {
            break;
        }
    }
    if out.is_empty() {
        return Err("wordlist produced no labels".into());
    }
    Ok(out)
}

/// Pure conversion — unit-testable.
pub(super) fn vhost_findings(baseline: &Probe, found: &[(String, u16, usize)]) -> Vec<Finding> {
    if found.is_empty() {
        return vec![finding(
            Severity::Info,
            "No distinct virtual hosts found",
            format!(
                "All probed Host headers produced the same response as the \
                 baseline (status {} / {} bytes). The server either serves one \
                 site, or the vhosts are not in the tried name list.",
                baseline.0, baseline.1
            ),
            "Try a larger vhost wordlist, or enumerate via TLS SNI / DNS instead.",
            "0 distinct vhosts",
            json!({"count": 0}),
        )];
    } else {
        found
            .iter()
            .map(|(name, status, len)| {
                finding(
                    Severity::Info,
                    format!("Virtual host responds: {name}"),
                    format!(
                        "A request with `Host: {name}` returned HTTP {status} with \
                         {len} bytes — different from the default site, so this \
                         vhost is likely configured on the server."
                    ),
                    "Add discovered vhosts to the scan scope; forgotten vhosts are \
                     a classic unpatched entry point.",
                    format!("Host: {name} → HTTP {status}, {len} bytes"),
                    json!({"vhost": name, "status": status, "body_bytes": len}),
                )
            })
            .collect()
    }
}

fn finding(
    severity: Severity,
    title: impl Into<String>,
    description: impl Into<String>,
    remediation: &str,
    proof: impl Into<String>,
    metadata: serde_json::Value,
) -> Finding {
    let mut f = Finding::new(title, "Web Server", severity, FindingKind::Observation);
    f.description = description.into();
    f.remediation = remediation.to_string();
    f.proof = proof.into();
    f.metadata = metadata;
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differs_on_status_and_size() {
        assert!(differs(&(200, 100), &(403, 250)));
        assert!(!differs(&(200, 100), &(200, 100)));
        // same status → not interesting even if size differs slightly
        assert!(!differs(&(200, 100), &(200, 110)));
        // different status but nearly identical body → default-site echo
        assert!(!differs(&(200, 1000), &(400, 1005)));
    }

    #[test]
    fn empty_findings_get_info() {
        let fs = vhost_findings(&(200, 10), &[]);
        assert_eq!(fs.len(), 1);
        assert!(fs[0].title.contains("No distinct"));
    }

    #[test]
    fn found_vhosts_listed() {
        let fs = vhost_findings(&(200, 10), &[("staging.acme.test".to_string(), 403, 250)]);
        assert_eq!(fs.len(), 1);
        assert!(fs[0].title.contains("staging.acme.test"));
        assert_eq!(fs[0].metadata["status"], json!(403));
    }

    #[test]
    fn url_rebuild_swaps_host() {
        let u = rebuild_url_with_ip("http://acme.test:8080/app", "192.0.2.5", Some(8080)).unwrap();
        assert_eq!(u, "http://192.0.2.5:8080/app");
        let u = rebuild_url_with_ip("https://acme.test/x", "192.0.2.5", Some(443)).unwrap();
        assert_eq!(u, "https://192.0.2.5/x");
    }

    #[test]
    fn labels_load_and_cap() {
        assert!(load_labels("", 5).unwrap().len() == 5);
        assert!(load_labels("", 10_000).unwrap().len() > 250);
    }
}
