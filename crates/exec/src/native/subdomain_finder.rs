//! Native subdomain enumeration scanner (active DNS brute-force).
//!
//! Fields (see `plugins/subdomain-finder.toml`):
//! - `domain` (string, required)
//! - `wordlist` (string, optional) — path to a custom wordlist (one label
//!   per line); defaults to the embedded ~300-entry common list
//! - `max_labels` (integer) — how many candidates to try (cap 5000)
//! - `use_ct_logs` (boolean, default true) — also pull `crt.sh`
//!   certificate-transparency names (passive, no DNS traffic to the target)
//!
//! Active probing is DNS-only: each candidate label is resolved against the
//! system resolver. NXDOMAIN is "absent"; SERVFAIL/timeout is skipped.

use super::dns::{self, rtype, DnsRecord};
use super::{get_i64_or, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;

use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

const EMBEDDED_WORDLIST: &str = include_str!("subdomain_wordlist.txt");

pub struct SubdomainFinderScanner;

#[async_trait]
impl NativeScanner for SubdomainFinderScanner {
    fn id(&self) -> &'static str {
        "subdomain_finder"
    }

    fn name(&self) -> &'static str {
        "Subdomain Finder"
    }

    fn description(&self) -> &'static str {
        "Enumerate subdomains by brute-forcing common names against DNS \
         (active) and querying the public certificate-transparency log at \
         crt.sh (passive). Found hosts become observations."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let domain = get_str_or(inputs, "target", "")
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !dns::valid_name(&domain) {
            return Err(format!("invalid domain name `{domain}`"));
        }
        let max_labels = get_i64_or(inputs, "max_labels", 500).clamp(1, 5000) as usize;
        let use_ct = super::get_bool_or(inputs, "use_ct_logs", true);
        let enable_bruteforce = super::get_bool_or(inputs, "enable_bruteforce", true);
        let wordlist_path = super::get_str_or(inputs, "wordlist", "");

        // The DNS brute-force wordlist is only loaded when the profile
        // enables it (Passive profile sets enable_bruteforce=false).
        let labels: Vec<String> = if enable_bruteforce {
            load_labels(wordlist_path, max_labels)?
        } else {
            Vec::new()
        };
        let server = dns::system_server()
            .ok_or_else(|| "no DNS server available (resolv.conf empty?)".to_string())?;

        let mut found: Vec<(String, String)> = Vec::new();

        // ---- passive: certificate transparency --------------------------------
        if use_ct {
            ctx.sink
                .emit(crate::events::TaskEvent::Info(
                    "querying crt.sh certificate-transparency log…".into(),
                ))
                .await;
            match crtsh_names(&domain).await {
                Ok(names) => {
                    ctx.sink
                        .emit(crate::events::TaskEvent::Info(format!(
                            "crt.sh returned {} candidate name(s)",
                            names.len()
                        )))
                        .await;
                    for n in names {
                        found.push((n, "certificate-transparency".to_string()));
                    }
                }
                Err(e) => {
                    ctx.sink
                        .emit(crate::events::TaskEvent::Info(format!(
                            "crt.sh unavailable, continuing with DNS brute-force: {e}"
                        )))
                        .await;
                }
            }
        }

        // ---- active: DNS brute-force ------------------------------------------
    // Sprint 2.5 (#30): permutation generation — modify discovered labels
    // (api -> api2, api-dev, api-staging, api-old) and resolve them too.
    // Also: NS/MX/TXT/CNAME record harvest and AXFR attempt.

        if enable_bruteforce {
            ctx.sink
                .emit(crate::events::TaskEvent::Info(format!(
                    "resolving {} candidate labels against {}",
                    labels.len(),
                    server
                )))
                .await;

            let active = brute_force(&domain, &labels, server, &ctx.cancel).await;
            for (name, ips) in active {
                found.push((name, ips));
            }
        } else if !use_ct {
            return Err(
                "both crt.sh and DNS brute-force are disabled — pick at least one source".into(),
            );
        }

        // ---- dedupe + report ---------------------------------------------------
        found.sort();
        found.dedup_by(|a, b| a.0 == b.0);
        Ok(names_to_findings(&domain, &found))
    }
}

/// Labels to try: embedded list, or a custom file, capped at `max_labels`.
fn load_labels(path: &str, max_labels: usize) -> Result<Vec<String>, String> {
    let raw: &str = if path.is_empty() {
        EMBEDDED_WORDLIST
    } else {
        &std::fs::read_to_string(path).map_err(|e| format!("cannot read wordlist `{path}`: {e}"))?
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if !dns::valid_name(&format!("{l}.{}", domain_placeholder())) {
            continue;
        }
        out.push(l.to_ascii_lowercase());
        if out.len() >= max_labels {
            break;
        }
    }
    if out.is_empty() {
        return Err("wordlist produced no usable labels".into());
    }
    Ok(out)
}

fn domain_placeholder() -> &'static str {
    "example.test"
}

/// Resolve every candidate concurrently. Returns names that exist, paired
/// with their A-record addresses.
async fn brute_force(
    domain: &str,
    labels: &[String],
    server: SocketAddr,
    cancel: &tokio_util::sync::CancellationToken,
) -> Vec<(String, String)> {
    let mut set = tokio::task::JoinSet::new();
    for label in labels {
        let fqdn = format!("{label}.{domain}");
        set.spawn(async move {
            match dns::query(server, &fqdn, rtype::A).await {
                Ok(recs) if !recs.is_empty() => {
                    let ips: Vec<String> =
                        recs.iter().map(|r: &DnsRecord| r.data.clone()).collect();
                    Some((fqdn, ips.join(", ")))
                }
                _ => None, // empty answer / NXDOMAIN / servfail: skip
            }
        });
    }

    let mut results = Vec::new();
    while let Some(item) = set.join_next().await {
        if cancel.is_cancelled() {
            set.abort_all();
            break;
        }
        if let Ok(Some(pair)) = item {
            results.push(pair);
        }
    }
    results
}

/// Query crt.sh's public CT-log search for the domain.
async fn crtsh_names(domain: &str) -> Result<Vec<String>, String> {
    let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    let resp = client
        .get(&url)
        .header("user-agent", "SecuScan-2.0 (subdomain-finder)")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("crt.sh returned HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid JSON from crt.sh: {e}"))?;
    Ok(extract_ct_names(&body, domain))
}

/// Pure extraction from a crt.sh JSON array — unit-tested with a fixture.
pub(super) fn extract_ct_names(body: &serde_json::Value, domain: &str) -> Vec<String> {
    let mut names = Vec::new();
    let Some(arr) = body.as_array() else {
        return names;
    };
    for entry in arr {
        let Some(nv) = entry.get("name_value").and_then(|v| v.as_str()) else {
            continue;
        };
        for n in nv.split('\n') {
            let n = n.trim().trim_start_matches("*.").to_ascii_lowercase();
            if (n == domain || n.ends_with(&format!(".{domain}"))) && dns::valid_name(&n) {
                names.push(n);
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Pure conversion: (name, source/note) pairs → findings.
pub(super) fn names_to_findings(domain: &str, found: &[(String, String)]) -> Vec<Finding> {
    if found.is_empty() {
        return vec![finding(
            Severity::Info,
            format!("No subdomains found for {domain}"),
            "Neither the DNS brute-force nor the certificate-transparency log \
             surfaced live subdomains. The zone may be tightly scoped, or uses \
             names outside the tried wordlist."
                .to_string(),
            "Try a larger wordlist for the DNS pass, or a passive source with \
             broader coverage.",
            format!("0 subdomains for {domain}"),
            json!({"domain": domain, "count": 0}),
        )];
    }
    found
        .iter()
        .map(|(name, note)| {
            let note = note.as_str();
            finding(
                Severity::Info,
                format!("Subdomain: {name}"),
                format!(
                    "`{name}` resolved ({}). Subdomains can host forgotten or \
                         less-hardened services — add them to the scan scope.",
                    if note == "certificate-transparency" {
                        "seen in public certificate-transparency logs"
                    } else {
                        "A record"
                    }
                ),
                "Review each discovered host for stale deployments and apply the \
                 same hardening baseline as primary domains.",
                name.clone(),
                json!({"domain": domain, "subdomain": name, "source": note}),
            )
        })
        .collect()
}

fn finding(
    severity: Severity,
    title: impl Into<String>,
    description: impl Into<String>,
    remediation: &str,
    proof: impl Into<String>,
    metadata: serde_json::Value,
) -> Finding {
    let mut f = Finding::new(title, "DNS", severity, FindingKind::Observation);
    f.description = description.into();
    f.remediation = remediation.to_string();
    f.proof = proof.into();
    f.metadata = metadata;
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ct_names_extracted_and_filtered() {
        let body = json!([
            {"name_value": "www.example.com\nexample.com", "common_name": "x"},
            {"name_value": "*.example.com"},
            {"name_value": "evil.attacker.net"},
            {"name_value": "API.EXAMPLE.COM"},
            {"name_value": "not valid!!"}
        ]);
        let names = extract_ct_names(&body, "example.com");
        assert_eq!(
            names,
            vec!["api.example.com", "example.com", "www.example.com"]
        );
    }

    #[test]
    fn ct_garbage_handled() {
        assert!(extract_ct_names(&json!({"error": "rate limited"}), "example.com").is_empty());
        assert!(extract_ct_names(&json!([]), "example.com").is_empty());
    }

    #[test]
    fn embedded_wordlist_loads() {
        let labels = load_labels("", 10_000).unwrap();
        assert!(labels.len() > 250, "got {}", labels.len());
        assert!(labels.contains(&"www".to_string()));
        assert!(labels.iter().all(|l| !l.is_empty()));
    }

    #[test]
    fn wordlist_cap_respected() {
        let labels = load_labels("", 5).unwrap();
        assert_eq!(labels.len(), 5);
    }

    #[test]
    fn missing_wordlist_errors() {
        assert!(load_labels("/definitely/not/here.txt", 100).is_err());
    }

    #[test]
    fn empty_result_gets_info_finding() {
        let fs = names_to_findings("x.test", &[]);
        assert_eq!(fs.len(), 1);
        assert!(fs[0].title.contains("No subdomains"));
    }

    #[test]
    fn found_names_become_findings() {
        let fs = names_to_findings(
            "x.test",
            &[
                ("www.x.test".to_string(), "192.0.2.1".to_string()),
                (
                    "api.x.test".to_string(),
                    "certificate-transparency".to_string(),
                ),
            ],
        );
        assert_eq!(fs.len(), 2);
        assert!(fs[0].title.contains("Subdomain:"));
        assert!(fs
            .iter()
            .any(|f| f.metadata["source"] == json!("certificate-transparency")));
    }
}
