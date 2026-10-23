//! Native reverse-DNS (PTR) scanner.
//!
//! Fields (see `plugins/reverse-dns.toml`):
//! - `ip` (string, required) — IPv4 or IPv6 address

use super::dns::{self, rtype};
use super::{get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub struct ReverseDnsScanner;

#[async_trait]
impl NativeScanner for ReverseDnsScanner {
    fn id(&self) -> &'static str {
        "reverse_dns"
    }

    fn name(&self) -> &'static str {
        "Reverse DNS (PTR)"
    }

    fn description(&self) -> &'static str {
        "Resolve PTR records for an IP address to reveal the hostname an \
         operator assigned — useful to spot shared hosting, mail-server \
         identity mismatches and infrastructure naming leaks."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let ip_raw = get_str(inputs, "target")?.trim().to_string();
        let ip: IpAddr = ip_raw
            .parse()
            .map_err(|_| format!("`{ip_raw}` is not a valid IP address"))?;
        let _ = ctx;

        let server = dns::system_server()
            .ok_or_else(|| "no DNS server available (resolv.conf empty?)".to_string())?;
        let ptr_name = dns::arpa_ptr(&ip);
        let records = dns::query(server, &ptr_name, rtype::PTR)
            .await
            .map_err(super::dns_lookup::dns_err_msg)?;

        Ok(ptr_findings(&ip_raw, &ptr_name, &records))
    }
}

/// Pure conversion, unit-tested without a resolver.
pub(super) fn ptr_findings(
    ip: &str,
    arpa: &str,
    records: &[dns::DnsRecord],
) -> Vec<Finding> {
    let names: Vec<String> = records
        .iter()
        .filter(|r| r.rtype == rtype::PTR)
        .map(|r| r.data.clone())
        .collect();

    if names.is_empty() {
        return vec![finding(
            Severity::Info,
            format!("No PTR record for {ip}"),
            format!(
                "The resolver has no reverse mapping ({arpa}) for `{ip}`. Common for \
                 cloud VMs and CDN edges; mail servers without PTR are typically \
                 rejected by anti-spam systems."
            ),
            "For sending mail servers, publish a PTR that matches the HELO/EHLO name \
             and forward-resolves back to the same IP (FCrDNS).",
            format!("{arpa} -> (empty)"),
            json!({"ip": ip, "arpa": arpa}),
        )];
    }

    let mut out = Vec::new();
    for name in &names {
        // Generic cloud pool names hint at shared infrastructure; that is
        // useful recon context for the analyst.
        let shared = ["aws", "amazonaws", "compute", "ec2", "cloudfront", "googleusercontent",
            "azure", "cloudapp", "linode", "vultr", "ovh", "hetzner", "digitalocean"]
            .iter()
            .any(|k| name.to_ascii_lowercase().contains(k));
        out.push(finding(
            if shared { Severity::Info } else { Severity::Low },
            format!("PTR for {ip}: {name}"),
            format!(
                "The IP reverse-resolves to `{name}`.{}",
                if shared {
                    " The name pattern suggests a shared cloud/hosting pool."
                } else {
                    " A PTR exposing a descriptive internal hostname can leak \
                     infrastructure naming conventions."
                }
            ),
            "If the hostname is sensitive (project codes, environment names), use \
             neutral naming for publicly-facing addresses.",
            format!("{arpa} -> {name}"),
            json!({"ip": ip, "ptr": name, "shared_pool_hint": shared}),
        ));
    }
    out
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

    fn rec(data: &str) -> dns::DnsRecord {
        dns::DnsRecord {
            rtype: rtype::PTR,
            ttl: 300,
            data: data.to_string(),
        }
    }

    #[test]
    fn no_ptr_is_info() {
        let fs = ptr_findings("192.0.2.9", "9.2.0.192.in-addr.arpa", &[]);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Info);
        assert!(fs[0].title.contains("No PTR"));
    }

    #[test]
    fn descriptive_ptr_is_low() {
        let fs = ptr_findings("192.0.2.9", "9.2.0.192.in-addr.arpa", &[rec("mail.acme-corp.internal.")]);
        assert_eq!(fs[0].severity, Severity::Low);
        assert!(fs[0].title.contains("mail.acme-corp.internal"));
    }

    #[test]
    fn cloud_pool_ptr_is_info_with_hint() {
        let fs = ptr_findings(
            "192.0.2.9",
            "9.2.0.192.in-addr.arpa",
            &[rec("ec2-3-4-5-6.compute-1.amazonaws.com.")],
        );
        assert_eq!(fs[0].severity, Severity::Info);
        assert_eq!(fs[0].metadata["shared_pool_hint"], json!(true));
    }
}
