//! Native DNS record lookup scanner.
//!
//! Fields (see `plugins/dns-lookup.toml`):
//! - `domain` (string, required) — name to resolve
//! - `record_type` (select) — A | AAAA | CNAME | MX | TXT | NS | SOA | PTR | SRV | CAA

use super::dns::{self, rtype, DnsError};
use super::{get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;

pub struct DnsLookupScanner;

#[async_trait]
impl NativeScanner for DnsLookupScanner {
    fn id(&self) -> &'static str {
        "dns_lookup"
    }

    fn name(&self) -> &'static str {
        "DNS Lookup"
    }

    fn description(&self) -> &'static str {
        "Resolve DNS records for a domain (A, AAAA, CNAME, MX, TXT, NS, SOA, \
         PTR, SRV, CAA) using the system resolver, flagging security-relevant \
         entries such as permissive CAA policies."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let domain = get_str(inputs, "target")?.trim().to_ascii_lowercase();
        let type_str = super::get_str_or(inputs, "record_type", "A");
        let rt = rtype::parse(type_str)
            .ok_or_else(|| format!("unknown record type `{type_str}`"))?;
        if !dns::valid_name(&domain) {
            return Err(format!("invalid domain name `{domain}`"));
        }
        let _ = ctx;

        let server = dns::system_server()
            .ok_or_else(|| "no DNS server available (resolv.conf empty?)".to_string())?;
        let records = dns::query(server, &domain, rt)
            .await
            .map_err(dns_err_msg)?;

        Ok(records_to_findings(&domain, rt, &records))
    }
}

pub(super) fn dns_err_msg(e: DnsError) -> String {
    match e {
        DnsError::NxDomain => "domain does not exist (NXDOMAIN)".into(),
        DnsError::Server(c) => format!("DNS server refused query ({c})"),
        DnsError::Transport(t) => format!("DNS query failed: {t}"),
    }
}

/// Pure conversion: records → findings. Unit-tested without a resolver.
pub(super) fn records_to_findings(
    domain: &str,
    rt: u16,
    records: &[dns::DnsRecord],
) -> Vec<Finding> {
    if records.is_empty() {
        return vec![finding(
            Severity::Info,
            format!("No {} records for {domain}", rtype::name(rt)),
            format!(
                "The resolver answered without {} records for `{domain}` — either the \
                 name exists without records of this type, or it does not exist at all.",
                rtype::name(rt)
            ),
            "If this domain should have such records, publish them at your DNS provider.",
            format!("{} {domain}: (empty)", rtype::name(rt)),
            json!({"domain": domain, "type": rtype::name(rt), "count": 0}),
        )];
    }

    let mut findings = Vec::new();
    for rec in records {
        let (sev, note) = assess(rt, &rec.data);
        let f = finding(
            sev,
            format!("{} record: {}", rtype::name(rt), rec.data),
            format!(
                "`{domain}` publishes a {} record{}.",
                rtype::name(rt),
                note.unwrap_or_default()
            ),
            remediation_for(rt),
            rec.data.clone(),
            json!({"domain": domain, "type": rtype::name(rt), "ttl": rec.ttl}),
        );
        findings.push(f);
    }
    findings
}

/// Severity + optional extra note for a record value.
fn assess(rt: u16, data: &str) -> (Severity, Option<&'static str>) {
    match rt {
        rtype::CAA => {
            // "0 issuewild \"\"" style records intentionally restrict issuance
            if data.contains("\"\"") || data.contains("\";\"") {
                (
                    Severity::Info,
                    Some(" — a semicolon/empty value blocks certificate issuance, which is \
                          intentional for domains that should never get TLS certs."),
                )
            } else {
                (Severity::Info, None)
            }
        }
        rtype::TXT if data.contains("v=spf1") => (Severity::Info, Some(" (SPF policy)")),
        rtype::TXT if data.contains("v=DMARC1") => (Severity::Info, Some(" (DMARC policy)")),
        rtype::TXT if data.contains("atlassian") || data.contains("site-verification")
            || data.contains("domain-verification") =>
        {
            (
                Severity::Low,
                Some(" — verification/token TXT entries can reveal which third-party \
                      services an organisation uses"),
            )
        }
        rtype::MX => (Severity::Info, None),
        rtype::NS => (Severity::Info, None),
        _ => (Severity::Info, None),
    }
}

fn remediation_for(rt: u16) -> &'static str {
    match rt {
        rtype::CAA => "Use CAA records to restrict which CAs may issue certificates for \
                       this domain.",
        rtype::TXT => "Review TXT entries periodically — stale verification tokens should \
                       be removed.",
        rtype::MX => "Ensure MX targets are reachable and have SPF/DMARC aligned with the \
                      sending domain.",
        _ => "Keep DNS records tidy — unused records expand the attack surface.",
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

    fn rec(rt: u16, data: &str) -> dns::DnsRecord {
        dns::DnsRecord {
            rtype: rt,
            ttl: 300,
            data: data.to_string(),
        }
    }

    #[test]
    fn empty_answer_gets_info_finding() {
        let fs = records_to_findings("x.test", rtype::MX, &[]);
        assert_eq!(fs.len(), 1);
        assert!(fs[0].title.contains("No MX records"));
    }

    #[test]
    fn a_records_listed() {
        let fs = records_to_findings(
            "x.test",
            rtype::A,
            &[rec(rtype::A, "192.0.2.1"), rec(rtype::A, "192.0.2.2")],
        );
        assert_eq!(fs.len(), 2);
        assert!(fs[0].title.contains("192.0.2.1"));
        assert_eq!(fs[0].severity, Severity::Info);
    }

    #[test]
    fn spf_txt_is_annotated() {
        let fs = records_to_findings("x.test", rtype::TXT, &[rec(rtype::TXT, "v=spf1 -all")]);
        assert!(fs[0].description.contains("SPF"));
    }

    #[test]
    fn verification_txt_flagged_low() {
        let fs = records_to_findings(
            "x.test",
            rtype::TXT,
            &[rec(rtype::TXT, "google-site-verification=abc")],
        );
        assert_eq!(fs[0].severity, Severity::Low);
    }

    #[test]
    fn caa_empty_value_annotated() {
        let fs = records_to_findings("x.test", rtype::CAA, &[rec(rtype::CAA, "0 issue \"\"")]);
        assert!(fs[0].description.contains("intentional"));
    }
}
