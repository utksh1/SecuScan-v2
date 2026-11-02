//! Native email-security scanner (SPF / DMARC / DKIM / MX posture).
//!
//! Fields (see `plugins/email-security.toml`):
//! - `domain` (string, required)
//! - `dkim_selectors` (string, optional) — comma-separated extra selectors
//!   probed in addition to the built-in common list
//!
//! All checks are DNS-only TXT/MX lookups against the system resolver.

use super::dns::{self, rtype};
use super::{get_str, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;

pub struct EmailSecurityScanner;

const COMMON_DKIM_SELECTORS: &[&str] = &[
    "google",
    "default",
    "selector",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "zoho",
    "everlytickey1",
    "everlytickey2",
    "freshmail",
    "mte",
];

#[async_trait]
impl NativeScanner for EmailSecurityScanner {
    fn id(&self) -> &'static str {
        "email_security"
    }

    fn name(&self) -> &'static str {
        "Email Security (SPF/DKIM/DMARC)"
    }

    fn description(&self) -> &'static str {
        "Audit a domain's email spoofing defences: SPF policy strictness, \
         DMARC policy, DKIM selector records and MX presence — all via DNS."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let domain = get_str(inputs, "target")?
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !dns::valid_name(&domain) {
            return Err(format!("invalid domain name `{domain}`"));
        }
        let extra: Vec<String> = get_str_or(inputs, "dkim_selectors", "")
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let _ = ctx;

        let server = dns::system_server()
            .ok_or_else(|| "no DNS server available (resolv.conf empty?)".to_string())?;

        let q = |name: &str, rt: u16| {
            let name = name.to_string();
            async move { dns::query(server, &name, rt).await }
        };

        let mut findings = Vec::new();

        // ---- MX ---------------------------------------------------------------
        let mx = q(&domain, rtype::MX).await.unwrap_or_default();
        findings.extend(mx_findings(&domain, &mx));

        // ---- SPF ---------------------------------------------------------------
        let txt = q(&domain, rtype::TXT).await.unwrap_or_default();
        let spf: Option<String> = txt
            .iter()
            .find(|r| r.rtype == rtype::TXT && r.data.starts_with("v=spf1"))
            .map(|r| r.data.clone());
        findings.extend(spf_findings(&domain, spf.as_deref()));

        // ---- DMARC ---------------------------------------------------------------
        let dmarc_txt = q(&format!("_dmarc.{domain}"), rtype::TXT)
            .await
            .unwrap_or_default();
        let dmarc: Option<String> = dmarc_txt
            .iter()
            .find(|r| r.rtype == rtype::TXT && r.data.contains("v=DMARC"))
            .map(|r| r.data.clone());
        findings.extend(dmarc_findings(&domain, dmarc.as_deref()));

        // ---- DKIM ---------------------------------------------------------------
        let mut selectors: Vec<String> = COMMON_DKIM_SELECTORS
            .iter()
            .map(|s| s.to_string())
            .chain(extra)
            .collect();
        selectors.dedup();
        let mut dkim_hits = Vec::new();
        for sel in &selectors {
            let recs = q(&format!("{sel}._domainkey.{domain}"), rtype::TXT)
                .await
                .unwrap_or_default();
            if recs.iter().any(|r| r.rtype == rtype::TXT) {
                dkim_hits.push(sel.clone());
            }
        }
        findings.extend(dkim_findings(&domain, &dkim_hits, selectors.len()));

        Ok(findings)
    }
}

/// Pure: MX records → findings.
pub(super) fn mx_findings(domain: &str, records: &[dns::DnsRecord]) -> Vec<Finding> {
    let hosts: Vec<&str> = records
        .iter()
        .filter(|r| r.rtype == rtype::MX)
        .map(|r| r.data.as_str())
        .collect();
    if hosts.is_empty() {
        vec![finding(
            Severity::Low,
            format!("No MX record for {domain}"),
            "Without an MX record, mailers fall back to the A record — which may \
             point at a web server that should never receive mail."
                .to_string(),
            "Publish explicit MX records, or a null MX (\"0 .\") if the domain \
             receives no mail.",
            format!("MX {domain}: (none)"),
            json!({"domain": domain, "check": "mx", "present": false}),
        )]
    } else {
        vec![finding(
            Severity::Info,
            format!("{} MX record(s) for {domain}", hosts.len()),
            format!("Mail for `{domain}` is handled by: {}.", hosts.join("; ")),
            "Verify each MX target applies current TLS and is not an open relay.",
            format!("MX {domain}: {}", hosts.join("; ")),
            json!({"domain": domain, "check": "mx", "records": hosts}),
        )]
    }
}

/// Pure: SPF policy string → findings.
pub(super) fn spf_findings(domain: &str, spf: Option<&str>) -> Vec<Finding> {
    match spf {
        None => vec![finding(
            Severity::Medium,
            format!("No SPF record for {domain}"),
            "Without an SPF policy, any host can send mail claiming to be from \
             this domain, and recipients cannot reject forgeries in SMTP."
                .to_string(),
            "Publish an SPF record: `v=spf1 include:_spf.<provider> -all`.",
            format!("TXT {domain}: no v=spf1"),
            json!({"domain": domain, "check": "spf", "present": false}),
        )],
        Some(rec) => {
            let mut out = Vec::new();
            let qualifier = rec.split_whitespace().rfind(|m| {
                m.eq_ignore_ascii_case("all")
                    || m.eq_ignore_ascii_case("+all")
                    || m.eq_ignore_ascii_case("?all")
                    || m.eq_ignore_ascii_case("~all")
                    || m.eq_ignore_ascii_case("-all")
            });
            match qualifier {
                Some(q) if q.eq_ignore_ascii_case("+all") => out.push(finding(
                    Severity::High,
                    format!("SPF for {domain} allows any sender (+all)"),
                    "The `+all` mechanism whitelists the entire internet to send \
                     mail as this domain — SPF provides no protection."
                        .to_string(),
                    "Replace `+all` with `-all` (hard fail) after listing every \
                     legitimate sending source.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "spf", "all": "+all"}),
                )),
                Some(q) if q.eq_ignore_ascii_case("all") => out.push(finding(
                    Severity::High,
                    format!("SPF for {domain} ends with a bare `all` (implicit +all)"),
                    "`all` without a qualifier means PASS for every host — the \
                     policy is permissive by omission."
                        .to_string(),
                    "Use an explicit `-all` qualifier.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "spf", "all": "bare-all"}),
                )),
                Some(q) if q.eq_ignore_ascii_case("?all") => out.push(finding(
                    Severity::Low,
                    format!("SPF for {domain} is neutral (?all)"),
                    "A neutral policy neither allows nor denies unlisted senders, \
                     so most receivers treat forgeries as acceptable."
                        .to_string(),
                    "Move to `~all` (soft-fail) or `-all` once all senders are listed.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "spf", "all": "?all"}),
                )),
                Some(q) if q.eq_ignore_ascii_case("~all") => out.push(finding(
                    Severity::Low,
                    format!("SPF for {domain} is soft-fail (~all)"),
                    "Soft-fail marks unlisted senders as suspicious but delivers \
                     their mail; DMARC enforcement is needed for real protection."
                        .to_string(),
                    "Harden to `-all` when confident all senders are listed.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "spf", "all": "~all"}),
                )),
                _ => out.push(finding(
                    Severity::Info,
                    format!("SPF for {domain} is strict (-all)"),
                    "Unlisted senders fail the policy — the strongest SPF posture.".to_string(),
                    "Keep the record current; monitor DMARC reports for legitimate \
                     senders being rejected.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "spf", "all": "-all"}),
                )),
            }
            // RFC 7208: max 10 DNS lookups during evaluation
            let lookupish = rec
                .split_whitespace()
                .filter(|m| {
                    let lower = m.to_ascii_lowercase();
                    lower.starts_with("include:")
                        || lower.starts_with("a")
                        || lower.starts_with("mx")
                        || lower.starts_with("ptr")
                        || lower.starts_with("exists:")
                        || lower.starts_with("redirect=")
                })
                .count();
            if lookupish > 10 {
                out.push(finding(
                    Severity::Low,
                    format!("SPF for {domain} exceeds the 10-DNS-lookup limit"),
                    format!(
                        "The record contains {lookupish} lookup mechanisms; receivers \
                         must stop evaluating at 10, so mail from later mechanisms \
                         may be treated as failed."
                    ),
                    "Flatten the SPF record or use your provider's SPF-flattening service.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "spf", "lookups": lookupish}),
                ));
            }
            out
        }
    }
}

/// Pure: DMARC policy string → findings.
pub(super) fn dmarc_findings(domain: &str, dmarc: Option<&str>) -> Vec<Finding> {
    match dmarc {
        None => vec![finding(
            Severity::Medium,
            format!("No DMARC record for {domain}"),
            "Without DMARC, receivers get no instruction on what to do with \
             mail that fails SPF/DKIM — spoofing usually lands in the inbox."
                .to_string(),
            "Publish `_dmarc.{domain}` TXT: `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`.",
            format!("_dmarc.{domain}: (none)"),
            json!({"domain": domain, "check": "dmarc", "present": false}),
        )],
        Some(rec) => {
            let lower = rec.to_ascii_lowercase();
            let policy = ["p=reject", "p=quarantine", "p=none"]
                .into_iter()
                .find(|p| lower.contains(p));
            match policy {
                Some("p=reject") => vec![finding(
                    Severity::Info,
                    format!("DMARC for {domain} is at enforcement (p=reject)"),
                    "Failing mail is rejected — the strongest DMARC posture.".to_string(),
                    "Keep rua reporting in place to catch breakage early.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "dmarc", "policy": "reject"}),
                )],
                Some("p=quarantine") => vec![finding(
                    Severity::Low,
                    format!("DMARC for {domain} quarantines failures (p=quarantine)"),
                    "Failing mail goes to spam rather than being rejected — good, \
                     but full enforcement is stronger."
                        .to_string(),
                    "Move to `p=reject` after monitoring quarantine reports.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "dmarc", "policy": "quarantine"}),
                )],
                _ => vec![finding(
                    Severity::Medium,
                    format!("DMARC for {domain} is monitor-only (p=none)"),
                    "The policy takes no action on failing mail — commonly left \
                     over from a monitoring phase that never finished."
                        .to_string(),
                    "After reviewing reports, tighten to `p=quarantine`/`p=reject`.",
                    rec.to_string(),
                    json!({"domain": domain, "check": "dmarc", "policy": "none"}),
                )],
            }
        }
    }
}

/// Pure: DKIM selector hits → findings.
pub(super) fn dkim_findings(domain: &str, hits: &[String], tried: usize) -> Vec<Finding> {
    if hits.is_empty() {
        vec![finding(
            Severity::Low,
            format!("No DKIM record found for {domain}"),
            format!(
                "None of the {tried} common selector names published a \
                 `<selector>._domainkey.{domain}` record. Either the domain does not \
                 sign mail, or it uses a private selector name."
            ),
            "Publish DKIM keys and verify alignment with the From: domain.",
            format!("0 DKIM selectors resolved for {domain}"),
            json!({"domain": domain, "check": "dkim", "selectors_found": []}),
        )]
    } else {
        hits.iter()
            .map(|sel| {
                finding(
                    Severity::Info,
                    format!("DKIM key published for selector `{sel}` ({domain})"),
                    format!(
                        "`{sel}._domainkey.{domain}` resolves — the domain \
                             signs mail with this key."
                    ),
                    "Rotate DKIM keys periodically (≥2048-bit RSA or Ed25519).",
                    format!("{sel}._domainkey.{domain}: TXT present"),
                    json!({"domain": domain, "check": "dkim", "selector": sel}),
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
    let mut f = Finding::new(title, "Email Security", severity, FindingKind::Observation);
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
    fn missing_spf_is_medium() {
        let fs = spf_findings("x.test", None);
        assert_eq!(fs[0].severity, Severity::Medium);
        assert!(fs[0].title.contains("No SPF"));
    }

    #[test]
    fn plus_all_is_high() {
        for rec in ["v=spf1 +all", "v=spf1 mx all"] {
            let fs = spf_findings("x.test", Some(rec));
            assert_eq!(fs[0].severity, Severity::High, "{rec}");
            assert!(fs[0].title.contains("allows any sender") || fs[0].title.contains("bare"));
        }
    }

    #[test]
    fn softfail_and_neutral_are_low() {
        assert_eq!(
            spf_findings("x.test", Some("v=spf1 ~all"))[0].severity,
            Severity::Low
        );
        assert_eq!(
            spf_findings("x.test", Some("v=spf1 ?all"))[0].severity,
            Severity::Low
        );
    }

    #[test]
    fn hardfail_is_info() {
        let fs = spf_findings("x.test", Some("v=spf1 include:_spf.google.com -all"));
        assert_eq!(fs[0].severity, Severity::Info);
    }

    #[test]
    fn lookup_limit_flagged() {
        let rec = "v=spf1 include:a include:b include:c include:d include:e \
                   include:f include:g include:h include:i include:j include:k -all";
        let fs = spf_findings("x.test", Some(rec));
        assert!(fs.iter().any(|f| f.title.contains("10-DNS-lookup")));
    }

    #[test]
    fn missing_dmarc_is_medium() {
        let fs = dmarc_findings("x.test", None);
        assert_eq!(fs[0].severity, Severity::Medium);
    }

    #[test]
    fn dmarc_policies_ranked() {
        assert_eq!(
            dmarc_findings("x.test", Some("v=DMARC1; p=reject; rua=mailto:a@x.test"))[0].severity,
            Severity::Info
        );
        assert_eq!(
            dmarc_findings("x.test", Some("v=DMARC1; p=quarantine"))[0].severity,
            Severity::Low
        );
        assert_eq!(
            dmarc_findings("x.test", Some("v=DMARC1; p=none"))[0].severity,
            Severity::Medium
        );
        // no p= at all → monitor-only branch
        assert_eq!(
            dmarc_findings("x.test", Some("v=DMARC1"))[0].severity,
            Severity::Medium
        );
    }

    #[test]
    fn dkim_none_is_low_found_is_info() {
        assert_eq!(dkim_findings("x.test", &[], 15)[0].severity, Severity::Low);
        assert_eq!(
            dkim_findings("x.test", &["google".to_string()], 15)[0].severity,
            Severity::Info
        );
    }

    #[test]
    fn mx_absent_low_present_info() {
        assert_eq!(mx_findings("x.test", &[])[0].severity, Severity::Low);
        let rec = dns::DnsRecord {
            rtype: rtype::MX,
            ttl: 60,
            data: "10 mail.x.test".into(),
        };
        assert_eq!(mx_findings("x.test", &[rec])[0].severity, Severity::Info);
    }
}
