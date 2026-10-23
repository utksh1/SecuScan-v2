//! Drupal Scanner — fingerprinting + CVE matching (native, no droopescan).

use super::{get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use reqwest::Client;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct DrupalScanner;

const DRUPAL_CVES: &[(&str, &str, f64, &str, &str)] = &[
    ("CVE-2014-3704", "Drupalgeddon — SQL injection in expandArguments()", 7.5, "7.0-7.31", "CWE-89"),
    ("CVE-2018-7600", "Drupalgeddon 2 — RCE via multiple endpoints", 9.8, "7.0-7.57 / 8.0-8.3.9", "CWE-20"),
    ("CVE-2018-7602", "Drupalgeddon 3 — RCE via file upload", 8.1, "7.0-7.58 / 8.0-8.4.7", "CWE-94"),
];

#[async_trait]
impl NativeScanner for DrupalScanner {
    fn id(&self) -> &'static str { "drupal_scanner" }
    fn name(&self) -> &'static str { "Drupal Scanner" }
    fn description(&self) -> &'static str { "Drupal CMS fingerprinting + CVE matching + module enumeration" }

    async fn run(&self, inputs: &BTreeMap<String, serde_json::Value>, _ctx: &NativeCtx) -> Result<Vec<Finding>, String> {
        let url = get_str(inputs, "target")?;
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build().map_err(|e| format!("build client: {e}"))?;
        let resp = client.get(url).send().await.map_err(|e| format!("fetch {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("target returned {}", resp.status()));
        }
        let html = resp.text().await.unwrap_or_default();
        let mut findings = Vec::new();

        let is_drupal = html.contains("Drupal") || html.contains("/sites/all/") || html.contains("/core/modules/");
        if !is_drupal {
            findings.push(Finding {
                title: "Drupal not detected".into(),
                category: "CMS Detection".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!("No Drupal fingerprints found at {url}."),
                remediation: "If this site runs Drupal, ensure the Drupal fingerprints are not stripped.".into(),
                proof: format!("Searched for 'Drupal', '/sites/all/', '/core/modules/' in {url}"),
                url: Some(url.into()),
                metadata: json!({"detected": false}),
                ..Default::default()
            });
            return Ok(findings);
        }

        let version = extract_version(&html);
        if let Some(v) = &version {
            findings.push(Finding {
                title: format!("Drupal {v} detected"),
                category: "CMS Detection".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!("Drupal version {v} at {url}"),
                remediation: "Keep Drupal updated to the latest stable release.".into(),
                proof: format!("Version fingerprint: {v}"),
                url: Some(url.into()),
                metadata: json!({"version": v, "detected": true}),
                ..Default::default()
            });
        }

        if let Some(v) = &version {
            for (cve, title, cvss, range, cwe) in DRUPAL_CVES {
                if cve_matches(v, range) {
                    let severity = if *cvss >= 9.0 { Severity::Critical }
                        else if *cvss >= 7.0 { Severity::High }
                        else if *cvss >= 4.0 { Severity::Medium }
                        else { Severity::Low };
                    findings.push(Finding {
                        title: format!("{cve}: {title}"),
                        category: "Drupal CVE".into(),
                        severity,
                        kind: FindingKind::SuspectedIssue,
                        description: format!("Drupal {v} at {url} is affected by {cve} ({title}). Affected versions: {range}."),
                        remediation: "Upgrade Drupal to a patched version immediately.".into(),
                        proof: format!("Detected version {v} falls in affected range {range}"),
                        url: Some(url.into()),
                        metadata: json!({"cve": cve, "cvss_v3": cvss, "affected_range": range}),
                        cve: Some(cve.to_string()),
                        cvss_v3: Some(*cvss),
                        cwe: Some(cwe.to_string()),
                        confidence: Some("uncertain".into()),
                        ..Default::default()
                    });
                }
            }
        }

        if let Some(modules) = extract_modules(&html) {
            for m in modules.iter().take(50) {
                findings.push(Finding {
                    title: format!("Module installed: {m}"),
                    category: "Module Enumeration".into(),
                    severity: Severity::Info,
                    kind: FindingKind::Observation,
                    description: format!("Drupal module `{m}` is installed at {url}."),
                    remediation: "Verify each installed module is current and necessary.".into(),
                    proof: format!("Module reference found in page source: {m}"),
                    url: Some(url.into()),
                    metadata: json!({"module": m}),
                    ..Default::default()
                });
            }
        }

        // Check CHANGELOG.txt exposure.
        let changelog_url = format!("{}/CHANGELOG.txt", url.trim_end_matches('/'));
        if let Ok(resp) = client.get(&changelog_url).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("Drupal") {
                    findings.push(Finding {
                        title: "CHANGELOG.txt exposed".into(),
                        category: "Information Disclosure".into(),
                        severity: Severity::Medium,
                        kind: FindingKind::ValidatedIssue,
                        description: format!("CHANGELOG.txt is publicly accessible at {changelog_url}, disclosing the exact Drupal version and patch history."),
                        remediation: "Block access to CHANGELOG.txt, README.txt, LICENSE.txt via web server config.".into(),
                        proof: format!("Fetched {changelog_url} successfully; first 100 chars: {}", body.chars().take(100).collect::<String>()),
                        url: Some(changelog_url.clone()),
                        metadata: json!({"url": changelog_url}),
                        ..Default::default()
                    });
                }
            }
        }

        Ok(findings)
    }
}

fn extract_version(html: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(?i)content="Drupal\s+(\d+\.\d+(?:\.\d+)?)"#).ok()?;
    if let Some(c) = re.captures(html) {
        return Some(c.get(1)?.as_str().to_string());
    }
    let re2 = regex::Regex::new(r#"Drupal\s+(\d+\.\d+\.\d+)"#).ok()?;
    re2.captures(html).map(|c| c.get(1).unwrap().as_str().to_string())
}

fn extract_modules(html: &str) -> Option<Vec<String>> {
    let re = regex::Regex::new(r"/(?:sites/all/modules|core/modules)/([a-zA-Z0-9_]+)/").ok()?;
    let mut mods: Vec<String> = re.captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect();
    mods.sort();
    mods.dedup();
    if mods.is_empty() { None } else { Some(mods) }
}

fn cve_matches(version: &str, range: &str) -> bool {
    let v = match parse_version(version) {
        Some(v) => v,
        None => return false,
    };
    for part in range.split('/') {
        let part = part.trim();
        let bounds: Vec<&str> = part.split('-').collect();
        if bounds.len() != 2 { continue; }
        let lo = match parse_version(bounds[0].trim()) { Some(v) => v, None => continue };
        let hi = match parse_version(bounds[1].trim()) { Some(v) => v, None => continue };
        if v >= lo && v <= hi { return true; }
    }
    false
}

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 { return None; }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_extracted_from_meta_generator() {
        let html = r#"<meta name="Generator" content="Drupal 9.4.8 (https://drupal.org)" />"#;
        assert_eq!(extract_version(html), Some("9.4.8".into()));
    }

    #[test]
    fn cve_matches_in_range() {
        assert!(cve_matches("7.31", "7.0-7.31"));
        assert!(!cve_matches("7.32", "7.0-7.31"));
        assert!(cve_matches("8.3.9", "7.0-7.57 / 8.0-8.3.9"));
        assert!(!cve_matches("8.4.0", "7.0-7.57 / 8.0-8.3.9"));
    }
}
