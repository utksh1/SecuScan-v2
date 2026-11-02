//! Domain Finder — discover related domains via Certificate Transparency.

use super::{get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use reqwest::Client;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct DomainFinder;

#[async_trait]
impl NativeScanner for DomainFinder {
    fn id(&self) -> &'static str {
        "domain_finder"
    }
    fn name(&self) -> &'static str {
        "Domain Finder"
    }
    fn description(&self) -> &'static str {
        "Find related domains via Certificate Transparency logs"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        _ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = get_str(inputs, "target")?;
        let min_certainty = inputs
            .get("min_certainty")
            .and_then(|v| v.as_i64())
            .unwrap_or(30) as u32;

        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("build client: {e}"))?;

        let crt_url = format!("https://crt.sh/?q=%25.{target}&output=json");
        let resp = client
            .get(&crt_url)
            .send()
            .await
            .map_err(|e| format!("crt.sh query: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("crt.sh returned {}", resp.status()));
        }
        let body = resp.text().await.unwrap_or_default();
        let entries: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();

        let mut domains: std::collections::BTreeMap<String, usize> = Default::default();
        for entry in &entries {
            if let Some(names) = entry.get("name_value").and_then(|v| v.as_str()) {
                for name in names.lines() {
                    let name = name.trim().to_ascii_lowercase();
                    if name.is_empty() || name == target.to_ascii_lowercase() {
                        continue;
                    }
                    let name = name
                        .trim_start_matches('*')
                        .trim_start_matches('.')
                        .to_string();
                    if name == target.to_ascii_lowercase() {
                        continue;
                    }
                    *domains.entry(name).or_insert(0) += 1;
                }
            }
        }

        let target_lower = target.to_ascii_lowercase();
        let target_parent = target_lower
            .split_once('.')
            .map(|(_, rest)| rest)
            .unwrap_or(&target_lower);
        let mut findings = Vec::new();
        let mut count = 0;
        for (domain, hits) in &domains {
            let mut score = 30u32 + (*hits as u32) * 5;
            if domain.ends_with(target_parent) {
                score += 30;
            }
            score = score.min(100);
            if score < min_certainty {
                continue;
            }
            findings.push(Finding {
                title: format!("Related domain: {domain} (certainty {score}%)"),
                category: "Domain Discovery".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!("Domain `{domain}` is likely related to `{target}` — found {hits} time(s) in CT logs."),
                remediation: "Verify ownership and ensure each related domain is inventoried and monitored.".into(),
                proof: format!("crt.sh: {hits} certificate entries for {domain}"),
                url: None,
                metadata: json!({"domain": domain, "certainty": score, "ct_hits": hits}),
                ..Default::default()
            });
            count += 1;
            if count >= 100 {
                break;
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: format!("No related domains found for {target}"),
                category: "Domain Discovery".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!("CT log search returned no related domains above {min_certainty}% certainty."),
                remediation: "This may indicate the organization uses a unique certificate issuer or no SAN coverage.".into(),
                proof: format!("crt.sh query: {crt_url}"),
                url: None,
                metadata: json!({"target": target, "min_certainty": min_certainty}),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}
