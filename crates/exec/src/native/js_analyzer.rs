//! JavaScript analyzer — secrets, endpoints, source maps (cyweb / Arkenar class).
//!
//! Fetches the landing page, then a bounded set of same-origin scripts.
//! Secret matches are redacted in proof. Detection only.

use super::website_scanner::{harvest_js_paths, join_url, same_origin};
use super::{get_i64_or, get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct JsAnalyzer;

#[async_trait]
impl NativeScanner for JsAnalyzer {
    fn id(&self) -> &'static str {
        "js_analyzer"
    }
    fn name(&self) -> &'static str {
        "JavaScript Analyzer"
    }
    fn description(&self) -> &'static str {
        "Harvest same-origin JS: API paths, source maps, redacted secret patterns"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = super::http_headers::normalize_url(get_str(inputs, "target")?)?;
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 10_000).clamp(1_000, 30_000) as u64,
        );
        let max_scripts = get_i64_or(inputs, "max_scripts", 8).clamp(1, 20) as usize;
        let client = super::http_headers::build_client(true, timeout)?;

        let landing = client
            .get(&target)
            .header("user-agent", "SecuScan-2.0 (js-analyzer)")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let html = landing.text().await.unwrap_or_default();
        let mut scripts: Vec<String> = harvest_js_paths(&html)
            .into_iter()
            .filter_map(|p| join_url(&target, &p))
            .filter(|u| same_origin(&target, u) && u.ends_with(".js"))
            .collect();
        scripts.sort();
        scripts.dedup();
        scripts.truncate(max_scripts);

        ctx.sink
            .emit(crate::events::TaskEvent::Info(format!(
                "js-analyzer: {} script(s) from {target}",
                scripts.len()
            )))
            .await;

        let mut findings = Vec::new();
        let mut bodies = vec![html];
        for url in &scripts {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let Ok(resp) = client.get(url).send().await else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let text = resp.text().await.unwrap_or_default();
            findings.extend(analyze_js(url, &text));
            bodies.push(text);
        }
        // Also scan the HTML itself for inline secrets / maps.
        findings.extend(analyze_js(&target, &bodies[0]));

        let mut endpoints = Vec::new();
        for body in &bodies {
            for p in harvest_js_paths(body) {
                if p.starts_with("/api") || p.starts_with("/v1") || p.starts_with("/graphql") {
                    endpoints.push(p);
                }
            }
        }
        endpoints.sort();
        endpoints.dedup();
        if !endpoints.is_empty() {
            findings.push(Finding {
                title: format!("{} API-like paths in JavaScript", endpoints.len()),
                category: "API".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: "Same-origin scripts reference these API paths.".into(),
                remediation: "Confirm each is intentionally public.".into(),
                proof: endpoints
                    .iter()
                    .take(30)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
                url: Some(target.clone()),
                metadata: json!({ "endpoints": endpoints }),
                ..Default::default()
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: format!("No JS secrets or maps on {target}"),
                category: "Web".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "Fetched {} script(s); no secret regex or source map hit.",
                    scripts.len()
                ),
                url: Some(target),
                ..Default::default()
            });
        }
        Ok(findings)
    }
}

pub fn analyze_js(url: &str, body: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (kind, re) in secret_regexes() {
        if let Some(m) = re.find(body) {
            out.push(Finding {
                title: format!("Possible {kind} in JavaScript"),
                category: "Web".into(),
                severity: Severity::High,
                kind: FindingKind::SuspectedIssue,
                description: format!("A {kind} pattern matched in {url}. Value is redacted."),
                remediation:
                    "Rotate the credential; load secrets from the environment, not the bundle."
                        .into(),
                proof: format!("{url}\n{}…", redact(m.as_str())),
                url: Some(url.into()),
                metadata: json!({ "kind": kind }),
                cwe: Some("CWE-798".into()),
                owasp: Some("A02:2021-Cryptographic Failures".into()),
                confidence: Some("uncertain".into()),
                ..Default::default()
            });
        }
    }
    if let Some(map) = super::dast_engine::source_map_ref(body) {
        out.push(Finding {
            title: format!("Source map: {map}"),
            category: "Web".into(),
            severity: Severity::Low,
            kind: FindingKind::Observation,
            description: "The bundle points at a source map.".into(),
            remediation: "Do not ship .map files to production.".into(),
            proof: format!("{url} → {map}"),
            url: Some(url.into()),
            cwe: Some("CWE-540".into()),
            ..Default::default()
        });
    }
    out
}

fn secret_regexes() -> Vec<(&'static str, regex::Regex)> {
    [
        ("AWS access key", r"AKIA[0-9A-Z]{16}"),
        ("GitHub token", r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        ("Google API key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        ("Private key header", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        (
            "JWT",
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        ),
    ]
    .into_iter()
    .filter_map(|(k, p)| regex::Regex::new(p).ok().map(|r| (k, r)))
    .collect()
}

fn redact(s: &str) -> String {
    if s.len() <= 8 {
        return "****".into();
    }
    format!("{}…{}", &s[..4], &s[s.len().saturating_sub(4)..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_redacts_aws_key() {
        let fs = analyze_js("https://a.test/app.js", "const k = 'AKIAIOSFODNN7EXAMPLE';");
        assert!(fs.iter().any(|f| f.title.contains("AWS")));
        assert!(fs.iter().all(|f| !f.proof.contains("IOSFODNN7EXAMPLE")));
    }

    #[test]
    fn source_map_noted() {
        let fs = analyze_js("https://a.test/app.js", "//# sourceMappingURL=app.js.map\n");
        assert!(fs.iter().any(|f| f.title.contains("Source map")));
    }
}
