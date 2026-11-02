//! Native CORS misconfiguration scanner.
//!
//! Fields (see `plugins/cors-check.toml`):
//! - `target` (string, required) — URL to probe
//! - `extra_origins` (string, optional) — comma-separated origins to try
//!   in addition to the built-in probe set
//! - `timeout_ms` (integer, default 10000)
//!
//! Probes: an attacker-controlled origin, `null` (sandboxed iframe), a
//! subdomain of the target host, and a suffix look-alike — then inspects
//! `Access-Control-Allow-Origin` / `-Credentials` for reflection.

use super::http_headers::build_client;
use super::{get_i64_or, get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use reqwest::header::HeaderMap;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct CorsCheckScanner;

#[async_trait]
impl NativeScanner for CorsCheckScanner {
    fn id(&self) -> &'static str {
        "cors_check"
    }

    fn name(&self) -> &'static str {
        "CORS Misconfiguration Check"
    }

    fn description(&self) -> &'static str {
        "Probe a URL's cross-origin behaviour with attacker origins (arbitrary, \
         null, subdomain, suffix look-alike) and report reflective or wildcard \
         Access-Control policies, including credential leakage."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = super::http_headers::normalize_url(get_str(inputs, "target")?)?;
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 10_000).clamp(500, 30_000) as u64,
        );
        let _ = ctx;

        let host = reqwest::Url::parse(&target)
            .map_err(|e| format!("cannot parse target URL: {e}"))?
            .host_str()
            .ok_or("target URL has no host")?
            .to_string();

        let mut origins = vec![
            "https://attacker.example.com".to_string(),
            "null".to_string(),
            format!("https://evil.{host}"),
            format!("https://{host}.attacker.example.com"),
        ];
        for extra in get_str_extra(inputs, "extra_origins") {
            origins.push(extra);
        }

        let client = build_client(false, timeout)?;

        let mut findings = Vec::new();
        for origin in &origins {
            let resp = client
                .get(&target)
                .header("origin", origin)
                .header("user-agent", "SecuScan-2.0 (cors-check)")
                .send()
                .await
                .map_err(|e| format!("request to {target} failed: {e}"))?;
            let headers = resp.headers().clone();
            findings.extend(cors_findings_for_origin(origin, &headers, &host));
        }

        // baseline wildcard check (no Origin header at all)
        if let Ok(resp) = client
            .get(&target)
            .header("user-agent", "SecuScan-2.0 (cors-check)")
            .send()
            .await
        {
            let headers = resp.headers().clone();
            if let Some(acao) = header_str(&headers, "access-control-allow-origin") {
                if acao == "*" {
                    findings.push(finding(
                        Severity::Low,
                        "CORS: wildcard `Access-Control-Allow-Origin: *` on unauthenticated response",
                        "The endpoint allows scripts from ANY origin to read its \
                         responses. Safe for genuinely public data, but confirm \
                         nothing sensitive is served from this path."
                            .to_string(),
                        "If the data is private, echo verified origins explicitly \
                         instead of `*`.",
                        "access-control-allow-origin: * (no Origin header sent)",
                        json!({"acao": "*"}),
                    ));
                }
            }
        }

        Ok(findings)
    }
}

/// Inspect one probe response. Pure, unit-testable.
pub(super) fn cors_findings_for_origin(
    origin: &str,
    headers: &HeaderMap,
    target_host: &str,
) -> Vec<Finding> {
    let Some(acao) = header_str(headers, "access-control-allow-origin") else {
        return vec![];
    };
    let acac = header_str(headers, "access-control-allow-credentials")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let reflected = acao == origin;
    let label = origin_label(origin, target_host);

    if reflected && acac {
        vec![finding(
            Severity::High,
            format!("CORS reflects attacker origin `{origin}` WITH credentials ({label})"),
            "The endpoint echoes an attacker-chosen Origin AND allows credentials, \
             so a malicious page can read authenticated responses from victims' \
             browsers — equivalent to a cross-site data leak."
                .to_string(),
            "Allow-list exact origins server-side; never reflect an unvalidated \
             Origin header when `Access-Control-Allow-Credentials: true`.",
            format!(
                "origin: {origin} → access-control-allow-origin: {acao}, allow-credentials: true"
            ),
            json!({"origin": origin, "reflected": true, "credentials": true, "probe": label}),
        )]
    } else if reflected && origin == "null" {
        vec![finding(
            Severity::Medium,
            "CORS allows the `null` origin",
            "The `null` origin is used by sandboxed iframes and local files; \
             reflecting it lets documents from file:// or sandboxed frames read \
             this endpoint cross-origin."
                .to_string(),
            "Do not reflect `null`; allow-list real origins only.",
            "origin: null → access-control-allow-origin: null".to_string(),
            json!({"origin": "null", "reflected": true, "credentials": acac, "probe": label}),
        )]
    } else if reflected {
        let sev = if origin.contains(target_host) || origin.ends_with(target_host) {
            // subdomain reflection — lower risk, still noteworthy
            Severity::Low
        } else {
            Severity::Medium
        };
        vec![finding(
            sev,
            format!("CORS reflects attacker origin `{origin}` ({label})"),
            "The endpoint echoes an attacker-chosen Origin. Without credentials \
             this exposes only public data, but it often indicates origin \
             validation is missing entirely."
                .to_string(),
            "Allow-list exact origins server-side instead of reflecting the \
             Origin header.",
            format!("origin: {origin} → access-control-allow-origin: {acao}"),
            json!({"origin": origin, "reflected": true, "credentials": acac, "probe": label}),
        )]
    } else {
        // not reflected — policy exists but is not trivially abusable
        vec![]
    }
}

fn origin_label(origin: &str, target_host: &str) -> &'static str {
    match origin {
        "https://attacker.example.com" => "arbitrary origin",
        "null" => "null origin",
        o if o.ends_with(target_host) => "subdomain of target",
        o if o.starts_with("https://") && o.contains(target_host) => "suffix look-alike",
        _ => "custom",
    }
}

fn get_str_extra(inputs: &BTreeMap<String, serde_json::Value>, key: &str) -> Vec<String> {
    super::get_str_or(inputs, key, "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
}

fn finding(
    severity: Severity,
    title: impl Into<String>,
    description: impl Into<String>,
    remediation: &str,
    proof: impl Into<String>,
    metadata: serde_json::Value,
) -> Finding {
    let mut f = Finding::new(title, "CORS", severity, FindingKind::SuspectedIssue);
    f.description = description.into();
    f.remediation = remediation.to_string();
    f.proof = proof.into();
    f.metadata = metadata;
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn no_acao_is_clean() {
        let fs = cors_findings_for_origin(
            "https://attacker.example.com",
            &headers(&[("content-type", "text/html")]),
            "target.test",
        );
        assert!(fs.is_empty());
    }

    #[test]
    fn reflected_with_credentials_is_high() {
        let fs = cors_findings_for_origin(
            "https://attacker.example.com",
            &headers(&[
                (
                    "access-control-allow-origin",
                    "https://attacker.example.com",
                ),
                ("access-control-allow-credentials", "true"),
            ]),
            "target.test",
        );
        assert_eq!(fs[0].severity, Severity::High);
        assert!(fs[0].title.contains("WITH credentials"));
    }

    #[test]
    fn null_reflection_is_medium() {
        let fs = cors_findings_for_origin(
            "null",
            &headers(&[("access-control-allow-origin", "null")]),
            "target.test",
        );
        assert_eq!(fs[0].severity, Severity::Medium);
    }

    #[test]
    fn arbitrary_reflection_without_creds_is_medium() {
        let fs = cors_findings_for_origin(
            "https://attacker.example.com",
            &headers(&[(
                "access-control-allow-origin",
                "https://attacker.example.com",
            )]),
            "target.test",
        );
        assert_eq!(fs[0].severity, Severity::Medium);
    }

    #[test]
    fn subdomain_reflection_is_low() {
        let fs = cors_findings_for_origin(
            "https://evil.target.test",
            &headers(&[("access-control-allow-origin", "https://evil.target.test")]),
            "target.test",
        );
        assert_eq!(fs[0].severity, Severity::Low);
        assert_eq!(fs[0].metadata["probe"], json!("subdomain of target"));
    }
}
