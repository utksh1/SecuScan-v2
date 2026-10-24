//! API Scanner — OpenAPI / GraphQL first cut (native).
//!
//! Offline-first: a spec file on disk is enough. If `spec_url` is set it
//! is fetched. GraphQL introspection is a single POST and is reported as
//! a finding when it succeeds (schema leak), not used to crush the API.

use super::{get_i64_or, get_str, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

pub struct ApiScanner;

#[async_trait]
impl NativeScanner for ApiScanner {
    fn id(&self) -> &'static str { "api_scanner" }
    fn name(&self) -> &'static str { "API Scanner" }
    fn description(&self) -> &'static str {
        "Parse OpenAPI/Postman from disk or URL; probe operations; flag GraphQL introspection and missing rate-limit headers"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = get_str(inputs, "target")?;
        let spec_path = get_str_or(inputs, "spec_path", "");
        let spec_url = get_str_or(inputs, "spec_url", "");
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 10_000).clamp(1_000, 60_000) as u64,
        );
        let client = super::http_headers::build_client(true, timeout)?;
        let mut findings = Vec::new();

        let spec_text = if !spec_path.is_empty() {
            std::fs::read_to_string(spec_path)
                .map_err(|e| format!("read spec_path `{spec_path}`: {e}"))?
        } else if !spec_url.is_empty() {
            let resp = client.get(spec_url).send().await.map_err(|e| e.to_string())?;
            resp.text().await.map_err(|e| e.to_string())?
        } else {
            String::new()
        };

        if !spec_text.is_empty() {
            let spec = parse_spec(&spec_text)?;
            let ops = operations(&spec);
            findings.push(Finding {
                title: format!("API specification parsed ({} operations)", ops.len()),
                category: "API".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!("Loaded {} path operations from the supplied specification.", ops.len()),
                remediation: String::new(),
                proof: ops.iter().take(40).cloned().collect::<Vec<_>>().join("\n"),
                url: Some(target.to_string()),
                metadata: json!({ "operations": ops.len() }),
                ..Default::default()
            });
            let base = target.trim_end_matches('/');
            for op in ops.into_iter().take(25) {
                if ctx.cancel.is_cancelled() { break; }
                // Only probe GET-like documented paths that look safe.
                let (method, path) = op.split_once(' ').unwrap_or(("GET", op.as_str()));
                if !method.eq_ignore_ascii_case("get") { continue; }
                let url = if path.starts_with("http") { path.to_string() } else { format!("{base}{path}") };
                if url.contains('{') { continue; } // skip templated paths
                let Ok(resp) = client.get(&url).send().await else { continue };
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                if !headers.keys().any(|k| k.as_str().to_ascii_lowercase().contains("ratelimit")
                    || k.as_str().eq_ignore_ascii_case("x-ratelimit-limit"))
                    && (200..500).contains(&status)
                {
                    findings.push(Finding {
                        title: format!("Missing rate-limit headers on {method} {path}"),
                        category: "API".into(),
                        severity: Severity::Low,
                        kind: FindingKind::SuspectedIssue,
                        description: "No RateLimit / X-RateLimit-* header on a documented GET.".into(),
                        remediation: "Send IETF RateLimit headers (or vendor equivalents) on every API response.".into(),
                        proof: format!("GET {url} → {status}"),
                        url: Some(url),
                        metadata: json!({ "status": status }),
                        cwe: Some("CWE-770".into()),
                        owasp: Some("A04:2021-Insecure Design".into()),
                        confidence: Some("uncertain".into()),
                        ..Default::default()
                    });
                }
            }
        }

        // GraphQL introspection (single request).
        let gql = if target.contains("graphql") {
            target.to_string()
        } else {
            format!("{}/graphql", target.trim_end_matches('/'))
        };
        let body = json!({"query": "{ __schema { queryType { name } } }"});
        if let Ok(resp) = client.post(&gql).json(&body).send().await {
            let status = resp.status().as_u16();
            if let Ok(v) = resp.json::<Value>().await {
                if v.pointer("/data/__schema").is_some() {
                    findings.push(Finding {
                        title: "GraphQL introspection is enabled".into(),
                        category: "API".into(),
                        severity: Severity::Medium,
                        kind: FindingKind::ValidatedIssue,
                        description: "The endpoint answered an introspection query and returned a schema.".into(),
                        remediation: "Disable introspection in production; require auth on /graphql.".into(),
                        proof: format!("POST {gql} → {status}\n{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
                        url: Some(gql),
                        metadata: json!({ "status": status }),
                        cwe: Some("CWE-200".into()),
                        owasp: Some("A01:2021-Broken Access Control".into()),
                        confidence: Some("certain".into()),
                        ..Default::default()
                    });
                }
            }
        }

        if findings.is_empty() {
            return Err("no specification loaded and GraphQL introspection did not respond — provide spec_path or spec_url".into());
        }
        Ok(findings)
    }
}

pub fn parse_spec(text: &str) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Ok(v);
    }
    serde_yaml::from_str(text).map_err(|e| format!("spec is neither JSON nor YAML: {e}"))
}

pub fn operations(spec: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(paths) = spec.get("paths").and_then(|v| v.as_object()) {
        for (path, item) in paths {
            if let Some(obj) = item.as_object() {
                for method in obj.keys() {
                    if matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete" | "head" | "options") {
                        out.push(format!("{} {path}", method.to_ascii_uppercase()));
                    }
                }
            }
        }
    }
    // Postman collection v2
    if out.is_empty() {
        if let Some(items) = spec.get("item").and_then(|v| v.as_array()) {
            collect_postman(items, &mut out);
        }
    }
    out
}

fn collect_postman(items: &[Value], out: &mut Vec<String>) {
    for item in items {
        if let Some(nested) = item.get("item").and_then(|v| v.as_array()) {
            collect_postman(nested, out);
        }
        if let Some(req) = item.get("request") {
            let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
            let url = req.get("url")
                .and_then(|u| u.get("raw").and_then(|v| v.as_str()).or_else(|| u.as_str()))
                .unwrap_or("");
            if !url.is_empty() {
                out.push(format!("{method} {url}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_paths_extracted() {
        let spec = r#"{"openapi":"3.0.0","paths":{"/pets":{"get":{},"post":{}},"/pets/{id}":{"get":{}}}}"#;
        let v = parse_spec(spec).unwrap();
        let ops = operations(&v);
        assert!(ops.contains(&"GET /pets".into()));
        assert!(ops.contains(&"POST /pets".into()));
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn yaml_spec_parses() {
        let spec = "openapi: 3.0.0\npaths:\n  /health:\n    get: {}\n";
        let v = parse_spec(spec).unwrap();
        assert!(operations(&v).contains(&"GET /health".into()));
    }
}
