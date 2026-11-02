//! API Scanner — OpenAPI / GraphQL first cut (native).
//!
//! Offline-first: a spec file on disk is enough. If `spec_url` is set it
//! is fetched. GraphQL introspection is a single POST and is reported as
//! a finding when it succeeds (schema leak), not used to crush the API.

use super::{get_bool_or, get_i64_or, get_str, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

pub struct ApiScanner;

#[async_trait]
impl NativeScanner for ApiScanner {
    fn id(&self) -> &'static str {
        "api_scanner"
    }
    fn name(&self) -> &'static str {
        "API Scanner"
    }
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
        // v4.2.1 profile knobs: cap how many spec paths are probed and gate
        // the more aggressive passes (verb tamper, GraphQL introspection).
        let max_operations = get_i64_or(inputs, "max_operations", 40).clamp(1, 200) as usize;
        let probe_verb_tamper = get_bool_or(inputs, "probe_verb_tamper", true);
        let probe_graphql = get_bool_or(inputs, "probe_graphql", true);
        let client = super::http_headers::build_client(true, timeout)?;
        let mut findings = Vec::new();

        let mut spec_text = if !spec_path.is_empty() {
            std::fs::read_to_string(spec_path)
                .map_err(|e| format!("read spec_path `{spec_path}`: {e}"))?
        } else if !spec_url.is_empty() {
            let resp = client
                .get(spec_url)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            resp.text().await.map_err(|e| e.to_string())?
        } else {
            String::new()
        };

        let base = target.trim_end_matches('/');
        if spec_text.is_empty() {
            for guess in [
                "/openapi.json",
                "/swagger.json",
                "/v3/api-docs",
                "/api-docs",
            ] {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                let url = format!("{base}{guess}");
                let Ok(resp) = client.get(&url).send().await else {
                    continue;
                };
                if !resp.status().is_success() {
                    continue;
                }
                let text = resp.text().await.unwrap_or_default();
                if parse_spec(&text).is_ok() && text.contains("paths") {
                    spec_text = text;
                    findings.push(Finding {
                        title: format!("OpenAPI document exposed at {guess}"),
                        category: "API".into(),
                        severity: Severity::Low,
                        kind: FindingKind::Observation,
                        description: "An unauthenticated GET returned a parseable OpenAPI/Swagger document.".into(),
                        remediation: "Serve the spec only to authenticated operators, or on an internal host.".into(),
                        proof: format!("GET {url} → 200"),
                        url: Some(url),
                        metadata: json!({ "path": guess }),
                        cwe: Some("CWE-200".into()),
                        owasp: Some("A01:2021-Broken Access Control".into()),
                        confidence: Some("certain".into()),
                        ..Default::default()
                    });
                    break;
                }
            }
        }

        if !spec_text.is_empty() {
            let spec = parse_spec(&spec_text)?;
            let ops = operations(&spec);
            findings.push(Finding {
                title: format!("API specification parsed ({} operations)", ops.len()),
                category: "API".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "Loaded {} path operations from the supplied specification.",
                    ops.len()
                ),
                remediation: String::new(),
                proof: ops.iter().take(40).cloned().collect::<Vec<_>>().join("\n"),
                url: Some(target.to_string()),
                metadata: json!({ "operations": ops.len() }),
                ..Default::default()
            });
            let mut unauth_ok = 0u32;
            for op in ops.into_iter().take(max_operations) {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                let (method, path) = op.split_once(' ').unwrap_or(("GET", op.as_str()));
                let url = if path.starts_with("http") {
                    path.to_string()
                } else {
                    format!("{base}{path}")
                };
                if url.contains('{') {
                    continue;
                }
                match method.to_ascii_uppercase().as_str() {
                    "GET" => {
                        let Ok(resp) = client.get(&url).send().await else {
                            continue;
                        };
                        let status = resp.status().as_u16();
                        let headers = resp.headers().clone();
                        let body = resp.text().await.unwrap_or_default();
                        if (200..300).contains(&status) {
                            unauth_ok += 1;
                            if let Some(key) = json_secret_key(&body) {
                                findings.push(Finding {
                                    title: format!("Response JSON contains sensitive key `{key}`"),
                                    category: "API".into(),
                                    severity: Severity::Medium,
                                    kind: FindingKind::SuspectedIssue,
                                    description: "An unauthenticated GET returned a JSON object with a credential-like key.".into(),
                                    remediation: "Never return secrets, tokens, or password hashes in API responses.".into(),
                                    proof: format!("GET {url} → {status}\n{}", truncate_json(&body, 400)),
                                    url: Some(url.clone()),
                                    metadata: json!({ "status": status, "key": key }),
                                    cwe: Some("CWE-200".into()),
                                    owasp: Some("A02:2021-Cryptographic Failures".into()),
                                    confidence: Some("uncertain".into()),
                                    ..Default::default()
                                });
                            }
                        }
                        if !headers.keys().any(|k| {
                            k.as_str().to_ascii_lowercase().contains("ratelimit")
                                || k.as_str().eq_ignore_ascii_case("x-ratelimit-limit")
                        }) && (200..500).contains(&status)
                        {
                            findings.push(Finding {
                                title: format!("Missing rate-limit headers on {method} {path}"),
                                category: "API".into(),
                                severity: Severity::Low,
                                kind: FindingKind::SuspectedIssue,
                                description: "No RateLimit / X-RateLimit-* header on a documented GET.".into(),
                                remediation: "Send IETF RateLimit headers (or vendor equivalents) on every API response.".into(),
                                proof: format!("GET {url} → {status}"),
                                url: Some(url.clone()),
                                metadata: json!({ "status": status }),
                                cwe: Some("CWE-770".into()),
                                owasp: Some("A04:2021-Insecure Design".into()),
                                confidence: Some("uncertain".into()),
                                ..Default::default()
                            });
                        }
                        // Verb tamper: documented GET also answers DELETE unauthenticated.
                        // Gated by the probe_verb_tamper profile knob (v4.2.1).
                        if probe_verb_tamper && (200..300).contains(&status) {
                            if let Ok(del) = client.delete(&url).send().await {
                                let ds = del.status().as_u16();
                                if (200..300).contains(&ds) {
                                    findings.push(Finding {
                                        title: format!("DELETE accepted on documented GET {path}"),
                                        category: "API".into(),
                                        severity: Severity::Medium,
                                        kind: FindingKind::SuspectedIssue,
                                        description: "An unauthenticated DELETE against a read path returned 2xx.".into(),
                                        remediation: "Reject unadvertised verbs; require auth on mutating methods.".into(),
                                        proof: format!("DELETE {url} → {ds}"),
                                        url: Some(url),
                                        metadata: json!({ "status": ds }),
                                        cwe: Some("CWE-650".into()),
                                        owasp: Some("A01:2021-Broken Access Control".into()),
                                        confidence: Some("uncertain".into()),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if unauth_ok >= 3 {
                findings.push(Finding {
                    title: format!("{unauth_ok} documented GET operations reachable without auth"),
                    category: "API".into(),
                    severity: Severity::Low,
                    kind: FindingKind::Observation,
                    description: "Several spec paths answered 2xx with no credentials presented."
                        .into(),
                    remediation: "Confirm each is intentionally public; require auth on the rest."
                        .into(),
                    proof: format!("{unauth_ok} unauthenticated 2xx GETs against {base}"),
                    url: Some(base.to_string()),
                    metadata: json!({ "unauth_ok": unauth_ok }),
                    cwe: Some("CWE-306".into()),
                    owasp: Some("A01:2021-Broken Access Control".into()),
                    confidence: Some("uncertain".into()),
                    ..Default::default()
                });
            }
        }

        // GraphQL introspection (single request). Gated by the
        // probe_graphql profile knob (v4.2.1) — skipped in the Quick profile.
        if probe_graphql {
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
        }

        if findings.is_empty() {
            return Err(format!(
                "no specification loaded{} — provide spec_path or spec_url",
                if probe_graphql {
                    " and GraphQL introspection did not respond"
                } else {
                    " and GraphQL probe is disabled"
                }
            ));
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
                    if matches!(
                        method.as_str(),
                        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                    ) {
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
            let url = req
                .get("url")
                .and_then(|u| u.get("raw").and_then(|v| v.as_str()).or_else(|| u.as_str()))
                .unwrap_or("");
            if !url.is_empty() {
                out.push(format!("{method} {url}"));
            }
        }
    }
}

pub fn json_secret_key(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let obj = v.as_object()?;
    for key in [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "access_token",
        "id_token",
    ] {
        if obj.contains_key(key) {
            return Some(key.into());
        }
    }
    None
}

fn truncate_json(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_paths_extracted() {
        let spec =
            r#"{"openapi":"3.0.0","paths":{"/pets":{"get":{},"post":{}},"/pets/{id}":{"get":{}}}}"#;
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

    #[test]
    fn secret_keys_detected() {
        assert_eq!(json_secret_key(r#"{"ok":true}"#), None);
        assert_eq!(
            json_secret_key(r#"{"access_token":"x"}"#).as_deref(),
            Some("access_token")
        );
        assert_eq!(json_secret_key("not-json"), None);
    }
}
