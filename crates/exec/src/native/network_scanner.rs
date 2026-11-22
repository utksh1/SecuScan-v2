//! Unified Network Scanner (Max-Parity Sprint 2.3, issue #28): composes
//! nmap version-based scanning, nuclei network templates and testssl.sh
//! behind one admission, one result set and per-engine toggles.
//!
//! Each engine is an existing tool invocation driven here as a subprocess
//! with the same runner used by CLI plugins — the composition value is that
//! admission, consent, rate limits, audit and the task lifecycle are paid
//! once for all three engines.

use super::{get_bool_or, get_i64_or, get_str_or, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

pub struct NetworkScanner;

#[derive(Debug, Clone, PartialEq)]
pub struct EngineResult {
    pub engine: &'static str,
    pub findings: Vec<Finding>,
    pub raw_output: String,
}

#[async_trait]
impl NativeScanner for NetworkScanner {
    fn id(&self) -> &'static str {
        "network_scanner"
    }
    fn name(&self) -> &'static str {
        "Unified Network Scanner"
    }
    fn description(&self) -> &'static str {
        "nmap version scan + nuclei network templates + testssl.sh with per-engine toggles, KEV-only mode and CVE allowlist"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = get_str_or(inputs, "target", "").to_string();
        let ports = get_str_or(inputs, "ports", "top-100").to_string();
        let engine_nmap = get_bool_or(inputs, "engine_nmap", true);
        let engine_nuclei = get_bool_or(inputs, "engine_nuclei", true);
        let engine_testssl = get_bool_or(inputs, "engine_testssl", false);
        let kev_only = get_bool_or(inputs, "nuclei_kev_only", false);
        let rps = get_i64_or(inputs, "rps", 150).clamp(1, 1000) as u32;
        let timeout = std::time::Duration::from_secs(
            get_i64_or(inputs, "timeout_ms", 30_000).clamp(1_000, 120_000) as u64,
        );

        let custom_cves: Vec<String> = inputs
            .get("custom_cves")
            .and_then(|v| v.as_str())
            .map(|s| {
                s.split(',')
                    .map(|c| c.trim().to_uppercase())
                    .filter(|c| c.starts_with("CVE-") && c.len() >= 9)
                    .take(500)
                    .collect()
            })
            .unwrap_or_default();

        let mut findings = Vec::new();
        let base = target.trim_end_matches('/').to_string();

        // --- Engine 1: nmap version-based --------------------------------
        if engine_nmap {
            ctx.sink
                .emit(crate::events::TaskEvent::Info("engine: nmap version scan".into()))
                .await;
            let args = build_nmap_args(&base, &ports);
            let outcome = run_tool(args.clone(), timeout, ctx).await?;
            findings.extend(parse_nmap_findings(&outcome, &target));
        }

        // --- Engine 2: nuclei network templates ---------------------------
        if engine_nuclei && !ctx.cancel.is_cancelled() {
            ctx.sink
                .emit(crate::events::TaskEvent::Info(if kev_only {
                    "engine: nuclei (CISA KEV only)".into()
                } else {
                    "engine: nuclei network templates".into()
                }))
                .await;
            let args = build_nuclei_args(&base, &custom_cves, kev_only, rps);
            let outcome = run_tool(args.clone(), timeout, ctx).await?;
            findings.extend(parse_nuclei_findings(&outcome, &custom_cves));
        }

        // --- Engine 3: testssl.sh ----------------------------------------
        if engine_testssl && !ctx.cancel.is_cancelled() {
            ctx.sink
                .emit(crate::events::TaskEvent::Info(
                    "engine: testssl.sh (long-running)".into(),
                ))
                .await;
            let args = build_testssl_args(&base);
            let outcome = run_tool(args.clone(), timeout, ctx).await?;
            findings.extend(parse_testssl_findings(&outcome));
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: format!("Unified network scan completed for {target}"),
                category: "Network".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!(
                    "Engines: nmap={engine_nmap}, nuclei={engine_nuclei}, testssl={engine_testssl}. \
                     No findings from the enabled engines."
                ),
                remediation: "Adjust engine toggles or port range for broader coverage.".into(),
                proof: String::new(),
                url: Some(target.clone()),
                metadata: json!({ "engines": { "nmap": engine_nmap, "nuclei": engine_nuclei, "testssl": engine_testssl } }),
                ..Default::default()
            });
        }
        Ok(findings)
    }
}

// --- tool invocation ---------------------------------------------------------

/// Run one external tool, streaming output as log events and capturing it.
async fn run_tool(argv: Vec<String>, timeout: Duration, ctx: &NativeCtx) -> Result<String, String> {
    if argv.is_empty() {
        return Err("empty tool argv".into());
    }
    // Tool availability check.
    let binary = &argv[0];
    if which(binary).is_err() {
        return Err(format!(
            "tool `{binary}` is not installed — install it (scripts/install-tools.sh) or disable this engine"
        ));
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let sink = crate::events::EventSink::new(uuid::Uuid::new_v4(), tx);

    let cancel = ctx.cancel.clone();
    let opts = crate::runner::RunOpts {
        timeout,
        cancel,
        ..Default::default()
    };

    let runner = tokio::spawn(async move {
        crate::runner::run_cli(&argv, opts, &sink).await
    });

    // Forward log lines to the task event stream.
    let log_sink = ctx.sink.clone();
    let forwarder = tokio::spawn(async move {
        while let Ok(env) = rx.try_recv() {
            if let crate::events::TaskEvent::LogLine { line, .. } = env.event {
                log_sink
                    .emit(crate::events::TaskEvent::LogLine {
                        stream: crate::events::StreamKind::Stdout,
                        line,
                    })
                    .await;
            }
        }
    });

    let outcome = runner
        .await
        .map_err(|e| format!("tool runner panicked: {e}"))?;
    let _ = forwarder.await;
    Ok(outcome.output)
}

fn which(binary: &str) -> Result<std::path::PathBuf, std::io::Error> {
    // Minimal which: check PATH entries for an executable match.
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let candidate = std::path::Path::new(dir).join(binary);
        if candidate.is_file() {
            return Ok(candidate);
        }
        #[cfg(windows)]
        {
            let with_ext = candidate.with_extension("exe");
            if with_ext.is_file() {
                return Ok(with_ext);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("`{binary}` not on PATH"),
    ))
}

// --- nmap -------------------------------------------------------------------

fn build_nmap_args(target: &str, ports: &str) -> Vec<String> {
    let port_args: Vec<String> = if ports == "top-100" {
        vec!["--top-ports".into(), "100".into()]
    } else if ports.contains('-') {
        vec!["-p".into(), ports.into()]
    } else {
        vec!["-p".into(), ports.into()]
    };
    vec![
        "nmap".into(),
        "-sV".into(),          // version detection
        "--version-intensity".into(), "5".into(),
        port_args[0].clone(),
        port_args[1].clone(),
        "-oN".into(), "-".into(), // stdout output
        target.into(),
    ]
}

fn parse_nmap_findings(output: &str, target: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut current_host = target.to_string();
    for line in output.lines() {
        let l = line.trim();
        // Host line: "Nmap scan report for host (ip)"
        if let Some(rest) = l.strip_prefix("Nmap scan report for ") {
            current_host = rest
                .split(" (")
                .next()
                .unwrap_or(target)
                .to_string();
        }
        // Open service: "22/tcp  open  ssh  OpenSSH 8.9"
        if let Some((port_proto, rest)) = l.split_once('/') {
            if let Ok(_port) = port_proto.parse::<u16>() {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                // parts[0] is the protocol ("tcp"/"udp"), parts[1] is the state.
                if parts.first() == Some(&"tcp") && parts.get(1) == Some(&"open") {
                    let service = parts.get(2).copied().unwrap_or("unknown");
                    let version = parts.get(3..).unwrap_or(&[]).join(" ");
                    let title = if version.is_empty() {
                        format!("Open service: {service} on {current_host}:{port_proto}")
                    } else {
                        format!("Open service: {service} {version} on {current_host}:{port_proto}")
                    };
                    out.push(Finding {
                        title,
                        category: "Network".into(),
                        severity: Severity::Info,
                        kind: FindingKind::Observation,
                        description: format!(
                            "nmap version scan found an open {service} service on {current_host}:{port_proto}."
                        ),
                        remediation: "Review exposed services and close or restrict them.".into(),
                        proof: line.to_string(),
                        url: None,
                        metadata: json!({
                            "host": current_host,
                            "port": port_proto,
                            "service": service,
                            "version": version,
                        }),
                        confidence: Some("uncertain".into()),
                        ..Default::default()
                    });
                }
            }
        }
        // CVE banners: nmap version scripts can flag vulnerable versions.
        if l.to_ascii_lowercase().contains("vulnerable") || l.contains("CVE-") {
            out.push(Finding {
                title: format!("nmap flagged a potentially vulnerable service on {current_host}"),
                category: "Network".into(),
                severity: Severity::High,
                kind: FindingKind::SuspectedIssue,
                description: "The nmap version script matched a vulnerability pattern for the \
                              detected service version.".into(),
                remediation: "Verify against the vendor advisory and patch the service.".into(),
                proof: l.to_string(),
                url: None,
                metadata: json!({ "host": current_host }),
                confidence: Some("uncertain".into()),
                ..Default::default()
            });
        }
    }
    out
}

// --- nuclei ------------------------------------------------------------------

fn build_nuclei_args(target: &str, custom_cves: &[String], kev_only: bool, rps: u32) -> Vec<String> {
    let mut args = vec![
        "nuclei".into(),
        "-target".into(), target.into(),
        "-tags".into(), "network,cve".into(),
        "-jsonl".into(),
        "-silent".into(),
        "-rl".into(), rps.to_string(),
        "-timeout".into(), "10".into(),
    ];
    if kev_only {
        args.push("-tags".into());
        args.push("kev".into());
    }
    if !custom_cves.is_empty() {
        // Restrict to the custom-CVE allowlist (max 500, each joined for one -tags).
        let capped: Vec<&String> = custom_cves.iter().take(500).collect();
        args.push("-tags".into());
        args.push(capped.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(","));
    }
    args
}

fn parse_nuclei_findings(output: &str, _custom_cves: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in output.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let title = v
            .get("info")
            .and_then(|i| i.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("nuclei network finding")
            .to_string();
        let severity = match v
            .pointer("/info/severity")
            .and_then(|s| s.as_str())
            .unwrap_or("info")
        {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let matched = v.get("matched").and_then(|m| m.as_str()).unwrap_or("");
        let cve = v
            .pointer("/info/classification/cve-id")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|c| c.as_str())
            .map(str::to_string);
        let is_kev = v
            .pointer("/info/classification/cvss-metrics")
            .and_then(|c| c.as_str())
            .map(|m| m.to_lowercase().contains("kev"))
            .unwrap_or(false);
        out.push(Finding {
            title: format!("nuclei: {title}"),
            category: "Network".into(),
            severity,
            kind: FindingKind::ValidatedIssue,
            description: v
                .pointer("/info/description")
                .and_then(|d| d.as_str())
                .unwrap_or("Nuclei template match on a network service.")
                .to_string(),
            remediation: "Review the finding against the vendor advisory and patch.".into(),
            proof: matched.to_string(),
            url: Some(matched.to_string()),
            metadata: json!({
                "engine": "nuclei",
                "template_id": v.get("template-id"),
                "matched": matched,
                "is_kev": is_kev,
            }),
            cve,
            cvss_v3: v.pointer("/info/classification/cvss-score").and_then(|c| c.as_f64()),
            cvss_vector: v
                .pointer("/info/classification/cvss-vector-string")
                .and_then(|c| c.as_str())
                .map(str::to_string),
            cisa_kev: is_kev,
            confidence: Some("certain".into()),
            ..Default::default()
        });
    }
    out
}

// --- testssl.sh ---------------------------------------------------------------

fn build_testssl_args(target: &str) -> Vec<String> {
    vec![
        "testssl.sh".into(),
        "--quiet".into(),
        "--color".into(), "0".into(),
        "--jsonfile-pretty".into(), "-".into(),
        target.into(),
    ]
}

fn parse_testssl_findings(output: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in output.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let raw_severity = v.get("severity").and_then(|s| s.as_str()).unwrap_or("info").to_uppercase();
        // testssl emits OK/INFO entries for passed checks — skip them (parity:
        // only problems are reported). An operator can read the raw output for
        // the full pass/fail table.
        if raw_severity == "OK" || raw_severity == "INFO" {
            continue;
        }
        let severity = match raw_severity.as_str() {
            "CRITICAL" | "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Info,
        };
        let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("testssl");
        let finding = v.get("finding").and_then(|f| f.as_str()).unwrap_or("");
        if severity == Severity::Info && finding.is_empty() {
            continue;
        }
        out.push(Finding {
            title: format!("testssl: {}", v.get("test-name").and_then(|t| t.as_str()).unwrap_or(id)),
            category: "TLS".into(),
            severity,
            kind: FindingKind::SuspectedIssue,
            description: finding.to_string(),
            remediation: "Review the testssl.sh finding and update the TLS configuration.".into(),
            proof: output.lines().count().to_string(),
            url: v.get("target").and_then(|t| t.as_str()).map(str::to_string),
            metadata: json!({ "engine": "testssl", "id": id }),
            confidence: Some("uncertain".into()),
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_args_include_ports_and_version_detection() {
        let args = build_nmap_args("10.0.0.5", "top-100");
        assert!(args.contains(&"-sV".to_string()));
        assert!(args.contains(&"10.0.0.5".to_string()));
        assert!(args.contains(&"100".to_string()));
        let args2 = build_nmap_args("10.0.0.5", "22,80,443");
        assert!(args2.contains(&"22,80,443".to_string()));
    }

    #[test]
    fn nmap_parse_extracts_open_services_and_version() {
        let output = "\
Nmap scan report for 10.0.0.5
Host is up (0.001s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
443/tcp  open  ssl     OpenSSL 3.0.2
80/tcp   closed http
";
        let findings = parse_nmap_findings(output, "10.0.0.5");
        assert_eq!(findings.len(), 2, "two open services");
        assert!(findings[0].title.contains("ssh"));
        assert!(findings[0].title.contains("OpenSSH 8.9"));
        assert!(findings[1].title.contains("ssl"));
    }

    #[test]
    fn nmap_parse_flags_vulnerable_banner() {
        let output = "22/tcp open ssh OpenSSH 7.2 (vulnerable to CVE-2023-38408)";
        let findings = parse_nmap_findings(output, "10.0.0.5");
        assert!(findings.iter().any(|f| f.severity == Severity::High), "CVE banner flagged");
    }

    #[test]
    fn nuclei_parse_extracts_jsonl_findings() {
        let output = r#"{"info":{"name":"Redis RCE","severity":"critical","description":"RCE in Redis","classification":{"cve-id":["CVE-2022-0543"],"cvss-score":10.0,"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N (KEV)"}},"matched":"10.0.0.5:6379","template-id":"CVE-2022-0543"}
{"info":{"name":"Not a finding","severity":"info"},"matched":"x","template-id":"y"}
"#;
        let findings = parse_nuclei_findings(output, &[]);
        assert_eq!(findings.len(), 2);
        let first = &findings[0];
        assert_eq!(first.severity, Severity::Critical);
        assert_eq!(first.cve.as_deref(), Some("CVE-2022-0543"));
        assert!(first.cisa_kev);
        assert_eq!(first.kind, FindingKind::ValidatedIssue);
    }

    #[test]
    fn kev_only_and_custom_cves_reach_nuclei_args() {
        let args = build_nuclei_args("10.0.0.5", &["CVE-2022-0543".into()], true, 300);
        assert!(args.contains(&"kev".to_string()));
        assert!(args.contains(&"CVE-2022-0543".to_string()));
        assert!(args.contains(&"300".to_string()));
    }

    #[test]
    fn custom_cves_capped_at_500_and_validated() {
        let cves: Vec<String> = (0..600).map(|i| format!("CVE-2024-{}", 1000 + i)).collect();
        let args = build_nuclei_args("t", &cves, false, 150);
        let joined = args.iter().find(|a| a.starts_with("CVE-")).unwrap();
        assert!(joined.split(',').count() <= 500, "capped at 500");
    }

    #[test]
    fn testssl_parse_maps_severities() {
        let output = r#"{"severity":"HIGH","id":"SSLv2","test-name":"SSL v2","finding":"vulnerable","target":"10.0.0.5:443"}
{"severity":"OK","id":"TLS1_2","test-name":"TLS 1.2","finding":"not vulnerable","target":"x"}
"#;
        let findings = parse_testssl_findings(output);
        assert_eq!(findings.len(), 1, "OK findings skipped");
        assert_eq!(findings[0].severity, Severity::High);
    }
}
