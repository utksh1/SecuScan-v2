//! Declarative parser engine: turns raw scanner output into normalized
//! [`Finding`]s using only the rules declared in the plugin manifest.
//!
//! Replaces v1's `parser.py` subprocess sandbox — no plugin-supplied code is
//! ever executed, which removes an entire class of supply-chain risk while
//! keeping the two wrapping patterns that cover the vast majority of tools:
//!
//! - [`ParserSpec::LineRegex`] — one finding per matching line (nmap, gobuster…)
//! - [`ParserSpec::JsonLines`] — one finding per JSON object line (nuclei…)

use crate::error::{CoreError, CoreResult};
use crate::manifest::{JsonFindingTemplate, LineFindingTemplate, ParserSpec, SeverityRule, StaticRule};
use crate::models::{Finding, FindingKind, Severity, MAX_FINDINGS_PER_TASK};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// Hard cap on output size fed to the parser (8 MiB, matching v1's sandbox).
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Parse raw tool output according to the manifest parser spec + static rules.
/// Truncates the result at [`MAX_FINDINGS_PER_TASK`] findings (flagged in the
/// returned marker list is unnecessary: truncation is deterministic).
pub fn parse_output(spec: &ParserSpec, static_rules: &[StaticRule], output: &str) -> CoreResult<Vec<Finding>> {
    let mut findings = match spec {
        ParserSpec::Passthrough => Vec::new(),
        ParserSpec::LineRegex {
            pattern,
            finding,
            severity_rules,
            metadata_fields,
        } => parse_line_regex(pattern, finding, severity_rules, metadata_fields, output)?,
        ParserSpec::JsonLines {
            finding,
            severity_map,
        } => parse_json_lines(finding, severity_map, output),
    };

    for rule in static_rules {
        if findings.len() >= MAX_FINDINGS_PER_TASK {
            break;
        }
        if let Some(f) = apply_static_rule(rule, output)? {
            findings.push(f);
        }
    }

    // Deduplicate identical (severity, title, url) triples produced by
    // overlapping rules, preserving first-seen order.
    let mut seen: HashSet<(String, String, Option<String>)> = HashSet::new();
    findings.retain(|f| {
        seen.insert((
            f.severity.to_string(),
            f.title.clone(),
            f.url.clone(),
        ))
    });

    findings.truncate(MAX_FINDINGS_PER_TASK);
    Ok(findings)
}

fn parse_line_regex(
    pattern: &str,
    template: &LineFindingTemplate,
    severity_rules: &[SeverityRule],
    metadata_fields: &[String],
    output: &str,
) -> CoreResult<Vec<Finding>> {
    let re = regex::Regex::new(pattern)
        .map_err(|e| CoreError::Parse(format!("invalid parser pattern: {e}")))?;
    let base_severity = Severity::parse(&template.severity)
        .ok_or_else(|| CoreError::Parse(format!("unknown base severity `{}`", template.severity)))?;

    let mut findings = Vec::new();
    for line in output.lines() {
        if findings.len() >= MAX_FINDINGS_PER_TASK {
            break;
        }
        let Some(caps) = re.captures(line) else {
            continue;
        };

        let title = substitute_groups(&template.title, &caps);
        let severity = effective_severity(base_severity, severity_rules, &caps);

        let mut metadata = Map::new();
        for mf in metadata_fields {
            if let Some(v) = caps.name(mf) {
                metadata.insert(mf.clone(), Value::String(v.as_str().to_string()));
            }
        }

        findings.push(Finding {
            kind: FindingKind::Observation,
            severity,
            title,
            category: template
                .category
                .clone()
                .unwrap_or_else(|| "General".to_string()),
            description: template
                .description
                .as_deref()
                .map(|d| substitute_groups(d, &caps))
                .unwrap_or_default(),
            remediation: template
                .remediation
                .as_deref()
                .map(|d| substitute_groups(d, &caps))
                .unwrap_or_default(),
            proof: template
                .proof
                .as_deref()
                .map(|d| substitute_groups(d, &caps))
                .unwrap_or_else(|| line.trim().to_string()),
            url: None,
            metadata: Value::Object(metadata),
        });
    }
    Ok(findings)
}

fn substitute_groups(template: &str, caps: &regex::Captures<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            None => {
                // unbalanced — keep literal
                out.push('{');
                rest = after;
            }
            Some(end) => {
                let name = &after[..end];
                match caps.name(name) {
                    Some(m) => out.push_str(m.as_str()),
                    None => out.push_str(&format!("{{{name}}}")),
                }
                rest = &after[end + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn effective_severity(
    base: Severity,
    rules: &[SeverityRule],
    caps: &regex::Captures<'_>,
) -> Severity {
    let mut sev = base;
    for rule in rules {
        if let Some(v) = caps.name(&rule.field) {
            if rule.values.iter().any(|allowed| allowed == v.as_str()) {
                if let Some(s) = Severity::parse(&rule.severity) {
                    // Rules may only *elevate* severity, never lower it.
                    if s > sev {
                        sev = s;
                    }
                }
            }
        }
    }
    sev
}

fn parse_json_lines(
    template: &JsonFindingTemplate,
    severity_map: &std::collections::BTreeMap<String, String>,
    output: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in output.lines() {
        if findings.len() >= MAX_FINDINGS_PER_TASK {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue; // tolerate non-JSON noise around the JSONL stream
        };
        if !obj.is_object() {
            continue;
        };

        let title = match dot_path(&obj, &template.title_field) {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => continue, // no title → nothing reportable on this line
        };

        let severity = template
            .severity_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                other if !other.is_null() => Some(other.to_string()),
                _ => None,
            })
            .and_then(|raw| {
                let key = raw.trim().to_ascii_lowercase();
                // direct SecuScan severities first, then the manifest map
                Severity::parse(&key)
                    .or_else(|| severity_map.get(&key).and_then(|m| Severity::parse(m)))
            })
            .unwrap_or(Severity::Info);

        let description = template
            .description_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(value_to_plain_string)
            .unwrap_or_default();
        let url = template
            .url_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(value_to_plain_string);
        let proof = template
            .proof_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(value_to_plain_string)
            .unwrap_or_else(|| line.chars().take(512).collect());

        findings.push(Finding {
            kind: template
                .kind
                .as_deref()
                .and_then(FindingKind::parse)
                .unwrap_or(FindingKind::SuspectedIssue),
            severity,
            title,
            category: template.category.clone().unwrap_or_else(|| "General".to_string()),
            description,
            remediation: template.remediation.clone().unwrap_or_default(),
            proof,
            url,
            metadata: json!({}),
        });
    }
    findings
}

fn value_to_plain_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Minimal dot-path walker: `a.b.0.c` traverses objects and arrays.
fn dot_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path.split('.') {
        if seg.is_empty() {
            return None;
        }
        cur = match cur {
            Value::Object(map) => map.get(seg)?,
            Value::Array(arr) => {
                let idx: usize = seg.parse().ok()?;
                arr.get(idx)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

fn apply_static_rule(rule: &StaticRule, output: &str) -> CoreResult<Option<Finding>> {
    let re = regex::Regex::new(&rule.pattern)
        .map_err(|e| CoreError::Parse(format!("invalid static rule pattern: {e}")))?;
    let Some(m) = re.find(output) else {
        return Ok(None);
    };
    let severity = Severity::parse(&rule.severity)
        .ok_or_else(|| CoreError::Parse(format!("unknown severity `{}`", rule.severity)))?;
    Ok(Some(Finding {
        kind: FindingKind::SuspectedIssue,
        severity,
        title: rule.title.clone(),
        category: rule.category.clone().unwrap_or_else(|| "General".to_string()),
        description: rule.description.clone().unwrap_or_default(),
        remediation: rule.remediation.clone().unwrap_or_default(),
        proof: rule
            .proof
            .clone()
            .unwrap_or_else(|| format!("matched `{}` at byte {}", rule.pattern, m.start())),
        url: None,
        metadata: json!({ "matched": m.as_str() }),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_spec() -> (String, LineFindingTemplate, Vec<SeverityRule>, Vec<String>) {
        (
            r"(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>[\w-]+)".to_string(),
            LineFindingTemplate {
                title: "Open port: {port}/{proto} ({service})".into(),
                description: Some("Port {port} is open and running {service}.".into()),
                remediation: Some("Verify whether {service} on port {port} should be exposed.".into()),
                proof: Some("{proto} port {port} is OPEN".into()),
                category: Some("Network Service".into()),
                severity: "info".into(),
            },
            vec![SeverityRule {
                field: "port".into(),
                values: vec![
                    "21".into(), "22".into(), "23".into(), "139".into(), "445".into(),
                    "3306".into(), "3389".into(), "5432".into(), "6379".into(),
                ],
                severity: "low".into(),
            }],
            vec!["port".into(), "proto".into(), "service".into()],
        )
    }

    #[test]
    fn nmap_style_line_regex() {
        let (p, f, r, m) = line_spec();
        let out = "22/tcp   open  ssh\n443/tcp  open  https\n9999/tcp closed xyz";
        let findings = parse_output(
            &ParserSpec::LineRegex {
                pattern: p,
                finding: f,
                severity_rules: r,
                metadata_fields: m,
            },
            &[],
            out,
        )
        .unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].title, "Open port: 22/tcp (ssh)");
        assert_eq!(findings[0].severity, Severity::Low); // high-risk port elevated
        assert_eq!(findings[1].severity, Severity::Info);
        assert_eq!(findings[0].metadata["port"], json!("22"));
        assert_eq!(findings[0].proof, "tcp port 22 is OPEN");
    }

    #[test]
    fn static_rule_fires_once() {
        let (p, f, r, m) = line_spec();
        let rule = StaticRule {
            pattern: "VULNERABLE".into(),
            title: "Potential vulnerability indicated by scanner".into(),
            severity: "high".into(),
            description: None,
            remediation: None,
            proof: None,
            category: None,
        };
        let out = "VULNERABLE something\nmore VULNERABLE text";
        let findings = parse_output(
            &ParserSpec::LineRegex {
                pattern: p,
                finding: f,
                severity_rules: r,
                metadata_fields: m,
            },
            &[rule],
            out,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn nuclei_style_json_lines() {
        let spec = ParserSpec::JsonLines {
            finding: JsonFindingTemplate {
                title_field: "info.name".into(),
                description_field: Some("info.description".into()),
                severity_field: Some("info.severity".into()),
                url_field: Some("matched_at".into()),
                proof_field: None,
                category: Some("Vulnerability".into()),
                remediation: None,
                kind: None,
            },
            severity_map: [("unknown".to_string(), "info".to_string())]
                .into_iter()
                .collect(),
        };
        let out = concat!(
            r#"{"info":{"name":"CVE-2023-1","severity":"high"},"matched_at":"http://t/x"}"#,
            "\n",
            r#"{"info":{"name":"CVE-2023-2","severity":"weird"},"matched_at":"http://t/y"}"#,
            "\n",
            "not json noise\n",
            "\n",
            r#"{"info":{"name":""},"matched_at":"http://t/z"}"#,
            "\n"
        );
        let findings = parse_output(&spec, &[], out).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].url.as_deref(), Some("http://t/x"));
        assert_eq!(findings[1].severity, Severity::Info); // unknown → info
        assert_eq!(findings[1].kind, FindingKind::SuspectedIssue);
    }

    #[test]
    fn dedup_identical_findings() {
        let spec = ParserSpec::JsonLines {
            finding: JsonFindingTemplate {
                title_field: "t".into(),
                description_field: None,
                severity_field: None,
                url_field: Some("u".into()),
                proof_field: None,
                category: None,
                remediation: None,
                kind: None,
            },
            severity_map: Default::default(),
        };
        let line = r#"{"t":"dup","u":"http://x"}"#;
        let out = format!("{line}\n{line}\n{line}");
        let findings = parse_output(&spec, &[], &out).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn severity_rules_never_lower() {
        // base medium, rule maps to low → must stay medium
        let spec = ParserSpec::LineRegex {
            pattern: r"(?P<v>\w+)".into(),
            finding: LineFindingTemplate {
                title: "{v}".into(),
                description: None,
                remediation: None,
                proof: None,
                category: None,
                severity: "medium".into(),
            },
            severity_rules: vec![SeverityRule {
                field: "v".into(),
                values: vec!["abc".into()],
                severity: "low".into(),
            }],
            metadata_fields: vec![],
        };
        let findings = parse_output(&spec, &[], "abc").unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn passthrough_yields_no_findings() {
        assert!(parse_output(&ParserSpec::Passthrough, &[], "anything").unwrap().is_empty());
    }

    #[test]
    fn dot_path_traverses_arrays() {
        let v = json!({"a": [{"b": 42}]});
        assert_eq!(dot_path(&v, "a.0.b").unwrap(), &json!(42));
        assert!(dot_path(&v, "a.9.b").is_none());
        assert!(dot_path(&v, "a.x").is_none());
    }

    #[test]
    fn output_cap_constant_sane() {
        assert_eq!(MAX_OUTPUT_BYTES, 8 * 1024 * 1024);
    }
}
