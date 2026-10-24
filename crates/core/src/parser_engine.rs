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
use crate::manifest::{
    JsonFindingTemplate, LineFindingTemplate, ParserSpec, SeverityRule, StaticRule,
};
use crate::models::{Finding, FindingKind, Severity, MAX_FINDINGS_PER_TASK};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// Hard cap on output size fed to the parser (8 MiB, matching v1's sandbox).
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Parse raw tool output according to the manifest parser spec + static rules.
/// Truncates the result at [`MAX_FINDINGS_PER_TASK`] findings (flagged in the
/// returned marker list is unnecessary: truncation is deterministic).
pub fn parse_output(
    spec: &ParserSpec,
    static_rules: &[StaticRule],
    output: &str,
) -> CoreResult<Vec<Finding>> {
    let mut findings = match spec {
        ParserSpec::Passthrough => Vec::new(),
        ParserSpec::LineRegex {
            pattern,
            finding,
            severity_rules,
            metadata_fields,
            skip_patterns,
        } => parse_line_regex(
            pattern, finding, severity_rules, metadata_fields, skip_patterns, output,
        )?,
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
    findings.retain(|f| seen.insert((f.severity.to_string(), f.title.clone(), f.url.clone())));

    findings.truncate(MAX_FINDINGS_PER_TASK);
    Ok(findings)
}

fn parse_line_regex(
    pattern: &str,
    template: &LineFindingTemplate,
    severity_rules: &[SeverityRule],
    metadata_fields: &[String],
    skip_patterns: &[String],
    output: &str,
) -> CoreResult<Vec<Finding>> {
    let re = regex::Regex::new(pattern)
        .map_err(|e| CoreError::Parse(format!("invalid parser pattern: {e}")))?;
    let skip_res: Vec<regex::Regex> = skip_patterns
        .iter()
        .map(|p| regex::Regex::new(p))
        .collect::<Result<_, _>>()
        .map_err(|e| CoreError::Parse(format!("invalid skip pattern: {e}")))?;
    let base_severity = Severity::parse(&template.severity).ok_or_else(|| {
        CoreError::Parse(format!("unknown base severity `{}`", template.severity))
    })?;

    let mut findings = Vec::new();
    for line in output.lines() {
        if findings.len() >= MAX_FINDINGS_PER_TASK {
            break;
        }
        if skip_res.iter().any(|re| re.is_match(line)) {
            continue;
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
            ..Default::default()
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
                    // Unmatched optional capture groups render as empty
                    // (mustache-style) so patterns with optional groups can
                    // feed every template field.
                    None => {}
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
            // Rule values support `*`/`?` globs (e.g. `OSVDB-*`), plus
            // exact matches.
            let hit = rule.values.iter().any(|allowed| {
                allowed == v.as_str() || crate::policy::glob_match(allowed, v.as_str())
            });
            if hit {
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
        // Proof: prefer the joined `proof_fields` list, then the single
        // `proof_field`, then the raw line (truncated).
        let joined_proof: Vec<String> = template
            .proof_fields
            .iter()
            .filter_map(|p| dot_path(&obj, p).and_then(value_to_plain_string))
            .collect();
        let proof = if !joined_proof.is_empty() {
            joined_proof.join(" | ")
        } else {
            template
                .proof_field
                .as_deref()
                .and_then(|p| dot_path(&obj, p))
                .and_then(value_to_plain_string)
                .unwrap_or_else(|| line.chars().take(512).collect())
        };

        // Per-finding category: split `category_field` on commas and match
        // each tag against `category_map` (exact, case-insensitive). Falls
        // back to the static category, then "General". Nuclei emits tags
        // as a JSON array; dalfox-style tools may emit a bare string --
        // both are normalized to a comma-separated list first.
        let category = template
            .category_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(value_to_tag_string)
            .and_then(|tags| {
                tags.split(',')
                    .filter_map(|t| {
                        let t = t.trim().to_ascii_lowercase();
                        if t.is_empty() {
                            return None;
                        }
                        template
                            .category_map
                            .iter()
                            .find(|(k, _)| k.to_ascii_lowercase() == t)
                            .map(|(_, v)| v.clone())
                    })
                    .next()
            })
            .or_else(|| template.category.clone())
            .unwrap_or_else(|| "General".to_string());

        // CVE: accept a bare string or an array (first element).
        let cve = template
            .cve_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(|v| match v {
                Value::String(s) if !s.is_empty() => Some(s.clone()),
                Value::Array(a) => a.iter().find_map(|e| match e {
                    Value::String(s) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                }),
                _ => None,
            })
            .filter(|s| s.to_ascii_uppercase().starts_with("CVE-"));
        let cvss_v3 = template
            .cvss_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(|v| match v {
                Value::Number(n) => n.as_f64(),
                Value::String(s) => s.trim().parse::<f64>().ok(),
                _ => None,
            })
            .map(|score| score.clamp(0.0, 10.0));
        let cvss_vector = template
            .cvss_vector_field
            .as_deref()
            .and_then(|p| dot_path(&obj, p))
            .and_then(value_to_plain_string)
            .filter(|s| s.contains("AV:"));

        // Copy listed dot-paths into metadata under their last segment.
        let mut metadata = serde_json::Map::new();
        for path in &template.metadata_fields {
            if let Some(v) = dot_path(&obj, path) {
                if !v.is_null() {
                    let key = path.rsplit('.').next().unwrap_or(path);
                    metadata.insert(key.to_string(), v.clone());
                }
            }
        }

        findings.push(Finding {
            kind: template
                .kind
                .as_deref()
                .and_then(FindingKind::parse)
                .unwrap_or(FindingKind::SuspectedIssue),
            severity,
            title,
            category,
            description,
            remediation: template.remediation.clone().unwrap_or_default(),
            proof,
            url,
            metadata: Value::Object(metadata),
            cve,
            cvss_v3,
            cvss_vector,
            ..Default::default()
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

/// Normalize a tag source to a comma-separated string: accepts a bare
/// string (`"cve,rce"`) or an array of strings (`["config","git"]`,
/// which nuclei emits for `info.tags`).
fn value_to_tag_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Array(a) => {
            let joined: Vec<String> = a
                .iter()
                .filter_map(|e| match e {
                    Value::String(s) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                })
                .collect();
            if joined.is_empty() {
                None
            } else {
                Some(joined.join(","))
            }
        }
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
        category: rule
            .category
            .clone()
            .unwrap_or_else(|| "General".to_string()),
        description: rule.description.clone().unwrap_or_default(),
        remediation: rule.remediation.clone().unwrap_or_default(),
        proof: rule
            .proof
            .clone()
            .unwrap_or_else(|| format!("matched `{}` at byte {}", rule.pattern, m.start())),
        url: None,
        metadata: json!({ "matched": m.as_str() }),
        ..Default::default()
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
                remediation: Some(
                    "Verify whether {service} on port {port} should be exposed.".into(),
                ),
                proof: Some("{proto} port {port} is OPEN".into()),
                category: Some("Network Service".into()),
                severity: "info".into(),
            },
            vec![SeverityRule {
                field: "port".into(),
                values: vec![
                    "21".into(),
                    "22".into(),
                    "23".into(),
                    "139".into(),
                    "445".into(),
                    "3306".into(),
                    "3389".into(),
                    "5432".into(),
                    "6379".into(),
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
                skip_patterns: vec![],
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
                skip_patterns: vec![],
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
                proof_fields: vec![],
                category: Some("Vulnerability".into()),
                category_field: None,
                category_map: Default::default(),
                cve_field: None,
                cvss_field: None,
                cvss_vector_field: None,
                metadata_fields: vec![],
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
    fn nuclei_deep_extraction_cve_cvss_category() {
        // Full nuclei JSONL line: tags -> category_map, classification ->
        // cve/cvss/vector, proof_fields join, metadata_fields copy.
        let spec = ParserSpec::JsonLines {
            finding: JsonFindingTemplate {
                title_field: "info.name".into(),
                description_field: Some("info.description".into()),
                severity_field: Some("info.severity".into()),
                url_field: Some("matched-at".into()),
                proof_field: Some("template-id".into()),
                proof_fields: vec!["curl-command".into(), "template-id".into()],
                category: Some("Vulnerability".into()),
                category_field: Some("info.tags".into()),
                category_map: [
                    ("sqli".to_string(), "SQL Injection".to_string()),
                    ("xss".to_string(), "XSS".to_string()),
                    ("wordpress".to_string(), "WordPress".to_string()),
                    ("credential".to_string(), "Credential".to_string()),
                ]
                .into_iter()
                .collect(),
                cve_field: Some("info.classification.cve-id".into()),
                cvss_field: Some("info.classification.cvss-score".into()),
                cvss_vector_field: Some("info.classification.cvss-vector".into()),
                metadata_fields: vec![
                    "info.tags".into(),
                    "info.reference".into(),
                    "host".into(),
                    "type".into(),
                ],
                remediation: None,
                kind: None,
            },
            severity_map: Default::default(),
        };
        let out = concat!(
            r#"{"template-id":"CVE-2021-44228-log4j-rce","info":{"name":"Apache Log4j RCE","severity":"critical","tags":"cve,rce,log4j","description":"Look for JNDI payloads.","classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0,"cvss-vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},"type":"http","host":"http://t","matched-at":"http://t/path","curl-command":"curl -X GET http://t/path"}"#,
            "\n",
            r#"{"template-id":"wp-plugin-x","info":{"name":"WP plugin X reflected XSS","severity":"high","tags":"xss,wordpress","classification":{}},"type":"http","host":"http://t","matched-at":"http://t/q"}"#,
            "\n",
            r#"{"template-id":"git-config","info":{"name":"Git Config Exposure","severity":"medium","tags":"exposure,config"},"type":"http","host":"http://t","matched-at":"http://t/.git/config","curl-command":"curl http://t/.git/config"}"#,
            "\n"
        );
        let findings = parse_output(&spec, &[], out).unwrap();
        assert_eq!(findings.len(), 3);

        // Line 1: no category_map tag matched (cve/rce/log4j unmapped) -> static.
        let f = &findings[0];
        assert_eq!(f.category, "Vulnerability");
        assert_eq!(f.cve.as_deref(), Some("CVE-2021-44228"));
        assert_eq!(f.cvss_v3, Some(10.0));
        assert_eq!(
            f.cvss_vector.as_deref(),
            Some("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
        // proof_fields join: curl-command | template-id
        assert_eq!(f.proof, "curl -X GET http://t/path | CVE-2021-44228-log4j-rce");
        assert_eq!(f.metadata["tags"], json!("cve,rce,log4j"));
        assert_eq!(f.metadata["reference"], json!(["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]));
        assert_eq!(f.metadata["host"], json!("http://t"));

        // Line 2: first tag xss maps before wordpress (tag order wins).
        let f = &findings[1];
        assert_eq!(f.category, "XSS");
        assert_eq!(f.cve, None);
        assert_eq!(f.cvss_v3, None);
        // No curl-command -> proof_fields yields template-id only.
        assert_eq!(f.proof, "wp-plugin-x");

        // Line 3: exposure falls back to static category; medium severity.
        let f = &findings[2];
        assert_eq!(f.category, "Vulnerability");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.proof, "curl http://t/.git/config | git-config");
    }

    #[test]
    fn nuclei_manifest_parses_real_template_output() {
        // Guards the full manifest -> ParserSpec -> findings path against
        // TOML-shape regressions (this exact path once silently produced
        // zero findings from valid nuclei JSONL).
        let src = std::fs::read_to_string("../../plugins/nuclei.toml")
            .expect("plugins/nuclei.toml must exist next to the workspace");
        let manifest: crate::manifest::PluginManifest =
            toml::from_str(&src).expect("nuclei.toml must deserialize");
        let ParserSpec::JsonLines { finding, severity_map } = &manifest.parser else {
            panic!("nuclei.toml parser must be json_lines, got {:?}", manifest.parser);
        };
        assert_eq!(finding.title_field, "info.name");
        assert_eq!(finding.url_field.as_deref(), Some("matched-at"));
        assert_eq!(finding.cve_field.as_deref(), Some("info.classification.cve-id"));
        assert!(finding.proof_fields.contains(&"curl-command".to_string()));
        assert!(finding.category_map.contains_key("sqli"));
        assert_eq!(severity_map.get("critical").map(String::as_str), Some("critical"));

        // A captured (abbreviated) nuclei JSONL line.
        let out = concat!(
            r#"{"template-id":"mysql-dump","info":{"name":"MySQL - Dump Files","tags":["exposure","backup","mysql","vuln"],"severity":"medium","classification":{"cve-id":null,"cwe-id":["cwe-200"],"cvss-score":5.3}},"type":"http","host":"127.0.0.1","matched-at":"http://127.0.0.1:8899/backup.sql","curl-command":"curl http://127.0.0.1:8899/backup.sql"}"#,
            "\n",
            r#"{"template-id":"sqli-template","info":{"name":"SQLi in thing","tags":["sqli","vuln"],"severity":"critical","classification":{"cve-id":["CVE-2024-1234"],"cvss-score":9.8,"cvss-vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},"type":"http","matched-at":"http://t/q","curl-command":"curl http://t/q"}"#,
            "\n"
        );
        let findings = parse_output(&manifest.parser, &[], out).unwrap();
        assert_eq!(findings.len(), 2, "both lines must yield findings");
        assert_eq!(findings[0].title, "MySQL - Dump Files");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].category, "Vulnerability"); // tags unmapped
        assert!(findings[0].proof.contains("curl"));
        assert_eq!(findings[0].metadata["tags"], json!(["exposure", "backup", "mysql", "vuln"]));
        // Second line maps sqli -> SQL Injection + extracts CVE/CVSS.
        assert_eq!(findings[1].category, "SQL Injection");
        assert_eq!(findings[1].cve.as_deref(), Some("CVE-2024-1234"));
        assert_eq!(findings[1].cvss_v3, Some(9.8));
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    #[test]
    fn nuclei_array_tags_map_to_categories() {
        // nuclei v3 emits info.tags as a JSON array, not a string.
        let spec = ParserSpec::JsonLines {
            finding: JsonFindingTemplate {
                title_field: "info.name".into(),
                description_field: None,
                severity_field: Some("info.severity".into()),
                url_field: Some("matched-at".into()),
                proof_field: None,
                proof_fields: vec![],
                category: Some("Vulnerability".into()),
                category_field: Some("info.tags".into()),
                category_map: [
                    ("sqli".to_string(), "SQL Injection".to_string()),
                    ("xss".to_string(), "XSS".to_string()),
                    ("wordpress".to_string(), "WordPress".to_string()),
                ]
                .into_iter()
                .collect(),
                cve_field: Some("info.classification.cve-id".into()),
                cvss_field: None,
                cvss_vector_field: None,
                metadata_fields: vec![],
                remediation: None,
                kind: None,
            },
            severity_map: Default::default(),
        };
        let out = concat!(
            r#"{"info":{"name":"WP plugin X","severity":"high","tags":["wordpress","wp-plugin","xss"],"classification":{"cve-id":null}},"matched-at":"http://t/x"}"#,
            "\n",
            r#"{"info":{"name":"Git Config","severity":"medium","tags":["config","git","exposure"],"classification":{"cwe-id":["cwe-552"]}},"matched-at":"http://t/.git/config"}"#,
            "\n"
        );
        let findings = parse_output(&spec, &[], out).unwrap();
        assert_eq!(findings.len(), 2);
        // Array tag order is preserved: wordpress maps before xss.
        assert_eq!(findings[0].category, "WordPress");
        // No mapped tag -> static fallback.
        assert_eq!(findings[1].category, "Vulnerability");
        // null cve-id -> no CVE on either finding.
        assert_eq!(findings[0].cve, None);
        assert_eq!(findings[1].cve, None);
    }

    #[test]
    fn json_lines_cve_validation_and_clamping() {
        // Bogus CVE strings are dropped; CVSS is clamped to 0..=10.
        let spec = ParserSpec::JsonLines {
            finding: JsonFindingTemplate {
                title_field: "info.name".into(),
                description_field: None,
                severity_field: Some("info.severity".into()),
                url_field: None,
                proof_field: None,
                proof_fields: vec![],
                category: None,
                category_field: None,
                category_map: Default::default(),
                cve_field: Some("cve".into()),
                cvss_field: Some("cvss".into()),
                cvss_vector_field: Some("vec".into()),
                metadata_fields: vec![],
                remediation: None,
                kind: None,
            },
            severity_map: Default::default(),
        };
        let out = concat!(
            r#"{"info":{"name":"a","severity":"low"},"cve":"OSVDB-1234","cvss":42.5,"vec":"not-a-vector"}"#,
            "\n",
            r#"{"info":{"name":"b","severity":"low"},"cve":"cve-2024-0001","cvss":"9.8","vec":"AV:N/AC:L"}"#,
            "\n"
        );
        let findings = parse_output(&spec, &[], out).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].cve, None); // not CVE- prefixed
        assert_eq!(findings[0].cvss_v3, Some(10.0)); // clamped
        assert_eq!(findings[0].cvss_vector, None); // no AV:
        assert_eq!(findings[1].cve.as_deref(), Some("cve-2024-0001"));
        assert_eq!(findings[1].cvss_v3, Some(9.8)); // string parse works
        assert_eq!(findings[1].cvss_vector.as_deref(), Some("AV:N/AC:L"));
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
                proof_fields: vec![],
                category: None,
                category_field: None,
                category_map: Default::default(),
                cve_field: None,
                cvss_field: None,
                cvss_vector_field: None,
                metadata_fields: vec![],
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
            skip_patterns: vec![],
        };
        let findings = parse_output(&spec, &[], "abc").unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    /// Regression: gobuster plugin parser must handle BOTH output formats.
    /// gobuster >= 3.5 prints `admin      (Status: 200) [Size: 34]`
    /// (no "Found:" prefix, no leading slash); older releases print
    /// `Found: /admin (Status: 200)`. Captured path is normalized (no
    /// leading slash) so severity globs match both.
    #[test]
    fn gobuster_both_output_formats() {
        let spec = ParserSpec::LineRegex {
            pattern: r"^(?:Found:\s+)?/?(?P<path>\S+?)\s+\(Status:\s+(?P<status>\d+)\)".into(),
            finding: LineFindingTemplate {
                title: "Discovered path: /{path} (HTTP {status})".into(),
                description: Some("The path /{path} exists.".into()),
                remediation: None,
                proof: Some("/{path} (Status: {status})".into()),
                category: Some("Content Discovery".into()),
                severity: "info".into(),
            },
            severity_rules: vec![SeverityRule {
                field: "path".into(),
                values: vec![
                    ".env*".into(),
                    ".git*".into(),
                    "backup*".into(),
                    "admin*".into(),
                ],
                severity: "medium".into(),
            }],
            metadata_fields: vec!["path".into(), "status".into()],
            skip_patterns: vec![],
        };
        let out = concat!(
            ".git                 (Status: 301) [Size: 0] [--> /.git/]\n",
            ".git/HEAD            (Status: 200) [Size: 21]\n",
            "admin                (Status: 301) [Size: 0] [--> /admin/]\n",
            "index.html           (Status: 200) [Size: 55]\n",
            "Found: /old-format   (Status: 200) [Size: 10]\n"
        );
        let findings = parse_output(&spec, &[], out).unwrap();
        assert_eq!(findings.len(), 5, "all lines parse in both formats");
        // modern format, sensitive path elevated
        assert_eq!(findings[0].title, "Discovered path: /.git (HTTP 301)");
        assert_eq!(findings[0].severity, Severity::Medium);
        // nested path under .git also elevated via glob
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[1].metadata["path"], json!(".git/HEAD"));
        // admin elevated
        assert_eq!(findings[2].severity, Severity::Medium);
        // ordinary path stays info
        assert_eq!(findings[3].severity, Severity::Info);
        // legacy "Found:" format parses with normalized path
        assert_eq!(findings[4].title, "Discovered path: /old-format (HTTP 200)");
        assert_eq!(findings[4].metadata["path"], json!("old-format"));
    }

    /// Regression: nikto check lines carry a numeric id `[740001]` that
    /// severity rules key off; summary lines without an id stay info, and
    /// colon-less check lines ("X appears to be outdated") still parse.
    #[test]
    fn nikto_check_ids_get_severity() {
        let spec = ParserSpec::LineRegex {
            pattern: r"^\+\s+(?:\[(?P<check>\d+)\]\s+)?(?P<item>[^:]+?)(?:\s*:\s*(?P<detail>.+))?$".into(),
            finding: LineFindingTemplate {
                title: "{item}".into(),
                description: Some("{detail}".into()),
                remediation: None,
                proof: None,
                category: Some("Web Server".into()),
                severity: "info".into(),
            },
            severity_rules: vec![
                SeverityRule {
                    field: "check".into(),
                    values: vec!["740001".into(), "006609".into()],
                    severity: "medium".into(),
                },
                SeverityRule {
                    field: "check".into(),
                    values: vec!["??????".into()],
                    severity: "low".into(),
                },
            ],
            metadata_fields: vec![],
            skip_patterns: vec![],
        };
        let out = concat!(
            "+ Target IP:          127.0.0.1\n",
            "+ Server: SimpleHTTP/0.6 Python/3.12.15\n",
            "+ [740001] /backup.zip: Potentially interesting backup/cert file found.  [Confidence: 70%]\n",
            "+ [006609] /.git/HEAD: Git HEAD file found. Full repo details may be present.\n",
            "+ [600652] Python/3.12.15 appears to be outdated (current is at least 3.14.6).\n"
        );
        let findings = parse_output(&spec, &[], out).unwrap();
        assert_eq!(findings.len(), 5);
        // summary lines: no id → info
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].title, "Target IP");
        assert_eq!(findings[0].description, "127.0.0.1");
        // backup + git exposure → medium
        assert_eq!(findings[2].severity, Severity::Medium);
        assert_eq!(findings[2].title, "/backup.zip");
        assert_eq!(findings[3].severity, Severity::Medium);
        // colon-less check line: still parsed, id elevates to low
        assert_eq!(findings[4].severity, Severity::Low);
        assert!(findings[4].title.contains("appears to be outdated"));
        assert_eq!(findings[4].description, "");
        // no proof template → verbatim scanner line as evidence
        assert_eq!(
            findings[2].proof,
            "+ [740001] /backup.zip: Potentially interesting backup/cert file found.  [Confidence: 70%]"
        );
    }

    /// Regression (found running real nikto 2.6.1): nikto's own diagnostics
    /// — `+ ERROR: Failed to check for updates`, `+ WARN: …`, run metadata
    /// (`+ Target IP`, `+ Start/End Time`, `+ N host(s) tested`) — matched
    /// the generic line pattern and became fake "findings". skip_patterns
    /// drops them before the main regex sees them.
    #[test]
    fn nikto_diagnostics_are_skipped() {
        let spec = ParserSpec::LineRegex {
            pattern: r"^\+\s+(?:\[(?P<check>\d+)\]\s+)?(?P<item>[^:]+?)(?:\s*:\s*(?P<detail>.+))?$".into(),
            finding: LineFindingTemplate {
                title: "{item}".into(),
                description: Some("{detail}".into()),
                remediation: None,
                proof: None,
                category: Some("Web Server".into()),
                severity: "info".into(),
            },
            severity_rules: vec![],
            metadata_fields: vec![],
            skip_patterns: vec![
                r"^\+\s+(ERROR|WARN):".into(),
                r"^\+\s+No web server found".into(),
                r"^\+\s+(Start|End) Time:".into(),
                r"^\+\s+Target (IP|Hostname|Port|Hostname:Port):".into(),
                r"^\+\s+\d+ host\(s\) tested".into(),
            ],
        };
        let out = concat!(
            "- Nikto v2.6.1\n",
            "+ Target IP:          127.0.0.1\n",
            "+ Target Port:        8899\n",
            "+ Start Time:         2026-10-23 11:08 (GMT)\n",
            "+ Server: SimpleHTTP/0.6 Python/3.12.15\n",
            "+ ERROR: Failed to check for updates: 400\n",
            "+ WARN: Could not connect to update server\n",
            "+ [740001] /backup.zip: Potentially interesting backup/cert file found.  [Confidence: 70%]\n",
            "+ End Time:           2026-10-23 11:08 (GMT)\n",
            "+ 1 host(s) tested\n"
        );
        let findings = parse_output(&spec, &[], out).unwrap();
        // only the real check line and the server banner survive
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].title, "Server");
        assert_eq!(findings[1].title, "/backup.zip");
        assert!(findings.iter().all(|f| f.title != "ERROR"));
        assert!(findings.iter().all(|f| f.title != "Target IP"));
        assert!(findings.iter().all(|f| f.title != "1 host(s) tested"));
    }

    #[test]
    fn passthrough_yields_no_findings() {
        assert!(parse_output(&ParserSpec::Passthrough, &[], "anything")
            .unwrap()
            .is_empty());
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
