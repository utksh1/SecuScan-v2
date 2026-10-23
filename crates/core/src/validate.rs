//! Manifest cross-validation and task-input validation.
//!
//! Both are *strict and total*: every problem is collected (not just the
//! first) so plugin authors get a complete report, and task authors get
//! actionable error messages.

use crate::error::{CoreError, CoreResult};
use crate::manifest::{EngineSpec, FieldSpec, FieldType, ParserSpec, PluginManifest, SeverityRule};
use crate::models::{FindingKind, Severity};
use std::collections::{BTreeMap, HashSet};

/// Hard limits shared by validation.
pub const MAX_STRING_INPUT: usize = 4_096;
pub const MIN_TIMEOUT_SECONDS: u64 = 1;
pub const MAX_TIMEOUT_SECONDS: u64 = 86_400;
pub const MAX_FIELDS: usize = 64;
pub const MAX_PRESETS: usize = 32;

/// Validate a manifest in place (structural checks are handled by serde;
/// this performs cross-reference and semantic checks). Returns every problem
/// found; the manifest must be rejected when the vector is non-empty.
pub fn validate_manifest(m: &PluginManifest) -> Vec<String> {
    let mut errs = Vec::new();

    // --- plugin identity -------------------------------------------------
    let id = &m.plugin.id;
    if id.is_empty() || id.len() > 64 {
        errs.push("plugin.id must be 1..=64 characters".into());
    } else if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || id.starts_with('-')
    {
        errs.push("plugin.id must match ^[a-z0-9][a-z0-9-]*$".into());
    }
    if m.plugin.name.trim().is_empty() {
        errs.push("plugin.name must not be empty".into());
    }
    if m.plugin.version.trim().is_empty() {
        errs.push("plugin.version must not be empty".into());
    }
    if m.plugin.description.trim().is_empty() {
        errs.push("plugin.description must not be empty".into());
    }
    if m.plugin.category.trim().is_empty() {
        errs.push("plugin.category must not be empty".into());
    }

    // --- fields ------------------------------------------------------------
    if m.fields.len() > MAX_FIELDS {
        errs.push(format!(
            "too many fields ({} > {MAX_FIELDS})",
            m.fields.len()
        ));
    }
    let mut seen_ids: HashSet<&str> = HashSet::new();
    let mut has_target = false;
    for f in &m.fields {
        if !seen_ids.insert(f.id.as_str()) {
            errs.push(format!("duplicate field id `{}`", f.id));
            continue;
        }
        validate_field(f, &mut errs);
        if f.id == "target" || f.id == "url" {
            if has_target {
                errs.push("only one of `target` / `url` fields may exist".into());
            }
            has_target = true;
        }
    }
    if !has_target {
        errs.push("every plugin must declare exactly one field named `target` or `url`".into());
    }

    // --- engine ------------------------------------------------------------
    match &m.engine {
        EngineSpec::Cli {
            binary,
            argv,
            timeout_seconds,
            ..
        } => {
            if argv.is_empty() {
                errs.push("engine.argv must not be empty".into());
            } else {
                let head = &argv[0];
                if head.contains('{') || head.starts_with("--if:") {
                    errs.push("engine.argv[0] must be a literal program name".into());
                } else if !binary.is_empty() && binary != head {
                    errs.push(format!(
                        "engine.binary `{binary}` does not match argv[0] `{head}`"
                    ));
                }
                for (idx, tok) in argv.iter().enumerate().skip(1) {
                    validate_template_token(tok, idx, &m.fields, &mut errs);
                }
            }
            if binary.trim().is_empty() {
                errs.push("engine.binary must not be empty".into());
            }
            if *timeout_seconds < MIN_TIMEOUT_SECONDS || *timeout_seconds > MAX_TIMEOUT_SECONDS {
                errs.push(format!(
                    "engine.timeout_seconds must be {MIN_TIMEOUT_SECONDS}..={MAX_TIMEOUT_SECONDS}"
                ));
            }
            if m.parser.is_passthrough_not_declared() {
                // fine: passthrough is a legitimate choice
            }
            validate_parser(m, &mut errs);
        }
        EngineSpec::Native {
            native,
            timeout_seconds,
        } => {
            if native.trim().is_empty() {
                errs.push("engine.native must be a non-empty native scanner id".into());
            }
            if *timeout_seconds < MIN_TIMEOUT_SECONDS || *timeout_seconds > MAX_TIMEOUT_SECONDS {
                errs.push(format!(
                    "engine.timeout_seconds must be {MIN_TIMEOUT_SECONDS}..={MAX_TIMEOUT_SECONDS}"
                ));
            }
        }
    }

    // --- presets -----------------------------------------------------------
    if m.presets.len() > MAX_PRESETS {
        errs.push(format!(
            "too many presets ({} > {MAX_PRESETS})",
            m.presets.len()
        ));
    }
    for (pname, values) in &m.presets {
        if pname.trim().is_empty() {
            errs.push("preset names must not be empty".into());
        }
        for (key, value) in values {
            match m.fields.iter().find(|f| &f.id == key) {
                None => errs.push(format!("preset `{pname}` references unknown field `{key}`")),
                Some(f) => {
                    if let Err(e) = check_value_against_field(f, value) {
                        errs.push(format!("preset `{pname}` field `{key}`: {e}"));
                    }
                }
            }
        }
    }

    // --- static rules ------------------------------------------------------
    for (i, r) in m.static_rules.iter().enumerate() {
        if let Err(e) = regex::Regex::new(&r.pattern) {
            errs.push(format!(
                "static_rules[{i}].pattern is not a valid regex: {e}"
            ));
        }
        if r.title.trim().is_empty() {
            errs.push(format!("static_rules[{i}].title must not be empty"));
        }
        if Severity::parse(&r.severity).is_none() {
            errs.push(format!(
                "static_rules[{i}].severity `{}` is not a known severity",
                r.severity
            ));
        }
    }

    // --- safety ------------------------------------------------------------
    if m.safety.max_concurrent == 0 || m.safety.max_concurrent > 64 {
        errs.push("safety.max_concurrent must be 1..=64".into());
    }
    if m.safety.max_per_hour > 100_000 {
        errs.push("safety.max_per_hour must be 0..=100000 (0 = unlimited)".into());
    }
    for t in &m.safety.allowed_targets {
        if t.trim().is_empty() {
            errs.push("safety.allowed_targets must not contain empty patterns".into());
        }
    }

    errs
}

fn validate_field(f: &FieldSpec, errs: &mut Vec<String>) {
    if f.id.trim().is_empty() {
        errs.push("field ids must not be empty".into());
        return;
    }
    if f.label.trim().is_empty() {
        errs.push(format!("field `{}` must have a label", f.id));
    }
    if let Some(p) = &f.pattern {
        if let Err(e) = regex::Regex::new(p) {
            errs.push(format!(
                "field `{}` pattern is not a valid regex: {e}",
                f.id
            ));
        }
    }
    match f.ftype {
        FieldType::Select => {
            if f.options.is_empty() {
                errs.push(format!("select field `{}` must declare options", f.id));
            }
        }
        FieldType::Integer => {
            if let (Some(min), Some(max)) = (f.min, f.max) {
                if min > max {
                    errs.push(format!("field `{}` has min > max", f.id));
                }
            }
        }
        _ => {
            if !f.options.is_empty() {
                errs.push(format!(
                    "field `{}` declares options but is not a select field",
                    f.id
                ));
            }
        }
    }
    if let Some(d) = &f.default {
        if let Err(e) = check_value_against_field(f, d) {
            errs.push(format!("field `{}` default: {e}", f.id));
        }
    }
}

/// Check a single JSON value against a field spec (used for defaults and
/// presets; task inputs go through [`normalize_inputs`]).
fn check_value_against_field(f: &FieldSpec, v: &serde_json::Value) -> Result<(), String> {
    use serde_json::Value;
    match f.ftype {
        FieldType::String | FieldType::Text => match v {
            Value::String(s) => {
                if s.len() > MAX_STRING_INPUT {
                    return Err(format!("value exceeds {MAX_STRING_INPUT} characters"));
                }
                check_pattern(f, s)
            }
            _ => Err("expected a string".into()),
        },
        FieldType::Integer => match v {
            Value::Number(n) => {
                let i = n
                    .as_i64()
                    .ok_or_else(|| "expected an integer".to_string())?;
                if let Some(min) = f.min {
                    if i < min {
                        return Err(format!("value {i} is below minimum {min}"));
                    }
                }
                if let Some(max) = f.max {
                    if i > max {
                        return Err(format!("value {i} is above maximum {max}"));
                    }
                }
                Ok(())
            }
            _ => Err("expected an integer".into()),
        },
        FieldType::Boolean => match v {
            Value::Bool(_) => Ok(()),
            Value::String(s) if s == "true" || s == "false" => Ok(()),
            _ => Err("expected a boolean".into()),
        },
        FieldType::Select => match v {
            Value::String(s) => {
                if f.options.iter().any(|o| &o.value == s) {
                    Ok(())
                } else {
                    Err(format!("`{s}` is not one of the allowed options"))
                }
            }
            _ => Err("expected a string option".into()),
        },
    }
}

fn check_pattern(f: &FieldSpec, s: &str) -> Result<(), String> {
    if s.contains('\0') || s.chars().any(|c| c.is_control()) {
        return Err("value must not contain control characters".into());
    }
    if let Some(p) = &f.pattern {
        let re = regex::Regex::new(p).map_err(|e| e.to_string())?;
        if !re.is_match(s) {
            return Err(f
                .message
                .clone()
                .unwrap_or_else(|| format!("value does not match required pattern {p}")));
        }
    }
    Ok(())
}

fn validate_template_token(tok: &str, idx: usize, fields: &[FieldSpec], errs: &mut Vec<String>) {
    if let Some(cond) = tok.strip_prefix("--if:") {
        // --if:field:then:X[:else:Y]
        let Some((field, rest)) = cond.split_once(":then:") else {
            errs.push(format!(
                "argv[{idx}]: conditional `{tok}` must contain `:then:`"
            ));
            return;
        };
        match fields.iter().find(|f| f.id == field) {
            None => errs.push(format!(
                "argv[{idx}]: conditional references unknown field `{field}`"
            )),
            Some(f) => {
                // Conditionals may reference any scalar field:
                // bool → true, string → non-empty, integer → non-zero.
                if matches!(f.ftype, FieldType::Select) {
                    errs.push(format!(
                        "argv[{idx}]: conditional field `{field}` cannot be a select field"
                    ));
                }
            }
        }
        let branches: Vec<&str> = match rest.rsplit_once(":else:") {
            Some((then, _else)) => vec![then, _else],
            None => vec![rest],
        };
        for b in branches {
            check_placeholders(b, idx, fields, errs);
        }
    } else {
        check_placeholders(tok, idx, fields, errs);
    }
}

fn check_placeholders(tok: &str, idx: usize, fields: &[FieldSpec], errs: &mut Vec<String>) {
    let re = regex::Regex::new(r"\{([a-zA-Z0-9_]+)\}").unwrap();
    for cap in re.captures_iter(tok) {
        let name = cap.get(1).unwrap().as_str();
        if !fields.iter().any(|f| f.id == name) {
            errs.push(format!(
                "argv[{idx}]: placeholder `{name}` does not reference a declared field"
            ));
        }
    }
}

fn validate_parser(m: &PluginManifest, errs: &mut Vec<String>) {
    match &m.parser {
        ParserSpec::Passthrough => {}
        ParserSpec::LineRegex {
            pattern,
            finding,
            severity_rules,
            metadata_fields,
            skip_patterns,
        } => {
            let re = match regex::Regex::new(pattern) {
                Ok(re) => re,
                Err(e) => {
                    errs.push(format!("parser.pattern is not a valid regex: {e}"));
                    return;
                }
            };
            for sp in skip_patterns {
                if let Err(e) = regex::Regex::new(sp) {
                    errs.push(format!("parser.skip_patterns: `{sp}` is not a valid regex: {e}"));
                }
            }
            if finding.title.trim().is_empty() {
                errs.push("parser.finding.title must not be empty".into());
            }
            let groups: HashSet<&str> = re.capture_names().flatten().collect();
            check_group_templates(&finding.title, &groups, "parser.finding.title", errs);
            if let Some(d) = &finding.description {
                check_group_templates(d, &groups, "parser.finding.description", errs);
            }
            if let Some(r) = &finding.remediation {
                check_group_templates(r, &groups, "parser.finding.remediation", errs);
            }
            if let Some(p) = &finding.proof {
                check_group_templates(p, &groups, "parser.finding.proof", errs);
            }
            if Severity::parse(&finding.severity).is_none() {
                errs.push(format!(
                    "parser.finding.severity `{}` is not a known severity",
                    finding.severity
                ));
            }
            for (i, rule) in severity_rules.iter().enumerate() {
                validate_severity_rule(rule, &groups, i, errs);
            }
            for mf in metadata_fields {
                if !groups.contains(mf.as_str()) {
                    errs.push(format!(
                        "parser.metadata_fields references unknown group `{mf}`"
                    ));
                }
            }
        }
        ParserSpec::JsonLines {
            finding,
            severity_map,
        } => {
            if finding.title_field.trim().is_empty() {
                errs.push("parser.finding.title_field must not be empty".into());
            }
            for (k, v) in severity_map {
                if Severity::parse(v).is_none() {
                    errs.push(format!(
                        "parser.severity_map[{k}] maps to unknown severity `{v}`"
                    ));
                }
            }
            if let Some(kind) = &finding.kind {
                if FindingKind::parse(kind).is_none() {
                    errs.push(format!("parser.finding.kind `{kind}` is not a known kind"));
                }
            }
        }
    }
}

fn validate_severity_rule(
    rule: &SeverityRule,
    groups: &HashSet<&str>,
    i: usize,
    errs: &mut Vec<String>,
) {
    if !groups.contains(rule.field.as_str()) {
        errs.push(format!(
            "parser.severity_rules[{i}].field references unknown group `{}`",
            rule.field
        ));
    }
    if Severity::parse(&rule.severity).is_none() {
        errs.push(format!(
            "parser.severity_rules[{i}].severity `{}` is not a known severity",
            rule.severity
        ));
    }
}

fn check_group_templates(t: &str, groups: &HashSet<&str>, what: &str, errs: &mut Vec<String>) {
    let re = regex::Regex::new(r"\{([a-zA-Z0-9_]+)\}").unwrap();
    for cap in re.captures_iter(t) {
        let name = cap.get(1).unwrap().as_str();
        if !groups.contains(name) {
            errs.push(format!("{what} references unknown capture group `{name}`"));
        }
    }
}

/// Validate and normalize task inputs against a plugin schema.
///
/// - unknown keys are rejected (catches typos early),
/// - defaults are applied for missing fields,
/// - required fields must be present after defaults,
/// - values are coerced to canonical JSON types and checked against
///   patterns, option lists and integer bounds,
/// - values that begin with `-` are rejected unless the field opts in with
///   `allow_dash = true` (argv flag-injection guard).
///
/// Returns the normalized input map.
pub fn normalize_inputs(
    m: &PluginManifest,
    inputs: &BTreeMap<String, serde_json::Value>,
) -> CoreResult<BTreeMap<String, serde_json::Value>> {
    use serde_json::Value;

    let field_ids: HashSet<&str> = m.fields.iter().map(|f| f.id.as_str()).collect();
    for key in inputs.keys() {
        if !field_ids.contains(key.as_str()) {
            return Err(CoreError::Input(format!(
                "unknown field `{key}` for plugin `{}`",
                m.plugin.id
            )));
        }
    }

    let mut normalized = BTreeMap::new();
    let mut errs = Vec::new();

    for f in &m.fields {
        let raw = inputs.get(&f.id).or(f.default.as_ref());
        let Some(raw) = raw else {
            if f.required {
                errs.push(format!("missing required field `{}`", f.id));
            }
            continue;
        };

        let value: Value = match f.ftype {
            FieldType::String | FieldType::Text => match raw {
                Value::String(s) => {
                    let s = s.trim();
                    if s.len() > MAX_STRING_INPUT {
                        errs.push(format!(
                            "field `{}` exceeds {MAX_STRING_INPUT} characters",
                            f.id
                        ));
                        continue;
                    }
                    if let Err(e) = check_pattern(f, s) {
                        errs.push(format!("field `{}`: {e}", f.id));
                        continue;
                    }
                    if s.starts_with('-') && !f.allow_dash {
                        errs.push(format!(
                            "field `{}` must not start with `-` (flag-injection guard)",
                            f.id
                        ));
                        continue;
                    }
                    Value::String(s.to_string())
                }
                Value::Number(n) if f.ftype == FieldType::String => {
                    // tolerate numeric hosts like 127.0.0.1 sent as number? Refuse:
                    errs.push(format!("field `{}` must be a string, got number", f.id));
                    continue;
                }
                _ => {
                    errs.push(format!("field `{}` must be a string", f.id));
                    continue;
                }
            },
            FieldType::Integer => match raw {
                Value::Number(n) => {
                    let Some(i) = n.as_i64() else {
                        errs.push(format!("field `{}` must be an integer", f.id));
                        continue;
                    };
                    if let Some(min) = f.min {
                        if i < min {
                            errs.push(format!("field `{}` must be >= {min}", f.id));
                            continue;
                        }
                    }
                    if let Some(max) = f.max {
                        if i > max {
                            errs.push(format!("field `{}` must be <= {max}", f.id));
                            continue;
                        }
                    }
                    Value::Number(serde_json::Number::from(i))
                }
                Value::String(s) => match s.trim().parse::<i64>() {
                    Ok(i) => {
                        if let Some(min) = f.min {
                            if i < min {
                                errs.push(format!("field `{}` must be >= {min}", f.id));
                                continue;
                            }
                        }
                        if let Some(max) = f.max {
                            if i > max {
                                errs.push(format!("field `{}` must be <= {max}", f.id));
                                continue;
                            }
                        }
                        Value::Number(serde_json::Number::from(i))
                    }
                    Err(_) => {
                        errs.push(format!("field `{}` must be an integer", f.id));
                        continue;
                    }
                },
                _ => {
                    errs.push(format!("field `{}` must be an integer", f.id));
                    continue;
                }
            },
            FieldType::Boolean => match raw {
                Value::Bool(b) => Value::Bool(*b),
                Value::String(s) => match s.to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" => Value::Bool(true),
                    "false" | "0" | "no" => Value::Bool(false),
                    _ => {
                        errs.push(format!("field `{}` must be a boolean", f.id));
                        continue;
                    }
                },
                _ => {
                    errs.push(format!("field `{}` must be a boolean", f.id));
                    continue;
                }
            },
            FieldType::Select => match raw {
                Value::String(s) => {
                    if f.options.iter().any(|o| &o.value == s) {
                        Value::String(s.clone())
                    } else {
                        errs.push(format!(
                            "field `{}`: `{s}` is not one of the allowed options",
                            f.id
                        ));
                        continue;
                    }
                }
                _ => {
                    errs.push(format!("field `{}` must be one of the options", f.id));
                    continue;
                }
            },
        };
        normalized.insert(f.id.clone(), value);
    }

    if !errs.is_empty() {
        return Err(CoreError::Input(errs.join("; ")));
    }
    Ok(normalized)
}

impl ParserSpec {
    fn is_passthrough_not_declared(&self) -> bool {
        matches!(self, ParserSpec::Passthrough)
    }
}
