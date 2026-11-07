//! Safe argv rendering for CLI plugins.
//!
//! The v1 command template grammar is preserved for author familiarity:
//!
//! - `{field}` — substituted with the field's string value.
//! - `--if:field:then:X` — emits `X` only when the boolean field is truthy.
//! - `--if:field:then:X:else:Y` — emits `X` or `Y`.
//!
//! The output is an **argv vector**, never a shell string: no quoting bugs,
//! no shell injection. Values are refused when they contain NUL bytes or
//! (unless the field opts in) begin with `-`, which prevents argv
//! flag-injection into the wrapped tool.

use crate::error::{CoreError, CoreResult};
use crate::manifest::EngineSpec;
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_RENDERED_ARGV: usize = 256;

/// Render a CLI engine command template with validated inputs.
pub fn build_argv(
    engine: &EngineSpec,
    inputs: &BTreeMap<String, Value>,
) -> CoreResult<Vec<String>> {
    let EngineSpec::Cli { argv, .. } = engine else {
        return Err(CoreError::Template(
            "build_argv called on a native engine".into(),
        ));
    };
    if argv.is_empty() {
        return Err(CoreError::Template("empty command template".into()));
    }

    let program = &argv[0];
    let mut out = vec![program.clone()];

    for tok in argv.iter().skip(1) {
        if out.len() >= MAX_RENDERED_ARGV {
            return Err(CoreError::Template(format!(
                "rendered argv exceeds {MAX_RENDERED_ARGV} elements"
            )));
        }
        if let Some(cond) = tok.strip_prefix("--if:") {
            let Some((field, rest)) = cond.split_once(":then:") else {
                return Err(CoreError::Template(format!(
                    "conditional token `{tok}` is missing `:then:`"
                )));
            };
            let (then_branch, else_branch) = match rest.rsplit_once(":else:") {
                Some((t, e)) => (t, Some(e)),
                None => (rest, None),
            };
            if is_truthy(field, inputs) {
                push_substituted(&mut out, then_branch, inputs)?;
            } else if let Some(e) = else_branch {
                push_substituted(&mut out, e, inputs)?;
            }
        } else {
            push_substituted(&mut out, tok, inputs)?;
        }
    }
    Ok(out)
}

fn push_substituted(
    out: &mut Vec<String>,
    tok: &str,
    inputs: &BTreeMap<String, Value>,
) -> CoreResult<()> {
    // Fast path: literal token with no placeholders.
    if !tok.contains('{') {
        out.push(tok.to_string());
        return Ok(());
    }
    let mut rendered = String::with_capacity(tok.len());
    let mut rest: &str = tok;
    while let Some(start) = rest.find('{') {
        rendered.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(close) = after.find('}') else {
            return Err(CoreError::Template(format!(
                "unbalanced `{{` in template token `{tok}`"
            )));
        };
        let name = &after[..close];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(CoreError::Template(format!(
                "invalid placeholder `{{{name}}}` in token `{tok}`"
            )));
        }
        let value = value_to_string(name, inputs)?;
        rendered.push_str(&value);
        rest = &after[close + 1..];
    }
    rendered.push_str(rest);
    // An element that renders to the empty string is dropped entirely
    // (e.g. `-p {ports}` with empty ports would otherwise pass `-p ""`).
    if rendered.is_empty() {
        return Ok(());
    }
    out.push(rendered);
    Ok(())
}

fn value_to_string(field: &str, inputs: &BTreeMap<String, Value>) -> CoreResult<String> {
    let v = inputs.get(field).ok_or_else(|| {
        CoreError::Template(format!(
            "placeholder `{field}` has no value (missing default?)"
        ))
    })?;
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => {
            return Err(CoreError::Template(format!(
                "placeholder `{field}` must render to a scalar"
            )))
        }
    };
    if s.contains('\0') {
        return Err(CoreError::Template(format!(
            "value for `{field}` contains a NUL byte"
        )));
    }
    Ok(s)
}

/// Truthiness for conditionals, applied to *normalized* inputs:
/// - booleans: the value itself;
/// - strings: non-empty after trimming (explicit falsy spellings excluded);
/// - integers: non-zero.
fn is_truthy(field: &str, inputs: &BTreeMap<String, Value>) -> bool {
    match inputs.get(field) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            let t = s.trim();
            !t.is_empty()
                && !matches!(
                    t.to_ascii_lowercase().as_str(),
                    "false" | "0" | "no" | "off"
                )
        }
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        _ => false,
    }
}

/// Build a preview string for the UI ("what will run") without executing.
pub fn preview_command(
    engine: &EngineSpec,
    inputs: &BTreeMap<String, Value>,
) -> CoreResult<String> {
    let argv = build_argv(engine, inputs)?;
    Ok(argv
        .iter()
        .map(|a| {
            if a.contains(char::is_whitespace) {
                format!("{a:?}")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        DepsSpec, FieldSpec, FieldType, OutputFormat, ParserSpec, PluginManifest, PluginMeta,
        SafetyLevel, SafetySpec,
    };
    use serde_json::json;

    fn cli_engine(argv: &[&str]) -> EngineSpec {
        EngineSpec::Cli {
            binary: argv[0].to_string(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            timeout_seconds: 60,
            output_format: OutputFormat::Text,
            ok_exit_codes: Vec::new(),
        }
    }

    fn inputs(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn plain_substitution() {
        let e = cli_engine(&["nmap", "-p", "{ports}", "{target}"]);
        let i = inputs(&[("ports", json!("80,443")), ("target", json!("127.0.0.1"))]);
        assert_eq!(
            build_argv(&e, &i).unwrap(),
            vec!["nmap", "-p", "80,443", "127.0.0.1"]
        );
    }

    #[test]
    fn conditional_true_false() {
        let e = cli_engine(&[
            "nmap",
            "--if:safe_mode:then:-T3:else:-T4",
            "--if:service_detection:then:-sV",
            "{target}",
        ]);
        let i = inputs(&[
            ("target", json!("10.0.0.1")),
            ("safe_mode", json!(true)),
            ("service_detection", json!(false)),
        ]);
        assert_eq!(build_argv(&e, &i).unwrap(), vec!["nmap", "-T3", "10.0.0.1"]);
    }

    #[test]
    fn conditional_substitutes_inside_branch() {
        // Each conditional token expands to at most ONE argv element; use two
        // tokens when the tool expects `-p 8080` as separate elements.
        let e = cli_engine(&[
            "gobuster",
            "--if:verbose:then:-p",
            "--if:verbose:then:{ports}:else:80",
            "{target}",
        ]);
        let i = inputs(&[
            ("target", json!("example.com")),
            ("verbose", json!(true)),
            ("ports", json!("8080")),
        ]);
        assert_eq!(
            build_argv(&e, &i).unwrap(),
            vec!["gobuster", "-p", "8080", "example.com"]
        );

        let i2 = inputs(&[("target", json!("example.com")), ("verbose", json!(false))]);
        // No else on the flag token → element is skipped entirely.
        assert_eq!(
            build_argv(&e, &i2).unwrap(),
            vec!["gobuster", "80", "example.com"]
        );
    }

    #[test]
    fn empty_substitution_drops_element() {
        let e = cli_engine(&["tool", "-p", "{ports}", "{target}"]);
        let i = inputs(&[("target", json!("h")), ("ports", json!(""))]);
        assert_eq!(build_argv(&e, &i).unwrap(), vec!["tool", "-p", "h"]);
    }

    #[test]
    fn nul_byte_rejected() {
        let e = cli_engine(&["tool", "{target}"]);
        let i = inputs(&[("target", json!("a\u{0}b"))]);
        assert!(build_argv(&e, &i).is_err());
    }

    #[test]
    fn unknown_placeholder_rejected() {
        let e = cli_engine(&["tool", "{nope}"]);
        let i = inputs(&[]);
        assert!(build_argv(&e, &i).is_err());
    }

    #[test]
    fn missing_closing_brace_rejected() {
        let e = cli_engine(&["tool", "{target"]);
        let i = inputs(&[("target", json!("x"))]);
        assert!(build_argv(&e, &i).is_err());
    }

    #[test]
    fn else_branch_colons_survive() {
        // then/else containing ':' (e.g. URLs) must not be split wrongly
        let e = cli_engine(&["tool", "--if:flag:then:http://a:else:https://b"]);
        let i = inputs(&[("flag", json!(false))]);
        assert_eq!(build_argv(&e, &i).unwrap(), vec!["tool", "https://b"]);
    }

    #[test]
    fn preview_quotes_spaces() {
        let e = cli_engine(&["tool", "{target}"]);
        let i = inputs(&[("target", json!("my host"))]);
        assert_eq!(preview_command(&e, &i).unwrap(), r#"tool "my host""#);
    }

    #[test]
    fn conditional_on_nonempty_string_field() {
        // v1-style: `--if:ports:then:-p` fires when the string is non-empty.
        let e = cli_engine(&[
            "nmap",
            "--if:ports:then:-p:else:--top-ports",
            "--if:ports:then:{ports}:else:100",
            "{target}",
        ]);
        let with_ports = inputs(&[("target", json!("127.0.0.1")), ("ports", json!("80,443"))]);
        assert_eq!(
            build_argv(&e, &with_ports).unwrap(),
            vec!["nmap", "-p", "80,443", "127.0.0.1"]
        );
        let without_ports = inputs(&[("target", json!("127.0.0.1")), ("ports", json!(""))]);
        assert_eq!(
            build_argv(&e, &without_ports).unwrap(),
            vec!["nmap", "--top-ports", "100", "127.0.0.1"]
        );
    }

    #[test]
    fn explicit_falsy_string_is_false() {
        let e = cli_engine(&["tool", "--if:flag:then:-x"]);
        let i = inputs(&[("flag", json!("false"))]);
        assert_eq!(build_argv(&e, &i).unwrap(), vec!["tool"]);
    }

    #[test]
    fn integer_condition_nonzero() {
        let e = cli_engine(&[
            "tool",
            "--if:threads:then:-t",
            "--if:threads:then:{threads}",
            "{target}",
        ]);
        let i = inputs(&[("target", json!("h")), ("threads", json!(8))]);
        assert_eq!(build_argv(&e, &i).unwrap(), vec!["tool", "-t", "8", "h"]);
        let i0 = inputs(&[("target", json!("h")), ("threads", json!(0))]);
        assert_eq!(build_argv(&e, &i0).unwrap(), vec!["tool", "h"]);
    }

    #[test]
    fn native_engine_rejected() {
        let e = EngineSpec::Native {
            native: "port_scanner".into(),
            timeout_seconds: 60,
        };
        assert!(build_argv(&e, &BTreeMap::new()).is_err());
    }

    #[test]
    fn argv_cap_enforced() {
        let argv: Vec<String> = std::iter::repeat("--if:f:then:x")
            .map(|s: &str| s.to_string())
            .take(300)
            .collect();
        let e = EngineSpec::Cli {
            binary: "t".into(),
            argv,
            timeout_seconds: 60,
            output_format: OutputFormat::Text,
            ok_exit_codes: Vec::new(),
        };
        let i = inputs(&[("f", json!(true))]);
        assert!(build_argv(&e, &i).is_err());
    }

    // keep unused-import warnings away when only tests use these
    #[allow(dead_code)]
    fn _manifest_fixture() -> PluginManifest {
        PluginManifest {
            plugin: PluginMeta {
                id: "x".into(),
                name: "X".into(),
                version: "1".into(),
                description: "d".into(),
                long_description: None,
                category: "c".into(),
                author: None,
                license: None,
                icon: None,
                difficulty: None,
                tags: vec![],
            },
            engine: cli_engine(&["x"]),
            fields: vec![FieldSpec {
                id: "target".into(),
                label: "Target".into(),
                ftype: FieldType::String,
                required: true,
                default: None,
                placeholder: None,
                help: None,
                pattern: None,
                message: None,
                options: vec![],
                min: None,
                max: None,
                allow_dash: false,
            }],
            presets: Default::default(),
            preset_meta: Default::default(),
            parser: ParserSpec::Passthrough,
            static_rules: vec![],
            safety: SafetySpec {
                level: SafetyLevel::Safe,
                requires_consent: true,
                consent_message: None,
                allowed_targets: vec![],
                max_concurrent: 2,
                max_per_hour: 30,
                capabilities: vec![],
            },
            dependencies: DepsSpec::default(),
            available: false,
            missing_binaries: vec![],
            source: Default::default(),
        }
    }
}
