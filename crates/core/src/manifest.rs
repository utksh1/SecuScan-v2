//! SecuScan v2 declarative plugin manifest format.
//!
//! A v2 plugin is a single TOML file. Unlike v1 (metadata.json + an arbitrary
//! `parser.py` executed inside a subprocess sandbox), the v2 format is fully
//! declarative: field schemas, command templates and output parsers are data,
//! not code. This removes the parser-sandbox attack surface entirely while
//! keeping the same expressive power for the common wrapping patterns.
//!
//! Engines come in two flavours:
//! - `cli`    — wraps an external binary. The command is an **argv template**;
//!   it is rendered to an argv vector and executed without a shell.
//! - `native` — runs an in-process Rust scanner registered under a well-known
//!   native id (see `secuscan-exec`).

use serde::Deserialize;
use std::collections::BTreeMap;

/// Top-level plugin manifest (one TOML file per plugin).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    pub plugin: PluginMeta,
    pub engine: EngineSpec,
    /// Form field definitions rendered by the UI and enforced by the backend.
    #[serde(default)]
    pub fields: Vec<FieldSpec>,
    /// Named partial-input bundles the UI can offer as one-click presets.
    #[serde(default)]
    pub presets: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// Output parser (CLI plugins only; ignored for native plugins).
    #[serde(default)]
    pub parser: ParserSpec,
    /// Regex rules evaluated against the *whole* output, independent of the
    /// line/json parser — used for heuristic markers such as `VULNERABLE`.
    #[serde(default)]
    pub static_rules: Vec<StaticRule>,
    pub safety: SafetySpec,
    #[serde(default)]
    pub dependencies: DepsSpec,

    // ---- filled in by the loader (not part of the file) ----
    #[serde(skip)]
    pub available: bool,
    #[serde(skip)]
    pub missing_binaries: Vec<String>,
    #[serde(skip)]
    pub source: std::path::PathBuf,
}

/// `[plugin]` identity block.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginMeta {
    /// Stable identifier, `^[a-z0-9][a-z0-9-]*$`.
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub long_description: Option<String>,
    /// Catalog category: network / web / recon / dns / exploitation …
    pub category: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    /// Icon key rendered by the frontend (lucide icon name).
    #[serde(default)]
    pub icon: Option<String>,
    /// Learning metadata: beginner / intermediate / advanced.
    #[serde(default)]
    pub difficulty: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `[engine]` — how the plugin executes.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EngineSpec {
    Cli {
        /// Binary name (argv[0]); must match the first template element.
        binary: String,
        /// Argv template. Supports `{field}` substitution and
        /// `--if:field:then:X` / `--if:field:then:X:else:Y` conditionals.
        argv: Vec<String>,
        #[serde(default = "default_timeout_seconds")]
        timeout_seconds: u64,
        /// `text` (default) or `json_lines`.
        #[serde(default)]
        output_format: OutputFormat,
    },
    Native {
        /// Well-known native scanner id, e.g. `port_scanner`.
        native: String,
        #[serde(default = "default_timeout_seconds")]
        timeout_seconds: u64,
    },
}

fn default_timeout_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Text,
    JsonLines,
}

/// `[[fields]]` — a single typed input field.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub ftype: FieldType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub help: Option<String>,
    /// Validation regex applied to string/text values.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Human message shown when `pattern` fails.
    #[serde(default)]
    pub message: Option<String>,
    /// Options for `select` fields.
    #[serde(default)]
    pub options: Vec<FieldOption>,
    /// Inclusive integer bounds.
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
    /// Allow values that begin with `-` (needed by a few tools; such values
    /// are refused by default to prevent argv flag injection).
    #[serde(default)]
    pub allow_dash: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Text,
    Integer,
    Boolean,
    Select,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldOption {
    pub value: String,
    pub label: String,
}

/// `[safety]` — policy envelope enforced before and during execution.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetySpec {
    /// `safe` | `intrusive` | `exploit`.
    pub level: SafetyLevel,
    #[serde(default = "default_true")]
    pub requires_consent: bool,
    #[serde(default)]
    pub consent_message: Option<String>,
    /// Glob/CIDR patterns restricting the `target` field
    /// (empty = no plugin-level restriction).
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// Sliding-window hourly cap; 0 = unlimited.
    #[serde(default = "default_max_per_hour")]
    pub max_per_hour: usize,
    /// Capability tokens this plugin needs (`network`, `docker`, `cloud`…);
    /// denied capabilities block task creation.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_max_concurrent() -> usize {
    2
}

fn default_max_per_hour() -> usize {
    30
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyLevel {
    Safe,
    Intrusive,
    Exploit,
}

impl SafetyLevel {
    pub fn label(&self) -> &'static str {
        match self {
            SafetyLevel::Safe => "safe",
            SafetyLevel::Intrusive => "intrusive",
            SafetyLevel::Exploit => "exploit",
        }
    }
}

/// `[dependencies]` — external requirements, checked for availability.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepsSpec {
    #[serde(default)]
    pub binaries: Vec<String>,
}

/// `[parser]` — declarative output normalization.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParserSpec {
    /// Capture output but produce no findings.
    #[default]
    Passthrough,
    /// One finding per matching output line.
    LineRegex {
        /// Regex with named capture groups.
        pattern: String,
        finding: LineFindingTemplate,
        /// Elevate severity when a captured group matches one of `values`.
        #[serde(default)]
        severity_rules: Vec<SeverityRule>,
        /// Capture group names copied verbatim into finding metadata.
        #[serde(default)]
        metadata_fields: Vec<String>,
        /// Lines matching any of these regexes are discarded before the
        /// main pattern runs — tool diagnostics and run metadata
        /// (`+ ERROR: …`, `+ Target IP: …`) are not security findings.
        #[serde(default)]
        skip_patterns: Vec<String>,
    },
    /// One finding per JSON object line (nuclei-style JSONL output).
    JsonLines {
        finding: JsonFindingTemplate,
        /// Maps the tool's own severity strings to SecuScan severities.
        #[serde(default)]
        severity_map: BTreeMap<String, String>,
    },
}

/// Template for line-regex findings; `{group}` placeholders are substituted
/// with the corresponding named capture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineFindingTemplate {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_severity() -> String {
    "info".to_string()
}

/// Template for JSONL findings; each `*_field` is a dot-path into the object.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonFindingTemplate {
    /// Required dot-path, e.g. `info.name`.
    pub title_field: String,
    #[serde(default)]
    pub description_field: Option<String>,
    #[serde(default)]
    pub severity_field: Option<String>,
    #[serde(default)]
    pub url_field: Option<String>,
    #[serde(default)]
    pub proof_field: Option<String>,
    /// Alternative to `proof_field`: several dot-paths joined with " | "
    /// (first non-empty wins per position; skipped when absent).
    #[serde(default)]
    pub proof_fields: Vec<String>,
    #[serde(default)]
    pub category: Option<String>,
    /// Dot-path whose (comma-separated) value is matched against
    /// `category_map` keys to derive a per-finding category; falls back
    /// to the static `category`. Example: `info.tags` for nuclei.
    #[serde(default)]
    pub category_field: Option<String>,
    /// Tag -> category mapping applied to the comma-separated value at
    /// `category_field` (first tag with an exact, case-insensitive key
    /// match wins). Example: `sqli = "SQL Injection"`.
    #[serde(default)]
    pub category_map: std::collections::BTreeMap<String, String>,
    /// Dot-path to a CVE id or an array of CVE ids (first is used).
    #[serde(default)]
    pub cve_field: Option<String>,
    /// Dot-path to a numeric CVSS v3 base score.
    #[serde(default)]
    pub cvss_field: Option<String>,
    /// Dot-path to a CVSS v3 vector string.
    #[serde(default)]
    pub cvss_vector_field: Option<String>,
    /// Dot-paths copied verbatim into finding metadata under their last
    /// path segment (e.g. `info.tags` -> `metadata.tags`).
    #[serde(default)]
    pub metadata_fields: Vec<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
}

/// `[[static_rules]]` — whole-output regex heuristics.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticRule {
    pub pattern: String,
    pub title: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityRule {
    /// Capture group name tested against `values`.
    pub field: String,
    pub values: Vec<String>,
    pub severity: String,
}
