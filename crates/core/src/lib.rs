//! SecuScan v2 — core domain crate.
//!
//! This crate is intentionally free of async runtime and framework concerns.
//! It owns:
//! - the normalized domain models ([`models`]) shared by every other crate,
//! - the declarative plugin manifest format and its loader/validator
//!   ([`manifest`], [`loader`], [`validate`]),
//! - the safe command builder that turns a manifest command template plus
//!   validated user inputs into an **argv vector** (never a shell string),
//! - the declarative parser engine that turns raw tool output into normalized
//!   findings without executing any plugin-supplied code,
//! - the target/safety policy engine ([`policy`]) used to decide whether a
//!   scan may run against a given host.

pub mod error;
pub mod loader;
pub mod manifest;
pub mod models;
pub mod parser_engine;
pub mod policy;
pub mod template;
pub mod validate;

pub use error::{CoreError, CoreResult};
pub use loader::{LoadIssue, PluginRegistry};
pub use manifest::{
    DepsSpec, EngineSpec, FieldOption, FieldSpec, FieldType, JsonFindingTemplate, LineFindingTemplate,
    ParserSpec, PluginManifest, PluginMeta, SafetyLevel, SafetySpec, SeverityRule, StaticRule,
};
pub use models::{AnalystStatus, Finding, FindingKind, Phase, Severity, TaskStatus};
pub use parser_engine::parse_output;
pub use policy::{NetworkPolicy, TargetVerdict};
pub use template::build_argv;
pub use validate::{normalize_inputs, validate_manifest};
