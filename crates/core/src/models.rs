use serde::{Deserialize, Serialize};
use std::fmt;

/// Normalized finding severity, ordered from least to most severe.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How far the platform trusts a finding produced by a scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Factual observation (open port, discovered header…).
    #[default]
    Observation,
    /// Scanner suspects an issue; requires analyst confirmation.
    SuspectedIssue,
    /// Scanner validated the issue (controlled proof).
    ValidatedIssue,
}

impl FindingKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "observation" => Some(FindingKind::Observation),
            "suspected_issue" => Some(FindingKind::SuspectedIssue),
            "validated_issue" => Some(FindingKind::ValidatedIssue),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            FindingKind::Observation => "observation",
            FindingKind::SuspectedIssue => "suspected_issue",
            FindingKind::ValidatedIssue => "validated_issue",
        }
    }
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Analyst triage state for a finding (mirrors v1 lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalystStatus {
    New,
    Confirmed,
    NeedsReview,
    FalsePositive,
    AcceptedRisk,
    Fixed,
}

impl AnalystStatus {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "new" => Some(AnalystStatus::New),
            "confirmed" => Some(AnalystStatus::Confirmed),
            "needs_review" => Some(AnalystStatus::NeedsReview),
            "false_positive" => Some(AnalystStatus::FalsePositive),
            "accepted_risk" => Some(AnalystStatus::AcceptedRisk),
            "fixed" => Some(AnalystStatus::Fixed),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            AnalystStatus::New => "new",
            AnalystStatus::Confirmed => "confirmed",
            AnalystStatus::NeedsReview => "needs_review",
            AnalystStatus::FalsePositive => "false_positive",
            AnalystStatus::AcceptedRisk => "accepted_risk",
            AnalystStatus::Fixed => "fixed",
        }
    }
}

/// Task lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "queued" => Some(TaskStatus::Queued),
            "running" => Some(TaskStatus::Running),
            "completed" => Some(TaskStatus::Completed),
            "failed" => Some(TaskStatus::Failed),
            "cancelled" => Some(TaskStatus::Cancelled),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            TaskStatus::Queued => "queued",
            TaskStatus::Running => "running",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        )
    }
}

/// Granular execution phase, streamed to the UI for progress display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Queued,
    Validating,
    Running,
    Parsing,
    Reporting,
    Finished,
}

impl Phase {
    pub fn label(&self) -> &'static str {
        match self {
            Phase::Queued => "queued",
            Phase::Validating => "validating",
            Phase::Running => "running",
            Phase::Parsing => "parsing",
            Phase::Reporting => "reporting",
            Phase::Finished => "finished",
        }
    }
}

/// Maximum number of findings a single task may produce before truncation.
pub const MAX_FINDINGS_PER_TASK: usize = 5_000;

/// A normalized finding produced by a scanner (native or CLI plugin).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Finding {
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub kind: FindingKind,
    pub description: String,
    pub remediation: String,
    pub proof: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Free-form metadata object (ports, service names, matched values…).
    #[serde(default = "default_metadata")]
    pub metadata: serde_json::Value,
    // --- v3.0.0 enrichment (all optional) ---
    /// CVE identifier (e.g. "CVE-2021-44228").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    /// CVSS v3 base score (0.0..=10.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_v3: Option<f64>,
    /// CVSS v3 vector string (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    /// EPSS score (0.0..=1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss_score: Option<f64>,
    /// EPSS percentile (0.0..=1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<f64>,
    /// Whether this CVE is in CISA's Known Exploited Vulnerabilities catalog.
    #[serde(default)]
    pub cisa_kev: bool,
    /// CWE identifier (e.g. "CWE-79").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// OWASP Top 10 mapping (e.g. "A03:2021-Injection").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    /// Confidence: 'certain' (exploited) vs 'uncertain' (detected only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
}

fn default_metadata() -> serde_json::Value {
    serde_json::json!({})
}

impl Finding {
    /// Convenience constructor used by native scanners.
    pub fn new(
        title: impl Into<String>,
        category: impl Into<String>,
        severity: Severity,
        kind: FindingKind,
    ) -> Self {
        Finding {
            title: title.into(),
            category: category.into(),
            severity,
            kind,
            description: String::new(),
            remediation: String::new(),
            proof: String::new(),
            url: None,
            metadata: default_metadata(),
            cve: None,
            cvss_v3: None,
            cvss_vector: None,
            epss_score: None,
            epss_percentile: None,
            cisa_kev: false,
            cwe: None,
            owasp: None,
            confidence: None,
        }
    }
}

/// Current UTC timestamp in RFC 3339 format (used across DB and API layers).
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Shift an RFC 3339 timestamp by `secs` seconds, preserving the canonical
/// format (UTC, millisecond precision) so lexical comparison stays valid.
/// An unparseable input falls back to "now + secs" — every timestamp in the
/// system is written by `now_iso`, so this only guards against corruption.
pub fn add_seconds_iso(ts: &str, secs: i64) -> String {
    let base = chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    (base + chrono::Duration::seconds(secs)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_seconds_roundtrips() {
        let base = "2026-01-02T03:04:05.678Z";
        assert_eq!(add_seconds_iso(base, 60), "2026-01-02T03:05:05.678Z");
        assert_eq!(add_seconds_iso(base, -5), "2026-01-02T03:04:00.678Z");
        // Result stays lexically comparable with the source.
        assert!(add_seconds_iso(base, 1).as_str() > base);
    }

    #[test]
    fn add_seconds_bad_input_falls_back_to_now_plus() {
        let out = add_seconds_iso("not-a-timestamp", 300);
        // Same canonical shape as now_iso: ...T..:..:...Z with millis.
        assert!(out.ends_with('Z'));
        assert!(chrono::DateTime::parse_from_rfc3339(&out).is_ok());
    }
}
