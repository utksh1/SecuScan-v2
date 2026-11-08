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

/// Named schedule frequencies (issue #25): compute the next run anchor for a
/// named frequency + 'HH:MM' wall-clock anchor in an IANA timezone, strictly
/// after `after_iso`. Monthly/quarterly clamp to the month's last day
/// (Jan 31 -> Feb 28). Returns None for unknown frequency/timezone.
pub fn compute_next_named_anchor(
    frequency: &str,
    anchor_time: &str,
    tz: &str,
    after_iso: &str,
) -> Option<String> {
    use chrono::{Duration, TimeZone, Utc};

    let (hh, mm) = {
        let mut it = anchor_time.split(':');
        let hh: u32 = it.next()?.parse().ok()?;
        let mm: u32 = it.next()?.parse().ok()?;
        if hh > 23 || mm > 59 {
            return None;
        }
        (hh, mm)
    };
    let tz_parsed: chrono_tz::Tz = tz.parse().ok()?;
    let after = chrono::DateTime::parse_from_rfc3339(after_iso).ok()?;
    let after_local = after.with_timezone(&tz_parsed);

    // First candidate: today at anchor time (local).
    let cand_date = after_local.date_naive();
    let mut candidate_local = tz_parsed
        .from_local_datetime(
            &cand_date.and_hms_opt(hh, mm, 0).expect("valid hms"),
        )
        .latest()?;

    let step_months = match frequency {
        "hourly" => {
            // anchor_time minute-of-hour; candidate may be within the hour.
            let next = if candidate_local > after_local {
                candidate_local
            } else {
                candidate_local + Duration::hours(1)
            };
            return Some(next.with_timezone(&Utc).to_rfc3339_opts(
                chrono::SecondsFormat::Millis,
                true,
            ));
        }
        "daily" => 0,
        "weekly" => 0,
        "monthly" => 1,
        "quarterly" => 3,
        _ => return None,
    };

    if frequency == "daily" {
        if candidate_local <= after_local {
            candidate_local += Duration::days(1);
        }
        return Some(candidate_local.with_timezone(&Utc).to_rfc3339_opts(
            chrono::SecondsFormat::Millis,
            true,
        ));
    }

    // weekly / monthly / quarterly: iterate candidates until strictly after.
    let mut guard = 0;
    while candidate_local <= after_local {
        guard += 1;
        if guard > 48 {
            return None;
        }
        let months = if frequency == "weekly" { 0 } else { step_months };
        if frequency == "weekly" {
            candidate_local += Duration::days(7);
        } else {
            // Same day-of-month, clamped to month end.
            let mut month = candidate_local.date_naive();
            for _ in 0..months {
                month = next_month_clamped(month);
            }
            candidate_local = tz_parsed
                .from_local_datetime(
                    &month.and_hms_opt(hh, mm, 0).expect("valid hms"),
                )
                .latest()?;
        }
    }
    Some(
        candidate_local
            .with_timezone(&Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
}

/// Next month's same day, clamped to the month's last day (Jan 31 -> Feb 28).
fn next_month_clamped(d: chrono::NaiveDate) -> chrono::NaiveDate {
    use chrono::Datelike;
    let (y, m) = if d.month() == 12 {
        (d.year() + 1, 1)
    } else {
        (d.year(), d.month() + 1)
    };
    let day = d.day().min(days_in_month(y, m));
    chrono::NaiveDate::from_ymd_opt(y, m, day).expect("clamped day is always valid")
}

fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => unreachable!("month 1-12"),
    }
}

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

    #[test]
    fn daily_anchor_skips_to_tomorrow_when_past() {
        // 2026-11-08T10:00Z; anchor 09:00 UTC -> next run tomorrow 09:00Z.
        let next = compute_next_named_anchor("daily", "09:00", "UTC", "2026-11-08T10:00:00.000Z")
            .unwrap();
        assert!(next.starts_with("2026-11-09T09:00:00"));
    }

    #[test]
    fn daily_anchor_later_today_when_not_past() {
        let next = compute_next_named_anchor("daily", "23:00", "UTC", "2026-11-08T10:00:00.000Z")
            .unwrap();
        assert!(next.starts_with("2026-11-08T23:00:00"));
    }

    #[test]
    fn monthly_clamps_to_month_end() {
        // Anchor on the 31st; November has 30 days.
        let next = compute_next_named_anchor("monthly", "08:00", "UTC", "2026-10-31T09:00:00.000Z")
            .unwrap();
        assert!(next.starts_with("2026-11-30T08:00:00"), "{next}");
        // Day-drift semantics: after a clamp (Oct 31 -> Nov 30) the original
        // 31 is not recoverable from the previous run time, so the anchor
        // becomes the 30th going forward. Documented behavior.
        let next2 = compute_next_named_anchor("monthly", "08:00", "UTC", "2026-11-30T09:00:00.000Z")
            .unwrap();
        assert!(next2.starts_with("2026-12-30T08:00:00"), "{next2}");
    }

    #[test]
    fn timezone_offsets_apply() {
        // 08:00 in Europe/Berlin (UTC+1 in November) = 07:00Z.
        let next = compute_next_named_anchor("daily", "08:00", "Europe/Berlin", "2026-11-08T09:00:00.000Z")
            .unwrap();
        assert!(next.starts_with("2026-11-09T07:00:00"), "{next}");
    }

    #[test]
    fn unknown_frequency_or_tz_is_none() {
        assert!(compute_next_named_anchor("yearly", "08:00", "UTC", "2026-11-08T09:00:00.000Z").is_none());
        assert!(compute_next_named_anchor("daily", "08:00", "Mars/Olympus", "2026-11-08T09:00:00.000Z").is_none());
        assert!(compute_next_named_anchor("daily", "99:00", "UTC", "2026-11-08T09:00:00.000Z").is_none());
    }
}
