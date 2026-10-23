//! Row types mapped from SQL. Domain enums come from `secuscan-core`.

use secuscan_core::models::{AnalystStatus, FindingKind, Severity, TaskStatus};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct WorkspaceRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TargetRow {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub kind: String,
    pub description: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub prefix: String,
    pub key_hash: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TaskRow {
    pub id: String,
    pub user_id: String,
    pub plugin_id: String,
    pub plugin_name: String,
    pub target: Option<String>,
    pub status: String,
    pub inputs_json: String,
    pub options_json: String,
    pub exit_code: Option<i64>,
    pub error: Option<String>,
    pub stats_json: Option<String>,
    /// Raw output is intentionally NOT selected in list queries.
    pub output: Option<String>,
    pub output_truncated: bool,
    pub workflow_run_id: Option<String>,
    /// Owning workspace; NULL = the synthetic "Personal" scope.
    pub workspace_id: Option<String>,
    /// Schedule that launched this task (NULL for manual/workflow starts).
    pub schedule_id: Option<String>,
    /// Robot run that launched this task (v2.6.0; NULL for non-robot tasks).
    pub robot_run_id: Option<String>,
    /// Auth profile attached to this task (v2.6.0; NULL = unauthenticated).
    pub auth_profile_id: Option<String>,
    /// v3.0.0 — OOB callback marker (appended to payloads; correlates blind callbacks).
    pub oob_marker: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

impl TaskRow {
    pub fn status(&self) -> TaskStatus {
        TaskStatus::parse(&self.status).unwrap_or(TaskStatus::Failed)
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TaskEventRow {
    pub id: i64,
    pub task_id: String,
    pub ts: String,
    pub level: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FindingRow {
    pub id: String,
    pub task_id: String,
    pub plugin_id: String,
    pub severity: String,
    pub kind: String,
    pub analyst_status: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub proof: String,
    pub url: Option<String>,
    pub metadata_json: String,
    pub created_at: String,
    // v3.0.0 — dedup + enrichment (nullable for backward compat)
    pub group_id: Option<String>,
    pub cve: Option<String>,
    pub cvss_v3: Option<f64>,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub cisa_kev: i64,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub confidence: Option<String>,
}

impl FindingRow {
    pub fn severity(&self) -> Severity {
        Severity::parse(&self.severity).unwrap_or(Severity::Info)
    }

    pub fn kind(&self) -> FindingKind {
        FindingKind::parse(&self.kind).unwrap_or(FindingKind::Observation)
    }

    pub fn analyst_status(&self) -> AnalystStatus {
        AnalystStatus::parse(&self.analyst_status).unwrap_or(AnalystStatus::New)
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct WorkflowRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps_json: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct WorkflowRunRow {
    pub id: String,
    pub workflow_id: String,
    pub status: String,
    pub task_ids_json: String,
    pub error: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PolicyAuditRow {
    pub id: i64,
    pub ts: String,
    pub user_id: Option<String>,
    pub plugin_id: String,
    pub target: String,
    pub verdict: String,
    pub layer: String,
    pub pattern: String,
    pub reason: String,
}

/// Dashboard counters.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DashboardSummary {
    pub tasks_total: i64,
    pub tasks_running: i64,
    pub tasks_queued: i64,
    pub tasks_completed: i64,
    pub tasks_failed: i64,
    pub tasks_cancelled: i64,
    pub findings_critical: i64,
    pub findings_high: i64,
    pub findings_medium: i64,
    pub findings_low: i64,
    pub findings_info: i64,
    pub findings_new: i64,
    pub users_total: i64,
    pub workflows_total: i64,
}

/// Async report generation job (see migration 0003 for the model rationale).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ReportJobRow {
    pub id: String,
    pub task_id: String,
    pub user_id: String,
    pub format: String,
    /// Minimum-severity threshold; NULL = include everything.
    pub severity_filter: Option<String>,
    /// `waiting` | `in_progress` | `finished` | `failed`.
    pub status: String,
    pub error: Option<String>,
    pub file_path: Option<String>,
    pub file_bytes: Option<i64>,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub webhook_attempts: i64,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

impl ReportJobRow {
    /// True while the job may still transition states.
    pub fn is_active(&self) -> bool {
        self.status == "waiting" || self.status == "in_progress"
    }
}

/// Recurring scan schedule (see migration 0004 for the model rationale).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ScheduleRow {
    pub id: String,
    pub user_id: String,
    pub workspace_id: Option<String>,
    pub name: String,
    pub plugin_id: String,
    pub inputs_json: String,
    pub preset: Option<String>,
    /// Denormalized display target derived from the normalized inputs.
    pub target: Option<String>,
    pub interval_seconds: i64,
    pub enabled: bool,
    pub next_run_at: String,
    pub last_run_at: Option<String>,
    pub last_task_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: Option<String>,
}

// --- v2.6.0 models ---------------------------------------------------------

/// Pentest Robot: a DAG of Tool/Filter/Extractor/Reducer nodes.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RobotRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub nodes_json: String,
    pub edges_json: String,
    pub source: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RobotRunRow {
    pub id: String,
    pub robot_id: String,
    pub workspace_id: Option<String>,
    pub status: String,
    pub state_json: String,
    pub targets_json: String,
    pub error: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub finished_at: Option<String>,
}

/// Aggregated asset in the Attack Surface inventory.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AttackSurfaceAssetRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub url: Option<String>,
    pub asset_key: String,
    pub metadata_json: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub created_at: String,
}

/// Reusable authentication profile for web scans.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuthProfileRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub name: String,
    pub method: String,
    pub config_json: String,
    pub notes: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

/// Workspace membership (owner / editor / viewer).
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct WorkspaceMemberRow {
    pub workspace_id: String,
    pub user_id: String,
    pub role: String,
    pub added_at: String,
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FindingCommentRow {
    pub id: String,
    pub finding_id: String,
    pub author_id: String,
    pub body: String,
    pub kind: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MentionRow {
    pub id: String,
    pub comment_id: String,
    pub mentioned_user_id: String,
    pub finding_id: String,
    pub workspace_id: Option<String>,
    pub read_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct BrandingRow {
    pub id: i64,
    pub org_name: String,
    pub logo_png: Option<Vec<u8>>,
    pub primary_color: String,
    pub accent_color: String,
    pub footer_text: String,
    pub updated_at: String,
    pub updated_by: Option<String>,
}

// --- v3.0.0 models ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OobHandlerRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub user_id: String,
    pub name: String,
    pub kind: String,
    pub config_json: String,
    pub secret: String,
    pub expires_at: String,
    pub created_at: String,
    pub hit_count: i64,
    pub last_hit_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OobHitRow {
    pub id: String,
    pub handler_id: String,
    pub task_id: Option<String>,
    pub payload_json: String,
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FindingGroupRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub plugin_id: String,
    pub title_norm: String,
    pub target_fingerprint: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FpMemoryRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub plugin_id: String,
    pub title_norm: String,
    pub target_fingerprint: String,
    pub decided_by: String,
    pub decided_at: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct NotificationRuleRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub name: String,
    pub rules_json: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct NotificationLogRow {
    pub id: String,
    pub rule_id: String,
    pub task_id: Option<String>,
    pub finding_id: Option<String>,
    pub channel: String,
    pub status: String,
    pub http_status: Option<i64>,
    pub error: Option<String>,
    pub payload_json: String,
    pub sent_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ScanGroupRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub name: String,
    pub description: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct WordlistRow {
    pub id: String,
    pub workspace_id: Option<String>,
    pub name: String,
    pub source: String,
    pub file_path: String,
    pub word_count: i64,
    pub size_bytes: i64,
    pub kind: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FindingTemplateRow {
    pub id: String,
    pub scope: String,
    pub workspace_id: Option<String>,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AssetImportRow {
    pub id: String,
    pub workspace_id: String,
    pub source: String,
    pub summary: String,
    pub created_count: i64,
    pub skipped_count: i64,
    pub created_by: String,
    pub created_at: String,
}
