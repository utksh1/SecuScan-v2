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
