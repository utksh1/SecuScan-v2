//! Task events, settings, policy audit log, plugin states, dashboard.

use crate::models::{DashboardSummary, PolicyAuditRow, TaskEventRow};
use crate::{now, DbResult};
use secuscan_core::policy::PolicyAuditEntry;
use sqlx::SqlitePool;

// --- task events -----------------------------------------------------------

/// An event to persist: `level` is the event tag, `payload` the full JSON.
pub struct NewTaskEvent<'a> {
    pub task_id: &'a str,
    pub ts: &'a str,
    pub level: &'a str,
    pub payload_json: &'a str,
}

pub async fn insert_events(pool: &SqlitePool, events: &[NewTaskEvent<'_>]) -> DbResult<()> {
    let mut tx = pool.begin().await?;
    for e in events {
        sqlx::query(
            "INSERT INTO task_events (task_id, ts, level, payload_json) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(e.task_id)
        .bind(e.ts)
        .bind(e.level)
        .bind(e.payload_json)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn list_events(
    pool: &SqlitePool,
    task_id: &str,
    after_id: i64,
    limit: i64,
) -> DbResult<Vec<TaskEventRow>> {
    sqlx::query_as::<_, TaskEventRow>(
        "SELECT * FROM task_events WHERE task_id = ?1 AND id > ?2 ORDER BY id ASC LIMIT ?3",
    )
    .bind(task_id)
    .bind(after_id)
    .bind(limit.clamp(1, 2000))
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn count_events(pool: &SqlitePool, task_id: &str) -> DbResult<i64> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM task_events WHERE task_id = ?1")
        .bind(task_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

// --- settings (typed accessors) ---------------------------------------------

pub async fn get_setting_json(pool: &SqlitePool, key: &str) -> DbResult<Option<serde_json::Value>> {
    let row: Option<String> = sqlx::query_scalar("SELECT value_json FROM settings WHERE key = ?1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    match row {
        Some(s) => Ok(serde_json::from_str(&s).ok()),
        None => Ok(None),
    }
}

pub async fn set_setting_json(
    pool: &SqlitePool,
    key: &str,
    value: &serde_json::Value,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO settings (key, value_json) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
    )
    .bind(key)
    .bind(value.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Stored network policy: `{"allow": [...], "deny": [...]}`.
pub async fn get_network_policy(
    pool: &SqlitePool,
) -> DbResult<secuscan_core::policy::NetworkPolicy> {
    let v = get_setting_json(pool, "network_policy").await?;
    Ok(
        serde_json::from_value(v.unwrap_or(serde_json::json!({"allow": [], "deny": []})))
            .unwrap_or_default(),
    )
}

pub async fn set_network_policy(
    pool: &SqlitePool,
    policy: &secuscan_core::policy::NetworkPolicy,
) -> DbResult<()> {
    set_setting_json(
        pool,
        "network_policy",
        &serde_json::json!({"allow": policy.allow, "deny": policy.deny}),
    )
    .await
}

/// Global consent requirement (default true).
pub async fn get_require_consent(pool: &SqlitePool) -> DbResult<bool> {
    let v = get_setting_json(pool, "require_consent").await?;
    Ok(v.and_then(|v| v.as_bool()).unwrap_or(true))
}

pub async fn set_require_consent(pool: &SqlitePool, require: bool) -> DbResult<()> {
    set_setting_json(pool, "require_consent", &serde_json::json!(require)).await
}

// --- policy audit log --------------------------------------------------------

pub async fn insert_policy_audit(pool: &SqlitePool, entry: &PolicyAuditEntry) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO policy_audit (ts, user_id, plugin_id, target, verdict, layer, pattern, reason) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&entry.ts)
    .bind(&entry.user)
    .bind(&entry.plugin_id)
    .bind(&entry.target)
    .bind(&entry.verdict)
    .bind(&entry.layer)
    .bind(&entry.pattern)
    .bind(&entry.reason)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_policy_audit(pool: &SqlitePool, limit: i64) -> DbResult<Vec<PolicyAuditRow>> {
    sqlx::query_as::<_, PolicyAuditRow>("SELECT * FROM policy_audit ORDER BY id DESC LIMIT ?1")
        .bind(limit.clamp(1, 500))
        .fetch_all(pool)
        .await
        .map_err(Into::into)
}

// --- plugin states -----------------------------------------------------------

pub async fn enabled_map(pool: &SqlitePool) -> DbResult<std::collections::HashMap<String, bool>> {
    let rows: Vec<(String, bool)> = sqlx::query_as("SELECT plugin_id, enabled FROM plugin_states")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().collect())
}

pub async fn set_plugin_enabled(pool: &SqlitePool, plugin_id: &str, enabled: bool) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO plugin_states (plugin_id, enabled) VALUES (?1, ?2) \
         ON CONFLICT(plugin_id) DO UPDATE SET enabled = excluded.enabled",
    )
    .bind(plugin_id)
    .bind(enabled)
    .execute(pool)
    .await?;
    Ok(())
}

// --- dashboard ----------------------------------------------------------------

/// `user_id` scopes task/finding counters to one user (None = global).
/// `workspace` additionally scopes the counters to one workspace
/// (`WorkspaceScope::All` = no workspace filtering).
///
/// When both a user and a workspace id are present the user binds to `?1`
/// and the workspace to `?2`; with no user the workspace binds to `?1`.
/// The fragments below are chosen accordingly.
pub async fn dashboard_summary(
    pool: &SqlitePool,
    user_id: Option<&str>,
    workspace: &super::workspaces::WorkspaceScope,
) -> DbResult<DashboardSummary> {
    let ws_id: Option<&str> = match workspace {
        super::workspaces::WorkspaceScope::Id(id) => Some(id.as_str()),
        _ => None,
    };
    // (tasks-table fragment, findings-join fragment)
    let (ws_tasks, ws_join) = match (workspace, user_id.is_some()) {
        (super::workspaces::WorkspaceScope::All, _) => ("", ""),
        (super::workspaces::WorkspaceScope::Id(_), true) => {
            (" AND workspace_id = ?2", " AND t.workspace_id = ?2")
        }
        (super::workspaces::WorkspaceScope::Id(_), false) => {
            (" AND workspace_id = ?1", " AND t.workspace_id = ?1")
        }
        (super::workspaces::WorkspaceScope::Personal, _) => {
            (" AND workspace_id IS NULL", " AND t.workspace_id IS NULL")
        }
    };

    // --- task-table counters (workspace column is unaliased) -------------
    let status_sql = match user_id {
        Some(_) => format!(
            "SELECT status, COUNT(*) FROM tasks WHERE user_id = ?1{ws_tasks} GROUP BY status"
        ),
        None => format!("SELECT status, COUNT(*) FROM tasks WHERE 1=1{ws_tasks} GROUP BY status"),
    };
    let counts: Vec<(String, i64)> = match (user_id, ws_id) {
        (Some(u), Some(w)) => sqlx::query_as(&status_sql).bind(u).bind(w),
        (Some(u), None) => sqlx::query_as(&status_sql).bind(u),
        (None, Some(w)) => sqlx::query_as(&status_sql).bind(w),
        (None, None) => sqlx::query_as(&status_sql),
    }
    .fetch_all(pool)
    .await?;

    let total_sql = match user_id {
        Some(_) => format!("SELECT COUNT(*) FROM tasks WHERE user_id = ?1{ws_tasks}"),
        None => format!("SELECT COUNT(*) FROM tasks WHERE 1=1{ws_tasks}"),
    };
    let tasks_total: i64 = match (user_id, ws_id) {
        (Some(u), Some(w)) => sqlx::query_scalar(&total_sql).bind(u).bind(w),
        (Some(u), None) => sqlx::query_scalar(&total_sql).bind(u),
        (None, Some(w)) => sqlx::query_scalar(&total_sql).bind(w),
        (None, None) => sqlx::query_scalar(&total_sql),
    }
    .fetch_one(pool)
    .await?;

    // --- findings counters (join tasks for user + workspace scoping) -----
    let sev_sql = match user_id {
        Some(_) => format!(
            "SELECT f.severity, COUNT(*) FROM findings f \
             JOIN tasks t ON t.id = f.task_id WHERE t.user_id = ?1{ws_join} GROUP BY f.severity"
        ),
        None => format!(
            "SELECT f.severity, COUNT(*) FROM findings f \
             JOIN tasks t ON t.id = f.task_id WHERE 1=1{ws_join} GROUP BY f.severity"
        ),
    };
    let sev: Vec<(String, i64)> = match (user_id, ws_id) {
        (Some(u), Some(w)) => sqlx::query_as(&sev_sql).bind(u).bind(w),
        (Some(u), None) => sqlx::query_as(&sev_sql).bind(u),
        (None, Some(w)) => sqlx::query_as(&sev_sql).bind(w),
        (None, None) => sqlx::query_as(&sev_sql),
    }
    .fetch_all(pool)
    .await?;

    let new_sql = match user_id {
        Some(_) => format!(
            "SELECT COUNT(*) FROM findings f JOIN tasks t ON t.id = f.task_id \
             WHERE f.analyst_status = 'new' AND t.user_id = ?1{ws_join}"
        ),
        None => format!(
            "SELECT COUNT(*) FROM findings f JOIN tasks t ON t.id = f.task_id \
             WHERE f.analyst_status = 'new'{ws_join}"
        ),
    };
    let new_findings: i64 = match (user_id, ws_id) {
        (Some(u), Some(w)) => sqlx::query_scalar(&new_sql).bind(u).bind(w),
        (Some(u), None) => sqlx::query_scalar(&new_sql).bind(u),
        (None, Some(w)) => sqlx::query_scalar(&new_sql).bind(w),
        (None, None) => sqlx::query_scalar(&new_sql),
    }
    .fetch_one(pool)
    .await?;

    let users_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    let workflows_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workflows")
        .fetch_one(pool)
        .await?;

    let mut s = DashboardSummary {
        tasks_total,
        users_total,
        workflows_total,
        findings_new: new_findings,
        ..Default::default()
    };
    for (status, n) in counts {
        match status.as_str() {
            "running" => s.tasks_running = n,
            "queued" => s.tasks_queued = n,
            "completed" => s.tasks_completed = n,
            "failed" => s.tasks_failed = n,
            "cancelled" => s.tasks_cancelled = n,
            _ => {}
        }
    }
    for (severity, n) in sev {
        match severity.as_str() {
            "critical" => s.findings_critical = n,
            "high" => s.findings_high = n,
            "medium" => s.findings_medium = n,
            "low" => s.findings_low = n,
            _ => s.findings_info = n,
        }
    }
    Ok(s)
}

/// Housekeeping: drop expired refresh tokens.
pub async fn cleanup_expired_tokens(pool: &SqlitePool) -> DbResult<u64> {
    super::users::delete_expired_refresh_tokens(pool).await
}

/// Current timestamp (RFC 3339).
pub fn now_ts() -> String {
    now()
}
