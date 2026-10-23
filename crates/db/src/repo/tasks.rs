//! Tasks: lifecycle persistence.

use super::workspaces::WorkspaceScope;
use crate::models::TaskRow;
use crate::{new_id, now, DbError, DbResult};
use secuscan_core::models::TaskStatus;
use sqlx::SqlitePool;

/// Payload for creating a task row (status starts `queued`).
pub struct NewTask<'a> {
    pub user_id: &'a str,
    pub plugin_id: &'a str,
    pub plugin_name: &'a str,
    pub target: Option<&'a str>,
    pub inputs_json: &'a str,
    pub options_json: &'a str,
    pub workflow_run_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
    /// Recurring schedule that auto-launched this task, if any.
    pub schedule_id: Option<&'a str>,
}

pub async fn create(pool: &SqlitePool, t: NewTask<'_>) -> DbResult<TaskRow> {
    let row = TaskRow {
        id: new_id(),
        user_id: t.user_id.to_string(),
        plugin_id: t.plugin_id.to_string(),
        plugin_name: t.plugin_name.to_string(),
        target: t.target.map(str::to_string),
        status: TaskStatus::Queued.label().to_string(),
        inputs_json: t.inputs_json.to_string(),
        options_json: t.options_json.to_string(),
        exit_code: None,
        error: None,
        stats_json: None,
        output: None,
        output_truncated: false,
        workflow_run_id: t.workflow_run_id.map(str::to_string),
        workspace_id: t.workspace_id.map(str::to_string),
        schedule_id: t.schedule_id.map(str::to_string),
        robot_run_id: None,
        auth_profile_id: None,
        oob_marker: None,
        sniper_run_id: None,
        created_at: now(),
        started_at: None,
        finished_at: None,
    };
    sqlx::query(
        "INSERT INTO tasks (id, user_id, plugin_id, plugin_name, target, status, inputs_json, \
         options_json, output_truncated, workflow_run_id, workspace_id, schedule_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12)",
    )
    .bind(&row.id)
    .bind(&row.user_id)
    .bind(&row.plugin_id)
    .bind(&row.plugin_name)
    .bind(&row.target)
    .bind(&row.status)
    .bind(&row.inputs_json)
    .bind(&row.options_json)
    .bind(&row.workflow_run_id)
    .bind(&row.workspace_id)
    .bind(&row.schedule_id)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn get(pool: &SqlitePool, id: &str) -> DbResult<TaskRow> {
    sqlx::query_as::<_, TaskRow>("SELECT * FROM tasks WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("task {id}")))
}

/// Full task row including raw output (used by detail endpoint).
pub async fn get_with_output(pool: &SqlitePool, id: &str) -> DbResult<TaskRow> {
    get(pool, id).await
}

#[derive(Debug, Default)]
pub struct TaskListFilters {
    pub user_id: Option<String>,
    pub status: Option<String>,
    pub plugin_id: Option<String>,
    pub workflow_run_id: Option<String>,
    pub search: Option<String>,
    pub workspace: WorkspaceScope,
    pub limit: i64,
    pub offset: i64,
}

/// List tasks without the heavy `output` column.
pub async fn list(pool: &SqlitePool, f: &TaskListFilters) -> DbResult<Vec<TaskRow>> {
    let limit = if f.limit <= 0 { 50 } else { f.limit.min(500) };
    let offset = f.offset.max(0);
    let mut n = 5usize; // ?1..?5 are bound above
    let (ws_clause, ws_bind) = f.workspace.clause("workspace_id", &mut n);
    n += 1;
    let p_lim = format!("?{n}");
    n += 1;
    let p_off = format!("?{n}");
    let sql = format!(
        "SELECT id, user_id, plugin_id, plugin_name, target, status, inputs_json, options_json, \
         exit_code, error, stats_json, NULL AS output, output_truncated, workflow_run_id, \
         workspace_id, schedule_id, robot_run_id, auth_profile_id, oob_marker, sniper_run_id, created_at, started_at, finished_at \
         FROM tasks \
         WHERE (?1 IS NULL OR user_id = ?1) \
           AND (?2 IS NULL OR status = ?2) \
           AND (?3 IS NULL OR plugin_id = ?3) \
           AND (?4 IS NULL OR workflow_run_id = ?4) \
           AND (?5 IS NULL OR target LIKE '%' || ?5 || '%' OR plugin_name LIKE '%' || ?5 || '%') \
           {ws_clause} \
         ORDER BY created_at DESC LIMIT {p_lim} OFFSET {p_off}"
    );
    let mut q = sqlx::query_as::<_, TaskRow>(&sql)
        .bind(&f.user_id)
        .bind(&f.status)
        .bind(&f.plugin_id)
        .bind(&f.workflow_run_id)
        .bind(&f.search);
    // Bind order must match placeholder order: the workspace clause comes
    // before LIMIT/OFFSET in the SQL text.
    if let Some(id) = ws_bind {
        q = q.bind(id);
    }
    q = q.bind(limit).bind(offset);
    q.fetch_all(pool).await.map_err(Into::into)
}

pub async fn count(pool: &SqlitePool, f: &TaskListFilters) -> DbResult<i64> {
    let mut n = 5usize;
    let (ws_clause, ws_bind) = f.workspace.clause("workspace_id", &mut n);
    let sql = format!(
        "SELECT COUNT(*) FROM tasks \
         WHERE (?1 IS NULL OR user_id = ?1) \
           AND (?2 IS NULL OR status = ?2) \
           AND (?3 IS NULL OR plugin_id = ?3) \
           AND (?4 IS NULL OR workflow_run_id = ?4) \
           AND (?5 IS NULL OR target LIKE '%' || ?5 || '%' OR plugin_name LIKE '%' || ?5 || '%') \
           {ws_clause}"
    );
    let mut q = sqlx::query_scalar::<_, i64>(&sql)
        .bind(&f.user_id)
        .bind(&f.status)
        .bind(&f.plugin_id)
        .bind(&f.workflow_run_id)
        .bind(&f.search);
    if let Some(id) = ws_bind {
        q = q.bind(id);
    }
    q.fetch_one(pool).await.map_err(Into::into)
}

pub async fn mark_running(pool: &SqlitePool, id: &str) -> DbResult<()> {
    let res = sqlx::query("UPDATE tasks SET status = 'running', started_at = ?1 WHERE id = ?2")
        .bind(now())
        .bind(id)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("task {id}")));
    }
    Ok(())
}

pub struct FinishTask<'a> {
    pub status: TaskStatus,
    pub exit_code: Option<i64>,
    pub error: Option<&'a str>,
    pub stats_json: &'a str,
    pub output: &'a str,
    pub output_truncated: bool,
}

pub async fn finish(pool: &SqlitePool, id: &str, f: FinishTask<'_>) -> DbResult<()> {
    let res = sqlx::query(
        "UPDATE tasks SET status = ?1, exit_code = ?2, error = ?3, stats_json = ?4, \
         output = ?5, output_truncated = ?6, finished_at = ?7 WHERE id = ?8",
    )
    .bind(f.status.label())
    .bind(f.exit_code)
    .bind(f.error)
    .bind(f.stats_json)
    .bind(f.output)
    .bind(f.output_truncated)
    .bind(now())
    .bind(id)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("task {id}")));
    }
    Ok(())
}

/// Mark any queued/running rows as failed — called at server startup so
/// tasks orphaned by a restart do not stay "running" forever.
pub async fn fail_orphans(pool: &SqlitePool, reason: &str) -> DbResult<u64> {
    let res = sqlx::query(
        "UPDATE tasks SET status = 'failed', error = ?1, finished_at = ?2 \
         WHERE status IN ('queued', 'running')",
    )
    .bind(reason)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn delete(pool: &SqlitePool, id: &str) -> DbResult<bool> {
    let res = sqlx::query("DELETE FROM tasks WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Recent tasks for the dashboard (no output column).
pub async fn recent(
    pool: &SqlitePool,
    user_id: Option<&str>,
    limit: i64,
) -> DbResult<Vec<TaskRow>> {
    recent_scoped(pool, user_id, &WorkspaceScope::All, limit).await
}

/// Recent tasks with an additional workspace scope (dashboard).
pub async fn recent_scoped(
    pool: &SqlitePool,
    user_id: Option<&str>,
    workspace: &WorkspaceScope,
    limit: i64,
) -> DbResult<Vec<TaskRow>> {
    let mut n = 1usize; // ?1 = user_id
    let (ws_clause, ws_bind) = workspace.clause("workspace_id", &mut n);
    n += 1;
    let p_lim = format!("?{n}");
    let sql = format!(
        "SELECT id, user_id, plugin_id, plugin_name, target, status, inputs_json, options_json, \
         exit_code, error, stats_json, NULL AS output, output_truncated, workflow_run_id, \
         workspace_id, schedule_id, robot_run_id, auth_profile_id, oob_marker, sniper_run_id, \
         created_at, started_at, finished_at \
         FROM tasks WHERE (?1 IS NULL OR user_id = ?1) \
         {ws_clause} \
         ORDER BY created_at DESC LIMIT {p_lim}"
    );
    let mut q = sqlx::query_as::<_, TaskRow>(&sql).bind(user_id);
    if let Some(id) = ws_bind {
        q = q.bind(id);
    }
    q = q.bind(limit.clamp(1, 50));
    q.fetch_all(pool).await.map_err(Into::into)
}

/// Live in-memory raw-output update for running tasks (so the UI can show
/// partial output before completion).
pub async fn update_output(
    pool: &SqlitePool,
    id: &str,
    output: &str,
    truncated: bool,
) -> DbResult<()> {
    sqlx::query("UPDATE tasks SET output = ?1, output_truncated = ?2 WHERE id = ?3")
        .bind(output)
        .bind(truncated)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Automatic diff baseline: the latest *other* completed run of the same
/// plugin against the same target, created no later than the reference
/// task, visible to `user_id` (None = admin / global). NULL targets match
/// via `IS` so target-less plugins still diff.
pub async fn find_previous_run(
    pool: &SqlitePool,
    user_id: Option<&str>,
    plugin_id: &str,
    target: Option<&str>,
    before_created_at: &str,
    exclude_id: &str,
) -> DbResult<Option<TaskRow>> {
    sqlx::query_as::<_, TaskRow>(
        "SELECT id, user_id, plugin_id, plugin_name, target, status, inputs_json, options_json, \
         exit_code, error, stats_json, NULL AS output, output_truncated, workflow_run_id, \
         workspace_id, schedule_id, robot_run_id, auth_profile_id, oob_marker, sniper_run_id, created_at, started_at, finished_at \
         FROM tasks \
         WHERE plugin_id = ?1 AND target IS ?2 AND status = 'completed' \
           AND id != ?3 AND created_at <= ?4 \
           AND (?5 IS NULL OR user_id = ?5) \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(plugin_id)
    .bind(target)
    .bind(exclude_id)
    .bind(before_created_at)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

/// Run history for one schedule (newest first), without the output column.
pub async fn list_for_schedule(
    pool: &SqlitePool,
    schedule_id: &str,
    limit: i64,
) -> DbResult<Vec<TaskRow>> {
    sqlx::query_as::<_, TaskRow>(
        "SELECT id, user_id, plugin_id, plugin_name, target, status, inputs_json, options_json, \
         exit_code, error, stats_json, NULL AS output, output_truncated, workflow_run_id, \
         workspace_id, schedule_id, robot_run_id, auth_profile_id, oob_marker, sniper_run_id, created_at, started_at, finished_at \
         FROM tasks WHERE schedule_id = ?1 \
         ORDER BY created_at DESC LIMIT ?2",
    )
    .bind(schedule_id)
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

/// True while a task launched by this schedule is still queued or running
/// (the scheduler's overlap guard).
pub async fn schedule_has_active_task(pool: &SqlitePool, schedule_id: &str) -> DbResult<bool> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM tasks \
         WHERE schedule_id = ?1 AND status IN ('queued', 'running')",
    )
    .bind(schedule_id)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}
