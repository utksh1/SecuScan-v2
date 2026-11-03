//! Recurring scan schedules: CRUD + the due-claiming helpers the
//! scheduler worker uses. See migration 0004 for the model rationale.

use super::workspaces::WorkspaceScope;
use crate::models::ScheduleRow;
use crate::{new_id, now, DbError, DbResult};
use sqlx::SqlitePool;

/// Admission bounds (mirrored by the DB CHECK on `interval_seconds`).
pub const MIN_INTERVAL_SECONDS: i64 = 300; // 5 minutes
pub const MAX_INTERVAL_SECONDS: i64 = 31_536_000; // 365 days

pub fn validate_interval(seconds: i64) -> Result<(), DbError> {
    if (MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&seconds) {
        Ok(())
    } else {
        Err(DbError::Invalid(format!(
            "interval_seconds must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS}"
        )))
    }
}

pub struct NewSchedule<'a> {
    pub user_id: &'a str,
    pub workspace_id: Option<&'a str>,
    pub name: &'a str,
    pub plugin_id: &'a str,
    pub inputs_json: &'a str,
    pub preset: Option<&'a str>,
    pub target: Option<&'a str>,
    pub interval_seconds: i64,
}

/// Create a schedule. `next_run_at` is anchored to `now + interval` — the
/// first automated run happens one interval after creation; use the
/// run-now endpoint for an immediate execution.
pub async fn create(pool: &SqlitePool, s: NewSchedule<'_>) -> DbResult<ScheduleRow> {
    validate_interval(s.interval_seconds)?;
    let row = ScheduleRow {
        id: new_id(),
        user_id: s.user_id.to_string(),
        workspace_id: s.workspace_id.map(str::to_string),
        name: s.name.to_string(),
        plugin_id: s.plugin_id.to_string(),
        inputs_json: s.inputs_json.to_string(),
        preset: s.preset.map(str::to_string),
        target: s.target.map(str::to_string),
        interval_seconds: s.interval_seconds,
        enabled: true,
        next_run_at: secuscan_core::models::add_seconds_iso(&now(), s.interval_seconds),
        last_run_at: None,
        last_task_id: None,
        last_error: None,
        created_at: now(),
        updated_at: None,
    };
    sqlx::query(
        "INSERT INTO schedules (id, user_id, workspace_id, name, plugin_id, inputs_json, \
         preset, target, interval_seconds, enabled, next_run_at, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11)",
    )
    .bind(&row.id)
    .bind(&row.user_id)
    .bind(&row.workspace_id)
    .bind(&row.name)
    .bind(&row.plugin_id)
    .bind(&row.inputs_json)
    .bind(&row.preset)
    .bind(&row.target)
    .bind(row.interval_seconds)
    .bind(&row.next_run_at)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn get(pool: &SqlitePool, id: &str) -> DbResult<ScheduleRow> {
    sqlx::query_as::<_, ScheduleRow>("SELECT * FROM schedules WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("schedule {id}")))
}

#[derive(Debug, Default)]
pub struct ScheduleListFilters {
    /// None = admin view (all users).
    pub user_id: Option<String>,
    pub workspace: WorkspaceScope,
    pub limit: i64,
    pub offset: i64,
}

pub async fn list(pool: &SqlitePool, f: &ScheduleListFilters) -> DbResult<Vec<ScheduleRow>> {
    let limit = if f.limit <= 0 { 100 } else { f.limit.min(500) };
    let offset = f.offset.max(0);
    let mut n = 1usize; // ?1 = user_id
    let (ws_clause, ws_bind) = f.workspace.clause("workspace_id", &mut n);
    n += 1;
    let p_lim = format!("?{n}");
    n += 1;
    let p_off = format!("?{n}");
    let sql = format!(
        "SELECT * FROM schedules \
         WHERE (?1 IS NULL OR (
           user_id = ?1 AND (workspace_id IS NULL OR EXISTS (
             SELECT 1 FROM workspaces w WHERE w.id = workspace_id
             AND (w.access_mode = 'shared' OR w.created_by = ?1
               OR EXISTS (SELECT 1 FROM workspace_members wm
                 WHERE wm.workspace_id = w.id AND wm.user_id = ?1))
           ))
         )) \
         {ws_clause} \
         ORDER BY created_at DESC LIMIT {p_lim} OFFSET {p_off}"
    );
    let mut q = sqlx::query_as::<_, ScheduleRow>(&sql).bind(&f.user_id);
    if let Some(id) = ws_bind {
        q = q.bind(id);
    }
    q = q.bind(limit).bind(offset);
    q.fetch_all(pool).await.map_err(Into::into)
}

pub async fn count(pool: &SqlitePool, f: &ScheduleListFilters) -> DbResult<i64> {
    let mut n = 1usize;
    let (ws_clause, ws_bind) = f.workspace.clause("workspace_id", &mut n);
    let sql = format!(
        "SELECT COUNT(*) FROM schedules \
         WHERE (?1 IS NULL OR (
           user_id = ?1 AND (workspace_id IS NULL OR EXISTS (
             SELECT 1 FROM workspaces w WHERE w.id = workspace_id
             AND (w.access_mode = 'shared' OR w.created_by = ?1
               OR EXISTS (SELECT 1 FROM workspace_members wm
                 WHERE wm.workspace_id = w.id AND wm.user_id = ?1))
           ))
         )) \
         {ws_clause}"
    );
    let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(&f.user_id);
    if let Some(id) = ws_bind {
        q = q.bind(id);
    }
    q.fetch_one(pool).await.map_err(Into::into)
}

pub struct ScheduleUpdate<'a> {
    pub name: &'a str,
    pub inputs_json: &'a str,
    pub preset: Option<&'a str>,
    pub target: Option<&'a str>,
    pub interval_seconds: i64,
    pub enabled: bool,
    /// Final workspace (None = the Personal scope).
    pub workspace_id: Option<&'a str>,
    /// Final anchor. The API layer re-anchors on interval change or
    /// re-enable; other edits keep the stored value.
    pub next_run_at: &'a str,
}

/// Full write of the mutable fields. The API layer merges the patch into
/// the loaded row first, so `None`-able columns (preset, target, workspace)
/// can genuinely be *cleared*, unlike a COALESCE-based partial update.
pub async fn update(pool: &SqlitePool, id: &str, u: ScheduleUpdate<'_>) -> DbResult<ScheduleRow> {
    validate_interval(u.interval_seconds)?;
    let res = sqlx::query(
        "UPDATE schedules SET \
         name = ?1, inputs_json = ?2, preset = ?3, target = ?4, interval_seconds = ?5, \
         enabled = ?6, workspace_id = ?7, next_run_at = ?8, updated_at = ?9 \
         WHERE id = ?10",
    )
    .bind(u.name)
    .bind(u.inputs_json)
    .bind(u.preset)
    .bind(u.target)
    .bind(u.interval_seconds)
    .bind(u.enabled)
    .bind(u.workspace_id)
    .bind(u.next_run_at)
    .bind(now())
    .bind(id)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("schedule {id}")));
    }
    get(pool, id).await
}

/// Record the outcome of a scheduler attempt: stamp `last_run_at`, link the
/// launched task (if any), set/clear `last_error`, and move the anchor
/// forward. A NULL error clears the previous failure message.
pub async fn mark_run(
    pool: &SqlitePool,
    id: &str,
    last_task_id: Option<&str>,
    error: Option<&str>,
    next_run_at: &str,
) -> DbResult<()> {
    let res = sqlx::query(
        "UPDATE schedules SET \
         last_run_at = ?1, last_task_id = COALESCE(?2, last_task_id), last_error = ?3, \
         next_run_at = ?4, updated_at = ?5 \
         WHERE id = ?6",
    )
    .bind(now())
    .bind(last_task_id)
    .bind(error)
    .bind(next_run_at)
    .bind(now())
    .bind(id)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("schedule {id}")));
    }
    Ok(())
}

/// Due schedules: enabled, anchored in the past, oldest first. Bounded so a
/// backlog cannot monopolize a single tick.
pub async fn list_due(pool: &SqlitePool, now_ts: &str) -> DbResult<Vec<ScheduleRow>> {
    sqlx::query_as::<_, ScheduleRow>(
        "SELECT * FROM schedules \
         WHERE enabled = 1 AND next_run_at <= ?1 \
         ORDER BY next_run_at ASC LIMIT 50",
    )
    .bind(now_ts)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn delete(pool: &SqlitePool, id: &str) -> DbResult<bool> {
    let res = sqlx::query("DELETE FROM schedules WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}
