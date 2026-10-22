//! Workflows and their runs.

use crate::models::{WorkflowRow, WorkflowRunRow};
use crate::{new_id, now, DbError, DbResult};
use secuscan_core::models::TaskStatus;
use sqlx::SqlitePool;

pub async fn create(
    pool: &SqlitePool,
    name: &str,
    description: &str,
    steps_json: &str,
    created_by: &str,
) -> DbResult<WorkflowRow> {
    let row = WorkflowRow {
        id: new_id(),
        name: name.trim().to_string(),
        description: description.trim().to_string(),
        steps_json: steps_json.to_string(),
        created_by: created_by.to_string(),
        created_at: now(),
        updated_at: None,
    };
    sqlx::query(
        "INSERT INTO workflows (id, name, description, steps_json, created_by, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&row.id)
    .bind(&row.name)
    .bind(&row.description)
    .bind(&row.steps_json)
    .bind(&row.created_by)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn get(pool: &SqlitePool, id: &str) -> DbResult<WorkflowRow> {
    sqlx::query_as::<_, WorkflowRow>("SELECT * FROM workflows WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("workflow {id}")))
}

pub async fn list(pool: &SqlitePool) -> DbResult<Vec<WorkflowRow>> {
    sqlx::query_as::<_, WorkflowRow>("SELECT * FROM workflows ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .map_err(Into::into)
}

pub async fn update(
    pool: &SqlitePool,
    id: &str,
    name: &str,
    description: &str,
    steps_json: &str,
) -> DbResult<()> {
    let res = sqlx::query(
        "UPDATE workflows SET name = ?1, description = ?2, steps_json = ?3, updated_at = ?4 \
         WHERE id = ?5",
    )
    .bind(name)
    .bind(description)
    .bind(steps_json)
    .bind(now())
    .bind(id)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("workflow {id}")));
    }
    Ok(())
}

pub async fn delete(pool: &SqlitePool, id: &str) -> DbResult<bool> {
    let res = sqlx::query("DELETE FROM workflows WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

// --- runs ------------------------------------------------------------------

pub async fn create_run(pool: &SqlitePool, workflow_id: &str) -> DbResult<WorkflowRunRow> {
    let row = WorkflowRunRow {
        id: new_id(),
        workflow_id: workflow_id.to_string(),
        status: TaskStatus::Queued.label().to_string(),
        task_ids_json: "[]".into(),
        error: None,
        created_at: now(),
        finished_at: None,
    };
    sqlx::query(
        "INSERT INTO workflow_runs (id, workflow_id, status, task_ids_json, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(&row.id)
    .bind(&row.workflow_id)
    .bind(&row.status)
    .bind(&row.task_ids_json)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn append_run_task(pool: &SqlitePool, run_id: &str, task_id: &str) -> DbResult<()> {
    // Read-modify-write is safe: only the workflow runner mutates a run.
    let current: String = sqlx::query_scalar("SELECT task_ids_json FROM workflow_runs WHERE id = ?1")
        .bind(run_id)
        .fetch_one(pool)
        .await?;
    let mut ids: Vec<String> = serde_json::from_str(&current).unwrap_or_default();
    ids.push(task_id.to_string());
    sqlx::query("UPDATE workflow_runs SET task_ids_json = ?1, status = 'running' WHERE id = ?2")
        .bind(serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into()))
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn finish_run(
    pool: &SqlitePool,
    run_id: &str,
    status: TaskStatus,
    error: Option<&str>,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE workflow_runs SET status = ?1, error = ?2, finished_at = ?3 WHERE id = ?4",
    )
    .bind(status.label())
    .bind(error)
    .bind(now())
    .bind(run_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_runs(pool: &SqlitePool, workflow_id: &str) -> DbResult<Vec<WorkflowRunRow>> {
    sqlx::query_as::<_, WorkflowRunRow>(
        "SELECT * FROM workflow_runs WHERE workflow_id = ?1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn count_workflows(pool: &SqlitePool) -> DbResult<i64> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM workflows")
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}
