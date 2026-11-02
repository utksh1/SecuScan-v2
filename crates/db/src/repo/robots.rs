//! Pentest Robots repository.
//!
//! Robots are DAGs of nodes (Tool / Filter / Extractor / Reducer). The
//! graph is stored as JSON; the runtime (in `crates/api/src/robot_runtime`)
//! walks it. This repo only persists rows — the orchestration lives higher
//! up so it can be unit-tested without a database.

use crate::models::{RobotRow, RobotRunRow};
use crate::new_id;
use crate::{DbError, DbResult};
use sqlx::SqlitePool;
use std::time::Duration;

const ROBOT_RUN_TIMEOUT: Duration = Duration::from_secs(86_400 * 2); // 48h

pub async fn create(
    db: &SqlitePool,
    name: &str,
    description: &str,
    nodes_json: &str,
    edges_json: &str,
    source: &str,
    user_id: &str,
) -> DbResult<RobotRow> {
    let id = new_id();
    let now = crate::now();
    sqlx::query(
        "INSERT INTO robots (id, name, description, nodes_json, edges_json, source, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(nodes_json)
    .bind(edges_json)
    .bind(source)
    .bind(user_id)
    .bind(&now)
    .execute(db)
    .await?;
    get(db, &id).await.map_err(Into::into)
}

pub async fn list(db: &SqlitePool) -> DbResult<Vec<RobotRow>> {
    sqlx::query_as::<_, RobotRow>("SELECT * FROM robots ORDER BY source DESC, created_at DESC")
        .fetch_all(db)
        .await
        .map_err(Into::into)
}

pub async fn get(db: &SqlitePool, id: &str) -> DbResult<RobotRow> {
    sqlx::query_as::<_, RobotRow>("SELECT * FROM robots WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn update(
    db: &SqlitePool,
    id: &str,
    name: &str,
    description: &str,
    nodes_json: &str,
    edges_json: &str,
) -> DbResult<()> {
    let now = crate::now();
    sqlx::query(
        "UPDATE robots SET name = ?, description = ?, nodes_json = ?, edges_json = ?, updated_at = ?
         WHERE id = ? AND source = 'user'",
    )
    .bind(name)
    .bind(description)
    .bind(nodes_json)
    .bind(edges_json)
    .bind(&now)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM robots WHERE id = ? AND source = 'user'")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

// --- runs ------------------------------------------------------------------

pub async fn create_run(
    db: &SqlitePool,
    robot_id: &str,
    workspace_id: Option<&str>,
    targets_json: &str,
    user_id: &str,
) -> DbResult<RobotRunRow> {
    let id = new_id();
    let now = crate::now();
    sqlx::query(
        "INSERT INTO robot_runs (id, robot_id, workspace_id, status, state_json, targets_json,
                                  created_by, created_at)
         VALUES (?, ?, ?, 'running', '{}', ?, ?, ?)",
    )
    .bind(&id)
    .bind(robot_id)
    .bind(workspace_id)
    .bind(targets_json)
    .bind(user_id)
    .bind(&now)
    .execute(db)
    .await?;
    get_run(db, &id).await.map_err(Into::into)
}

pub async fn get_run(db: &SqlitePool, id: &str) -> DbResult<RobotRunRow> {
    sqlx::query_as::<_, RobotRunRow>("SELECT * FROM robot_runs WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_runs(db: &SqlitePool, robot_id: &str) -> DbResult<Vec<RobotRunRow>> {
    sqlx::query_as::<_, RobotRunRow>(
        "SELECT * FROM robot_runs WHERE robot_id = ? ORDER BY created_at DESC",
    )
    .bind(robot_id)
    .fetch_all(db)
    .await
    .map_err(Into::into)
}

pub async fn set_run_state(db: &SqlitePool, run_id: &str, state_json: &str) -> DbResult<()> {
    sqlx::query("UPDATE robot_runs SET state_json = ? WHERE id = ?")
        .bind(state_json)
        .bind(run_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn finish_run(
    db: &SqlitePool,
    run_id: &str,
    status: &str,
    error: Option<&str>,
) -> DbResult<()> {
    let now = crate::now();
    sqlx::query("UPDATE robot_runs SET status = ?, error = ?, finished_at = ? WHERE id = ?")
        .bind(status)
        .bind(error)
        .bind(&now)
        .bind(run_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Returns the maximum wall-clock duration a robot run may take before the
/// runtime forcibly cancels it.
pub fn run_timeout() -> Duration {
    ROBOT_RUN_TIMEOUT
}
