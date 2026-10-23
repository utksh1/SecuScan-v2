//! Sniper Auto-Exploiter repository.

use crate::models::SniperRunRow;
use crate::{new_id, now, DbResult};
use sqlx::SqlitePool;

pub async fn create_run(
    db: &SqlitePool,
    finding_id: &str,
    workspace_id: Option<&str>,
    category: &str,
    target: Option<&str>,
    user_id: &str,
) -> DbResult<SniperRunRow> {
    let id = new_id();
    let ts = now();
    sqlx::query(
        "INSERT INTO sniper_runs (id, finding_id, workspace_id, category, target, status,
                                   state_json, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, 'running', '[]', ?, ?)",
    )
    .bind(&id)
    .bind(finding_id)
    .bind(workspace_id)
    .bind(category)
    .bind(target)
    .bind(user_id)
    .bind(&ts)
    .execute(db)
    .await?;
    get_run(db, &id).await
}

pub async fn get_run(db: &SqlitePool, id: &str) -> DbResult<SniperRunRow> {
    sqlx::query_as::<_, SniperRunRow>("SELECT * FROM sniper_runs WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_runs(db: &SqlitePool, finding_id: Option<&str>, limit: u32) -> DbResult<Vec<SniperRunRow>> {
    let limit = limit.clamp(1, 200) as i64;
    match finding_id {
        Some(fid) => sqlx::query_as::<_, SniperRunRow>(
            "SELECT * FROM sniper_runs WHERE finding_id = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(fid)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => sqlx::query_as::<_, SniperRunRow>(
            "SELECT * FROM sniper_runs ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}

pub async fn set_run_state(db: &SqlitePool, run_id: &str, state_json: &str) -> DbResult<()> {
    sqlx::query("UPDATE sniper_runs SET state_json = ? WHERE id = ?")
        .bind(state_json)
        .bind(run_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn attach_task(db: &SqlitePool, run_id: &str, task_id: &str) -> DbResult<()> {
    sqlx::query("UPDATE tasks SET sniper_run_id = ? WHERE id = ?")
        .bind(run_id)
        .bind(task_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn finish_run(
    db: &SqlitePool,
    run_id: &str,
    status: &str,
    outcome: Option<&str>,
    proof: Option<&str>,
    error: Option<&str>,
) -> DbResult<()> {
    let ts = now();
    sqlx::query(
        "UPDATE sniper_runs SET status = ?, outcome = ?, proof = ?, error = ?, finished_at = ?
         WHERE id = ?",
    )
    .bind(status)
    .bind(outcome)
    .bind(proof)
    .bind(error)
    .bind(&ts)
    .bind(run_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Mark the source finding as validated with the chain's proof.
pub async fn validate_finding(
    db: &SqlitePool,
    finding_id: &str,
    proof: &str,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE findings SET kind = 'validated_issue', analyst_status = 'confirmed', proof = ?
         WHERE id = ?",
    )
    .bind(proof)
    .bind(finding_id)
    .execute(db)
    .await?;
    Ok(())
}
