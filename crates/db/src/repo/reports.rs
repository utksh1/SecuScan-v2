//! Report jobs: async report generation persistence.

use crate::models::ReportJobRow;
use crate::{new_id, now, DbResult};
use sqlx::SqlitePool;

/// Payload for creating a report job (status starts `waiting`).
pub struct NewReportJob<'a> {
    pub task_id: &'a str,
    pub user_id: &'a str,
    pub format: &'a str,
    pub severity_filter: Option<&'a str>,
    pub webhook_url: Option<&'a str>,
    pub webhook_secret: Option<&'a str>,
}

pub async fn create(pool: &SqlitePool, j: NewReportJob<'_>) -> DbResult<ReportJobRow> {
    let row = ReportJobRow {
        id: new_id(),
        task_id: j.task_id.to_string(),
        user_id: j.user_id.to_string(),
        format: j.format.to_string(),
        severity_filter: j.severity_filter.map(str::to_string),
        status: "waiting".to_string(),
        error: None,
        file_path: None,
        file_bytes: None,
        webhook_url: j.webhook_url.map(str::to_string),
        webhook_secret: j.webhook_secret.map(str::to_string),
        webhook_attempts: 0,
        created_at: now(),
        started_at: None,
        finished_at: None,
    };
    sqlx::query(
        "INSERT INTO report_jobs (id, task_id, user_id, format, severity_filter, status, \
         webhook_url, webhook_secret, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'waiting', ?6, ?7, ?8)",
    )
    .bind(&row.id)
    .bind(&row.task_id)
    .bind(&row.user_id)
    .bind(&row.format)
    .bind(&row.severity_filter)
    .bind(&row.webhook_url)
    .bind(&row.webhook_secret)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn get(pool: &SqlitePool, id: &str) -> DbResult<ReportJobRow> {
    sqlx::query_as::<_, ReportJobRow>("SELECT * FROM report_jobs WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| crate::DbError::NotFound(format!("report job {id}")))
}

#[derive(Debug, Default)]
pub struct ReportJobListFilters {
    /// None = all users (admin view).
    pub user_id: Option<String>,
    pub task_id: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

/// List jobs newest-first. Callers clamp `limit` (the route enforces 1..=100).
pub async fn list(pool: &SqlitePool, f: &ReportJobListFilters) -> DbResult<Vec<ReportJobRow>> {
    let mut sql = String::from("SELECT * FROM report_jobs");
    let mut clauses: Vec<&'static str> = Vec::new();
    if f.user_id.is_some() {
        clauses.push("user_id = ?");
    }
    if f.task_id.is_some() {
        clauses.push("task_id = ?");
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?");
    let mut q = sqlx::query_as::<_, ReportJobRow>(&sql);
    if let Some(u) = &f.user_id {
        q = q.bind(u);
    }
    if let Some(t) = &f.task_id {
        q = q.bind(t);
    }
    q.bind(f.limit)
        .bind(f.offset)
        .fetch_all(pool)
        .await
        .map_err(Into::into)
}

pub async fn count(pool: &SqlitePool, f: &ReportJobListFilters) -> DbResult<i64> {
    let mut sql = String::from("SELECT COUNT(*) FROM report_jobs");
    let mut clauses: Vec<&'static str> = Vec::new();
    if f.user_id.is_some() {
        clauses.push("user_id = ?");
    }
    if f.task_id.is_some() {
        clauses.push("task_id = ?");
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    let mut q = sqlx::query_scalar::<_, i64>(&sql);
    if let Some(u) = &f.user_id {
        q = q.bind(u);
    }
    if let Some(t) = &f.task_id {
        q = q.bind(t);
    }
    q.fetch_one(pool).await.map_err(Into::into)
}

/// Number of jobs a user still has queued or rendering (admission cap).
pub async fn count_active_for_user(pool: &SqlitePool, user_id: &str) -> DbResult<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM report_jobs WHERE user_id = ?1 AND status IN ('waiting','in_progress')",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

pub async fn mark_running(pool: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("UPDATE report_jobs SET status = 'in_progress', started_at = ?2 WHERE id = ?1")
        .bind(id)
        .bind(now())
        .execute(pool)
        .await?;
    Ok(())
}

/// Terminal update payload: `finished` (with file) or `failed` (with reason).
pub struct FinishReport {
    pub file_path: Option<String>,
    pub file_bytes: Option<i64>,
    pub error: Option<String>,
}

/// Terminal update: `finished` (with file) or `failed` (with reason).
/// Both timestamp columns are stamped; `file_bytes` doubles as a sanity
/// check at download time. Returns the number of affected rows — 0 means
/// the job was deleted while running, and the caller should clean up any
/// artifact it wrote.
pub async fn finish(pool: &SqlitePool, id: &str, f: FinishReport) -> DbResult<u64> {
    let status = if f.error.is_some() {
        "failed"
    } else {
        "finished"
    };
    let res = sqlx::query(
        "UPDATE report_jobs SET status = ?2, error = ?3, file_path = ?4, file_bytes = ?5, \
         finished_at = ?6 WHERE id = ?1",
    )
    .bind(id)
    .bind(status)
    .bind(&f.error)
    .bind(&f.file_path)
    .bind(f.file_bytes)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn record_webhook_attempts(pool: &SqlitePool, id: &str, attempts: i64) -> DbResult<()> {
    sqlx::query("UPDATE report_jobs SET webhook_attempts = ?2 WHERE id = ?1")
        .bind(id)
        .bind(attempts)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a job row; returns it (with `file_path`) so the caller can remove
/// the artifact from disk.
pub async fn delete(pool: &SqlitePool, id: &str) -> DbResult<Option<ReportJobRow>> {
    let row = sqlx::query_as::<_, ReportJobRow>("SELECT * FROM report_jobs WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    if row.is_some() {
        sqlx::query("DELETE FROM report_jobs WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(row)
}

/// File locations for a task's jobs — used to clean the disk when the task
/// is deleted (the DB rows themselves cascade).
pub async fn file_paths_for_task(pool: &SqlitePool, task_id: &str) -> DbResult<Vec<String>> {
    sqlx::query_scalar::<_, String>(
        "SELECT file_path FROM report_jobs WHERE task_id = ?1 AND file_path IS NOT NULL",
    )
    .bind(task_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

/// Retention: drop a user's oldest *finished* jobs beyond `keep`, removing
/// their artifacts from disk. Returns the file paths to delete. The stale
/// set is tiny (only the overflow), so per-id statements are fine here —
/// no dynamic IN() string building needed.
pub async fn prune_finished(pool: &SqlitePool, user_id: &str, keep: i64) -> DbResult<Vec<String>> {
    let stale: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM report_jobs WHERE user_id = ?1 AND status = 'finished' \
         ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?2",
    )
    .bind(user_id)
    .bind(keep)
    .fetch_all(pool)
    .await?;
    let mut files = Vec::with_capacity(stale.len());
    for id in &stale {
        let fp: Option<String> =
            sqlx::query_scalar("SELECT file_path FROM report_jobs WHERE id = ?1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        if let Some(f) = fp {
            files.push(f);
        }
        sqlx::query("DELETE FROM report_jobs WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(files)
}

/// Startup recovery: jobs interrupted by a restart cannot resume (their
/// tokio task is gone) — mark them failed so the UI shows the truth.
pub async fn fail_interrupted(pool: &SqlitePool, reason: &str) -> DbResult<u64> {
    let res = sqlx::query(
        "UPDATE report_jobs SET status = 'failed', error = ?1, finished_at = ?2 \
         WHERE status IN ('waiting','in_progress')",
    )
    .bind(reason)
    .bind(now())
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
