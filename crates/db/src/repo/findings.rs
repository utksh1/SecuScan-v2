//! Findings: bulk insert, filters, triage updates.

use super::workspaces::WorkspaceScope;
use crate::models::FindingRow;
use crate::{new_id, now, DbError, DbResult};
use secuscan_core::models::{AnalystStatus, Finding};
use sqlx::SqlitePool;

/// Insert all findings for a task in one transaction.
pub async fn insert_many(
    pool: &SqlitePool,
    task_id: &str,
    plugin_id: &str,
    findings: &[Finding],
) -> DbResult<Vec<String>> {
    let mut tx = pool.begin().await?;
    let mut ids = Vec::with_capacity(findings.len());
    let ts = now();
    for f in findings {
        let id = new_id();
        sqlx::query(
            "INSERT INTO findings (id, task_id, plugin_id, severity, kind, analyst_status, \
             category, title, description, remediation, proof, url, metadata_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'new', ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )
        .bind(&id)
        .bind(task_id)
        .bind(plugin_id)
        .bind(f.severity.label())
        .bind(f.kind.label())
        .bind(&f.category)
        .bind(&f.title)
        .bind(&f.description)
        .bind(&f.remediation)
        .bind(&f.proof)
        .bind(&f.url)
        .bind(f.metadata.to_string())
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
        ids.push(id);
    }
    tx.commit().await?;
    Ok(ids)
}

#[derive(Debug, Default)]
pub struct FindingFilters {
    pub task_id: Option<String>,
    pub user_id: Option<String>,
    /// Multiple severities are OR-combined via a parameterized IN clause.
    pub severity: Vec<String>,
    pub kind: Option<String>,
    pub analyst_status: Option<String>,
    pub category: Option<String>,
    pub search: Option<String>,
    pub workspace: WorkspaceScope,
    pub limit: i64,
    pub offset: i64,
}

/// Running placeholder counter: every fragment asks for the next index and
/// records it, so bind order always matches placeholder order no matter
/// which optional clauses are present. (A previous version hard-coded the
/// severity start index and collided with the OFFSET parameter.)
struct Ph(usize);

impl Ph {
    fn next(&mut self) -> String {
        self.0 += 1;
        format!("?{}", self.0)
    }
}

impl FindingFilters {
    /// `(f.severity = ?n OR f.severity = ?m …)` fragment and its bind
    /// values. Advances `ph` by the number of severities.
    fn severity_clause(&self, ph: &mut Ph) -> (String, Vec<String>) {
        if self.severity.is_empty() {
            return (String::new(), Vec::new());
        }
        let placeholders: Vec<String> = (0..self.severity.len()).map(|_| ph.next()).collect();
        (
            format!(
                " AND (f.severity = {})",
                placeholders.join(" OR f.severity = ")
            ),
            self.severity.clone(),
        )
    }
}

pub async fn list(pool: &SqlitePool, f: &FindingFilters) -> DbResult<Vec<FindingRow>> {
    let limit = if f.limit <= 0 { 100 } else { f.limit.min(1000) };
    let offset = f.offset.max(0);

    let mut ph = Ph(0);
    let p_task = ph.next();
    let p_user = ph.next();
    let p_kind = ph.next();
    let p_status = ph.next();
    let p_cat = ph.next();
    let p_search = ph.next();
    let (ws_clause, ws_bind) = f.workspace.clause("t.workspace_id", &mut ph.0);
    let (sev_clause, sev_binds) = f.severity_clause(&mut ph);
    let p_lim = ph.next();
    let p_off = ph.next();

    let sql = format!(
        "SELECT f.* FROM findings f \
         JOIN tasks t ON t.id = f.task_id \
         WHERE ({p_task} IS NULL OR f.task_id = {p_task}) \
           AND ({p_user} IS NULL OR t.user_id = {p_user}) \
           AND ({p_kind} IS NULL OR f.kind = {p_kind}) \
           AND ({p_status} IS NULL OR f.analyst_status = {p_status}) \
           AND ({p_cat} IS NULL OR f.category = {p_cat}) \
           AND ({p_search} IS NULL OR f.title LIKE '%' || {p_search} || '%' OR f.description LIKE '%' || {p_search} || '%'){ws_clause}{sev_clause} \
         ORDER BY CASE f.severity \
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
            WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC \
         LIMIT {p_lim} OFFSET {p_off}"
    );
    let mut q = sqlx::query_as::<_, FindingRow>(&sql)
        .bind(&f.task_id)
        .bind(&f.user_id)
        .bind(&f.kind)
        .bind(&f.analyst_status)
        .bind(&f.category)
        .bind(&f.search);
    if let Some(id) = ws_bind {
        q = q.bind(id);
    }
    for value in sev_binds {
        q = q.bind(value);
    }
    q = q.bind(limit).bind(offset);
    q.fetch_all(pool).await.map_err(Into::into)
}

pub async fn count(pool: &SqlitePool, f: &FindingFilters) -> DbResult<i64> {
    let mut ph = Ph(0);
    let p_task = ph.next();
    let p_user = ph.next();
    let p_kind = ph.next();
    let p_status = ph.next();
    let p_cat = ph.next();
    let p_search = ph.next();
    let (ws_clause, ws_bind) = f.workspace.clause("t.workspace_id", &mut ph.0);
    let (sev_clause, sev_binds) = f.severity_clause(&mut ph);

    let sql = format!(
        "SELECT COUNT(*) FROM findings f \
         JOIN tasks t ON t.id = f.task_id \
         WHERE ({p_task} IS NULL OR f.task_id = {p_task}) \
           AND ({p_user} IS NULL OR t.user_id = {p_user}) \
           AND ({p_kind} IS NULL OR f.kind = {p_kind}) \
           AND ({p_status} IS NULL OR f.analyst_status = {p_status}) \
           AND ({p_cat} IS NULL OR f.category = {p_cat}) \
           AND ({p_search} IS NULL OR f.title LIKE '%' || {p_search} || '%' OR f.description LIKE '%' || {p_search} || '%'){ws_clause}{sev_clause}"
    );
    let mut q = sqlx::query_scalar::<_, i64>(&sql)
        .bind(&f.task_id)
        .bind(&f.user_id)
        .bind(&f.kind)
        .bind(&f.analyst_status)
        .bind(&f.category)
        .bind(&f.search);
    if let Some(id) = ws_bind {
        q = q.bind(id);
    }
    for value in sev_binds {
        q = q.bind(value);
    }
    q.fetch_one(pool).await.map_err(Into::into)
}

pub async fn get(pool: &SqlitePool, id: &str) -> DbResult<FindingRow> {
    sqlx::query_as::<_, FindingRow>("SELECT * FROM findings WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("finding {id}")))
}

pub async fn update_analyst_status(
    pool: &SqlitePool,
    id: &str,
    status: AnalystStatus,
) -> DbResult<FindingRow> {
    let res = sqlx::query("UPDATE findings SET analyst_status = ?1 WHERE id = ?2")
        .bind(status.label())
        .bind(id)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("finding {id}")));
    }
    get(pool, id).await
}

/// Severity counts for one task (ordered critical→info).
pub async fn severity_counts_for_task(
    pool: &SqlitePool,
    task_id: &str,
) -> DbResult<Vec<(String, i64)>> {
    sqlx::query_as::<_, (String, i64)>(
        "SELECT severity, COUNT(*) FROM findings WHERE task_id = ?1 GROUP BY severity",
    )
    .bind(task_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

/// All findings of one task without the list-endpoint clamp (bounded by the
/// 5 000-per-task insert cap). Used by the diff engine.
pub async fn list_all_for_task(pool: &SqlitePool, task_id: &str) -> DbResult<Vec<FindingRow>> {
    sqlx::query_as::<_, FindingRow>(
        "SELECT * FROM findings WHERE task_id = ?1 \
         ORDER BY CASE severity \
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
            WHEN 'low' THEN 3 ELSE 4 END, created_at",
    )
    .bind(task_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}
