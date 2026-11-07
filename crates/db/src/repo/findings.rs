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
             category, title, description, remediation, proof, url, metadata_json, created_at, \
             group_id, cve, cvss_v3, cvss_vector, epss_score, epss_percentile, cisa_kev, \
             cwe, owasp, confidence) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'new', ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                     NULL, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
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
        .bind(&f.cve)
        .bind(f.cvss_v3)
        .bind(&f.cvss_vector)
        .bind(f.epss_score)
        .bind(f.epss_percentile)
        .bind(if f.cisa_kev { 1i64 } else { 0 })
        .bind(&f.cwe)
        .bind(&f.owasp)
        .bind(&f.confidence)
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
    /// Keyset cursor (Sprint 2.1): encode of (severity_rank, created_at, id)
    /// — overrides `offset` when set, giving stable pagination under
    /// inserts/deletes. See `encode_cursor` / `decode_cursor`.
    pub cursor: Option<(i64, String, String)>,
}

/// Stable keyset cursor for the severity-ordered findings list.
pub fn encode_cursor(rank: i64, created_at: &str, id: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{rank}|{created_at}|{id}"))
}

/// Decode a cursor produced by [`encode_cursor`]; None on malformed input.
/// The returned fields are strictly charset-validated so the list query can
/// inline them as SQL literals (server-generated values; anything outside
/// the whitelist rejects the token outright).
pub fn decode_cursor(token: &str) -> Option<(i64, String, String)> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()?;
    let raw = String::from_utf8(raw).ok()?;
    let mut parts = raw.splitn(3, '|');
    let rank: i64 = parts.next()?.parse().ok()?;
    let created = parts.next()?.to_string();
    let id = parts.next()?.to_string();
    if !(0..=4).contains(&rank) {
        return None;
    }
    // ISO-8601 as produced by now_iso(): digits + T : . Z
    if created.is_empty()
        || !created
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'T' | ':' | '.' | 'Z' | '-'))
    {
        return None;
    }
    // new_id() = lowercase hex + dashes.
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return None;
    }
    Some((rank, created, id))
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
    // Cursor values are inlined as literals after strict charset
    // validation in `decode_cursor` (server-generated rank/created/id only)
    // — sidesteps the numbered-placeholder text-vs-bind-order contract for a
    // clause that sits before LIMIT in the SQL text (issue #24).
    let cursor_clause = match &f.cursor {
        Some((rank, created, id)) => format!(
            " AND ((CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END) > {rank} \
             OR ((CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END) = {rank} \
               AND (f.created_at < '{created}' OR (f.created_at = '{created}' AND f.id < '{id}'))))"
        ),
        None => String::new(),
    };
    let p_lim = ph.next();
    let p_off = ph.next();

    let sql = format!(
        "SELECT f.* FROM findings f \
         JOIN tasks t ON t.id = f.task_id \
         WHERE ({p_task} IS NULL OR f.task_id = {p_task}) \
           AND ({p_user} IS NULL
             OR (t.workspace_id IS NULL AND t.user_id = {p_user})
             OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = t.workspace_id
               AND ((w.access_mode = 'shared' AND t.user_id = {p_user})
                 OR (w.access_mode = 'private'
                   AND (w.created_by = {p_user} OR EXISTS (
                     SELECT 1 FROM workspace_members wm
                     WHERE wm.workspace_id = w.id AND wm.user_id = {p_user})))))) \
           AND ({p_kind} IS NULL OR f.kind = {p_kind}) \
           AND ({p_status} IS NULL OR f.analyst_status = {p_status}) \
           AND ({p_cat} IS NULL OR f.category = {p_cat}) \
           AND ({p_search} IS NULL OR f.title LIKE '%' || {p_search} || '%' OR f.description LIKE '%' || {p_search} || '%'){ws_clause}{sev_clause}{cursor_clause} \
         ORDER BY CASE f.severity \
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
            WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC, f.id DESC \
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
           AND ({p_user} IS NULL
             OR (t.workspace_id IS NULL AND t.user_id = {p_user})
             OR EXISTS (SELECT 1 FROM workspaces w WHERE w.id = t.workspace_id
               AND ((w.access_mode = 'shared' AND t.user_id = {p_user})
                 OR (w.access_mode = 'private'
                   AND (w.created_by = {p_user} OR EXISTS (
                     SELECT 1 FROM workspace_members wm
                     WHERE wm.workspace_id = w.id AND wm.user_id = {p_user})))))) \
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

/// One analyst triage update covering the full Sprint 2.1 surface: status,
/// severity override (Some("") resets), risk level, verified flag and the
/// audit trio (reason/by/at). Every field is optional; at least one caller
/// field must be set (enforced by the route).
#[allow(clippy::too_many_arguments)]
pub async fn update_triage(
    pool: &SqlitePool,
    id: &str,
    status: Option<AnalystStatus>,
    severity_override: Option<Option<&str>>,
    risk_level: Option<&str>,
    verified: Option<bool>,
    reason: Option<&str>,
    triage_by: &str,
) -> DbResult<FindingRow> {
    let current = get(pool, id).await?;
    // Freeze the scanner-reported severity on first override so the
    // override stays resettable to its true original.
    let severity_original = current
        .severity_original
        .clone()
        .or_else(|| Some(current.severity.clone()));
    let (set_override, override_value) = match severity_override {
        Some(Some(v)) if !v.is_empty() => (true, Some(v.to_string())),
        Some(_) => (true, None), // explicit reset
        None => (false, None),
    };
    sqlx::query(
        "UPDATE findings SET \
           analyst_status = COALESCE(?1, analyst_status), \
           severity_override = CASE WHEN ?2 THEN ?3 ELSE severity_override END, \
           severity_original = CASE WHEN ?2 THEN ?4 ELSE severity_original END, \
           risk_level = COALESCE(?5, risk_level), \
           verified = COALESCE(?6, verified), \
           triage_reason = COALESCE(?7, triage_reason), \
           triage_by = ?8, triage_at = ?9 \
         WHERE id = ?10",
    )
    .bind(status.as_ref().map(AnalystStatus::label))
    .bind(set_override)
    .bind(override_value)
    .bind(severity_original)
    .bind(risk_level)
    .bind(verified.map(|v| if v { 1i64 } else { 0i64 }))
    .bind(reason)
    .bind(triage_by)
    .bind(crate::now())
    .bind(id)
    .execute(pool)
    .await?;
    get(pool, id).await
}

/// Bulk status update (Sprint 2.1): one statement for the whole id set.
pub async fn bulk_update_status(
    pool: &SqlitePool,
    ids: &[String],
    status: AnalystStatus,
    triage_by: &str,
    reason: Option<&str>,
) -> DbResult<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    // Placeholder indices must account for the optional reason bind at ?4.
    let reason_offset = usize::from(reason.is_some());
    let placeholders = ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 4 + reason_offset))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE findings SET analyst_status = ?1, triage_by = ?2, triage_at = ?3, \
         triage_reason = COALESCE(?4_, triage_reason) WHERE id IN ({placeholders})"
    );
    // COALESCE with a numbered placeholder can't be written as ?4_ — build
    // with an explicit optional bind instead.
    let sql = if reason.is_some() {
        sql.replace("?4_", "?4")
    } else {
        sql.replace("COALESCE(?4_, triage_reason)", "triage_reason")
    };
    let ts = crate::now();
    let mut q = sqlx::query(&sql)
        .bind(status.label())
        .bind(triage_by)
        .bind(&ts);
    if let Some(r) = reason {
        q = q.bind(r);
    }
    for id in ids {
        q = q.bind(id);
    }
    Ok(q.execute(pool).await?.rows_affected())
}

/// A new finding that joined an existing dedup group inherits the group's
/// analyst *overrides* (severity override, risk level, verified flag) so
/// those decisions survive re-scan regeneration (issue #24 acceptance:
/// "override wins over regenerated value"). Deliberately NOT
/// `analyst_status`: status semantics belong to FP memory (forgetting an
/// FP must let the next scan report the finding fresh).
pub async fn inherit_group_triage(
    pool: &SqlitePool,
    group_id: &str,
    new_id: &str,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE findings SET \
           severity_override = (SELECT severity_override FROM findings WHERE group_id = ?1 AND severity_override IS NOT NULL LIMIT 1), \
           severity_original = (SELECT severity_original FROM findings WHERE group_id = ?1 AND severity_original IS NOT NULL LIMIT 1), \
           risk_level = (SELECT risk_level FROM findings WHERE group_id = ?1 AND risk_level IS NOT NULL LIMIT 1), \
           verified = (SELECT verified FROM findings WHERE group_id = ?1 AND verified IS NOT NULL LIMIT 1) \
         WHERE id = ?2",
    )
    .bind(group_id)
    .bind(new_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Effective severity: the analyst override when set, else the scanner value.
pub fn effective_severity(f: &crate::models::FindingRow) -> &str {
    f.severity_override.as_deref().unwrap_or(&f.severity)
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
