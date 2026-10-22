//! Workspaces and registered targets.
//!
//! Workspaces group tasks and targets into project hubs (client /
//! environment scoping, pentest-tools.com style). The "Personal" scope is
//! synthetic — tasks with `workspace_id IS NULL` — and never has a row.

use crate::models::{TargetRow, WorkspaceRow};
use crate::{new_id, now, DbError, DbResult};
use serde::Serialize;
use sqlx::SqlitePool;

/// How a query is scoped to a workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WorkspaceScope {
    /// No workspace filtering.
    #[default]
    All,
    /// Restrict to one workspace.
    Id(String),
    /// Only tasks without a workspace (the synthetic "Personal" one).
    Personal,
}

impl WorkspaceScope {
    /// SQL fragment for a column, e.g. ` AND (t.workspace_id = ?5)` /
    /// ` AND (t.workspace_id IS NULL)` / ``. Advances `ph` only when a
    /// bind is produced, so the caller's subsequent placeholders stay in
    /// sync with its bind calls.
    pub fn clause(&self, col: &str, ph: &mut usize) -> (String, Option<String>) {
        match self {
            WorkspaceScope::All => (String::new(), None),
            WorkspaceScope::Id(id) => {
                *ph += 1;
                (format!(" AND ({col} = ?{ph})"), Some(id.clone()))
            }
            WorkspaceScope::Personal => (format!(" AND ({col} IS NULL)"), None),
        }
    }
}

pub struct NewWorkspace<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub created_by: &'a str,
}

pub async fn create_workspace(pool: &SqlitePool, w: NewWorkspace<'_>) -> DbResult<WorkspaceRow> {
    let row = WorkspaceRow {
        id: new_id(),
        name: w.name.to_string(),
        description: w.description.to_string(),
        created_by: w.created_by.to_string(),
        created_at: now(),
        updated_at: None,
    };
    sqlx::query(
        "INSERT INTO workspaces (id, name, description, created_by, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(&row.id)
    .bind(&row.name)
    .bind(&row.description)
    .bind(&row.created_by)
    .bind(&row.created_at)
    .execute(pool)
    .await?;
    Ok(row)
}

pub async fn get_workspace(pool: &SqlitePool, id: &str) -> DbResult<WorkspaceRow> {
    sqlx::query_as::<_, WorkspaceRow>("SELECT * FROM workspaces WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("workspace {id}")))
}

pub async fn list_workspaces(pool: &SqlitePool) -> DbResult<Vec<WorkspaceRow>> {
    sqlx::query_as::<_, WorkspaceRow>("SELECT * FROM workspaces ORDER BY name COLLATE NOCASE")
        .fetch_all(pool)
        .await
        .map_err(Into::into)
}

pub struct WorkspaceUpdate<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
}

/// `updated_at` is stamped when anything actually changes.
pub async fn update_workspace(
    pool: &SqlitePool,
    id: &str,
    u: WorkspaceUpdate<'_>,
) -> DbResult<WorkspaceRow> {
    let res = sqlx::query(
        "UPDATE workspaces SET \
         name = COALESCE(?1, name), \
         description = COALESCE(?2, description), \
         updated_at = ?3 \
         WHERE id = ?4",
    )
    .bind(u.name)
    .bind(u.description)
    .bind(now())
    .bind(id)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound(format!("workspace {id}")));
    }
    get_workspace(pool, id).await
}

pub async fn delete_workspace(pool: &SqlitePool, id: &str) -> DbResult<bool> {
    let res = sqlx::query("DELETE FROM workspaces WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Counters for one workspace (task counts include every user's tasks —
/// workspaces are shared).
#[derive(Debug, Clone, Default, Serialize)]
pub struct WorkspaceCounts {
    pub tasks_total: i64,
    pub tasks_active: i64,
    pub targets_total: i64,
}

/// Counts for every workspace + the Personal scope in three fixed queries
/// (avoids the N+1 pattern of calling `workspace_counts` per row — this
/// list is polled by the UI switcher).
pub async fn all_workspace_counts(
    pool: &SqlitePool,
) -> DbResult<(
    std::collections::HashMap<String, WorkspaceCounts>,
    WorkspaceCounts,
)> {
    use std::collections::HashMap;

    let task_totals: Vec<(Option<String>, i64)> =
        sqlx::query_as("SELECT workspace_id, COUNT(*) FROM tasks GROUP BY workspace_id")
            .fetch_all(pool)
            .await?;
    let task_active: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT workspace_id, COUNT(*) FROM tasks \
         WHERE status IN ('queued', 'running') GROUP BY workspace_id",
    )
    .fetch_all(pool)
    .await?;
    let target_totals: Vec<(Option<String>, i64)> =
        sqlx::query_as("SELECT workspace_id, COUNT(*) FROM targets GROUP BY workspace_id")
            .fetch_all(pool)
            .await?;

    // NULL workspace_id (the Personal scope) is bucketed under the empty
    // string and extracted at the end.
    fn counts_entry<'a>(
        map: &'a mut std::collections::HashMap<String, WorkspaceCounts>,
        ws: &Option<String>,
    ) -> &'a mut WorkspaceCounts {
        match ws {
            Some(id) => map.entry(id.clone()).or_default(),
            None => map.entry(String::new()).or_default(),
        }
    }

    let mut map: HashMap<String, WorkspaceCounts> = HashMap::new();
    for (ws, n) in task_totals {
        counts_entry(&mut map, &ws).tasks_total = n;
    }
    for (ws, n) in task_active {
        counts_entry(&mut map, &ws).tasks_active = n;
    }
    for (ws, n) in target_totals {
        counts_entry(&mut map, &ws).targets_total = n;
    }
    let personal = map.remove("").unwrap_or_default();
    Ok((map, personal))
}

/// Counts for a single workspace (used by the detail endpoint).
pub async fn workspace_counts(pool: &SqlitePool, id: &str) -> DbResult<WorkspaceCounts> {
    let (tasks_total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM tasks WHERE workspace_id = ?1")
            .bind(id)
            .fetch_one(pool)
            .await?;
    let (tasks_active,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM tasks WHERE workspace_id = ?1 AND status IN ('queued', 'running')",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    let (targets_total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM targets WHERE workspace_id = ?1")
            .bind(id)
            .fetch_one(pool)
            .await?;
    Ok(WorkspaceCounts {
        tasks_total,
        tasks_active,
        targets_total,
    })
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// Derive the target kind from its name. Order matters: a URL contains a
/// host, but a bare host is never a URL.
pub fn derive_target_kind(name: &str) -> &'static str {
    if name.contains("://") || name.starts_with("//") {
        "url"
    } else if name.parse::<std::net::IpAddr>().is_ok()
        || name.trim_start_matches('[').contains("]:")
    {
        "ip_address"
    } else {
        "hostname"
    }
}

pub struct NewTarget<'a> {
    pub workspace_id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub created_by: &'a str,
}

pub async fn create_target(pool: &SqlitePool, t: NewTarget<'_>) -> DbResult<TargetRow> {
    let row = TargetRow {
        id: new_id(),
        workspace_id: t.workspace_id.to_string(),
        name: t.name.to_string(),
        kind: derive_target_kind(t.name).to_string(),
        description: t.description.to_string(),
        created_by: t.created_by.to_string(),
        created_at: now(),
    };
    let res = sqlx::query(
        "INSERT INTO targets (id, workspace_id, name, kind, description, created_by, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(&row.id)
    .bind(&row.workspace_id)
    .bind(&row.name)
    .bind(&row.kind)
    .bind(&row.description)
    .bind(&row.created_by)
    .bind(&row.created_at)
    .execute(pool)
    .await;
    match res {
        Ok(_) => {}
        // Catches both the direct duplicate insert and the check-then-insert
        // race: UNIQUE(workspace_id, name) is authoritative.
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(DbError::Conflict(format!(
                "target `{}` already exists in this workspace",
                t.name
            )))
        }
        Err(e) => return Err(e.into()),
    }
    Ok(row)
}

pub async fn get_target(pool: &SqlitePool, id: &str) -> DbResult<TargetRow> {
    sqlx::query_as::<_, TargetRow>("SELECT * FROM targets WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("target {id}")))
}

pub async fn list_targets(pool: &SqlitePool, workspace_id: &str) -> DbResult<Vec<TargetRow>> {
    sqlx::query_as::<_, TargetRow>(
        "SELECT * FROM targets WHERE workspace_id = ?1 ORDER BY created_at DESC, name",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub struct TargetUpdate<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
}

pub async fn update_target(
    pool: &SqlitePool,
    id: &str,
    u: TargetUpdate<'_>,
) -> DbResult<TargetRow> {
    let current = get_target(pool, id).await?;
    let new_name = u.name.unwrap_or(&current.name);
    let kind = if u.name.is_some() {
        derive_target_kind(new_name).to_string()
    } else {
        current.kind.clone()
    };
    let res = sqlx::query(
        "UPDATE targets SET name = ?1, kind = ?2, description = COALESCE(?3, description) \
         WHERE id = ?4",
    )
    .bind(new_name)
    .bind(&kind)
    .bind(u.description)
    .bind(id)
    .execute(pool)
    .await;
    match res {
        Ok(_) => {}
        // Rename collided with an existing target in the same workspace.
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(DbError::Conflict(format!(
                "target `{new_name}` already exists in this workspace"
            )))
        }
        Err(e) => return Err(e.into()),
    }
    get_target(pool, id).await
}

pub async fn delete_target(pool: &SqlitePool, id: &str) -> DbResult<bool> {
    let res = sqlx::query("DELETE FROM targets WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Per-target scan statistics shown on the Targets page. Matching is by
/// exact target string (the task's resolved `target` column).
#[derive(Debug, Clone, Default, Serialize)]
pub struct TargetStats {
    pub scans_total: i64,
    pub last_scanned_at: Option<String>,
}

/// Stats for every target in a workspace in two fixed queries (avoids
/// running 2 queries per target on the list endpoint).
pub async fn target_stats_many(
    pool: &SqlitePool,
    workspace_id: &str,
) -> DbResult<std::collections::HashMap<String, TargetStats>> {
    let totals: Vec<(String, i64)> = sqlx::query_as(
        "SELECT target, COUNT(*) FROM tasks WHERE workspace_id = ?1 AND target IS NOT NULL \
         GROUP BY target",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await?;
    let lasts: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT target, MAX(created_at) FROM tasks WHERE workspace_id = ?1 AND target IS NOT NULL \
         GROUP BY target",
    )
    .bind(workspace_id)
    .fetch_all(pool)
    .await?;
    let mut map: std::collections::HashMap<String, TargetStats> = std::collections::HashMap::new();
    for (target, n) in totals {
        map.entry(target).or_default().scans_total = n;
    }
    for (target, last) in lasts {
        if let Some(l) = last {
            if !l.is_empty() {
                map.entry(target).or_default().last_scanned_at = Some(l);
            }
        }
    }
    Ok(map)
}

pub async fn target_stats(
    pool: &SqlitePool,
    workspace_id: &str,
    name: &str,
) -> DbResult<TargetStats> {
    let (scans_total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM tasks WHERE workspace_id = ?1 AND target = ?2")
            .bind(workspace_id)
            .bind(name)
            .fetch_one(pool)
            .await?;
    let last: Option<(Option<String>,)> =
        sqlx::query_as("SELECT MAX(created_at) FROM tasks WHERE workspace_id = ?1 AND target = ?2")
            .bind(workspace_id)
            .bind(name)
            .fetch_optional(pool)
            .await?;
    let last_scanned_at = match last {
        // MAX() over an empty set yields one row containing NULL.
        Some((Some(s),)) if !s.is_empty() => Some(s),
        _ => None,
    };
    Ok(TargetStats {
        scans_total,
        last_scanned_at,
    })
}

/// Personal-scope aggregate (tasks with no workspace) for the switcher.
pub async fn personal_counts(pool: &SqlitePool) -> DbResult<(i64, i64)> {
    let (tasks_total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM tasks WHERE workspace_id IS NULL")
            .fetch_one(pool)
            .await?;
    let (tasks_active,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM tasks WHERE workspace_id IS NULL AND status IN ('queued', 'running')",
    )
    .fetch_one(pool)
    .await?;
    Ok((tasks_total, tasks_active))
}
