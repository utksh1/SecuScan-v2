//! Scan groups, wordlists, finding templates, asset imports — small repos
//! for v3.0.0 features that don't deserve their own file.

use crate::models::{AssetImportRow, FindingTemplateRow, ScanGroupRow, WordlistRow};
use crate::{new_id, now, DbResult};
use sqlx::SqlitePool;

// --- Scan Groups ----------------------------------------------------------

pub async fn create_scan_group(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    user_id: &str,
    name: &str,
    description: &str,
) -> DbResult<ScanGroupRow> {
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO scan_groups (id, workspace_id, name, description, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(name)
    .bind(description)
    .bind(user_id)
    .bind(&now_ts)
    .execute(db)
    .await?;
    sqlx::query_as::<_, ScanGroupRow>("SELECT * FROM scan_groups WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_scan_groups(
    db: &SqlitePool,
    workspace_id: Option<&str>,
) -> DbResult<Vec<ScanGroupRow>> {
    match workspace_id {
        Some(ws) => sqlx::query_as::<_, ScanGroupRow>(
            "SELECT * FROM scan_groups WHERE workspace_id = ? ORDER BY created_at DESC",
        )
        .bind(ws)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => {
            sqlx::query_as::<_, ScanGroupRow>("SELECT * FROM scan_groups ORDER BY created_at DESC")
                .fetch_all(db)
                .await
                .map_err(Into::into)
        }
    }
}

pub async fn add_task_to_group(
    db: &SqlitePool,
    scan_group_id: &str,
    task_id: &str,
) -> DbResult<()> {
    sqlx::query("INSERT OR IGNORE INTO scan_group_members (scan_group_id, task_id) VALUES (?, ?)")
        .bind(scan_group_id)
        .bind(task_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_tasks_in_group(db: &SqlitePool, scan_group_id: &str) -> DbResult<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT task_id FROM scan_group_members WHERE scan_group_id = ? ORDER BY rowid",
    )
    .bind(scan_group_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

pub async fn delete_scan_group(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM scan_groups WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

// --- Wordlists ------------------------------------------------------------

pub async fn create_wordlist(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    user_id: &str,
    name: &str,
    file_path: &str,
    word_count: i64,
    size_bytes: i64,
    kind: &str,
    source: &str,
) -> DbResult<WordlistRow> {
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO wordlists (id, workspace_id, name, source, file_path, word_count,
                                 size_bytes, kind, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(name)
    .bind(source)
    .bind(file_path)
    .bind(word_count)
    .bind(size_bytes)
    .bind(kind)
    .bind(user_id)
    .bind(&now_ts)
    .execute(db)
    .await?;
    sqlx::query_as::<_, WordlistRow>("SELECT * FROM wordlists WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_wordlists(
    db: &SqlitePool,
    workspace_id: Option<&str>,
) -> DbResult<Vec<WordlistRow>> {
    match workspace_id {
        Some(ws) => sqlx::query_as::<_, WordlistRow>(
            "SELECT * FROM wordlists WHERE workspace_id = ? OR source = 'builtin'
             ORDER BY source DESC, created_at DESC",
        )
        .bind(ws)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        None => sqlx::query_as::<_, WordlistRow>(
            "SELECT * FROM wordlists ORDER BY source DESC, created_at DESC",
        )
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}

pub async fn get_wordlist(db: &SqlitePool, id: &str) -> DbResult<WordlistRow> {
    sqlx::query_as::<_, WordlistRow>("SELECT * FROM wordlists WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn delete_wordlist(db: &SqlitePool, id: &str) -> DbResult<()> {
    // Don't delete builtin wordlists.
    sqlx::query("DELETE FROM wordlists WHERE id = ? AND source = 'user'")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

// --- Finding Templates ----------------------------------------------------

pub async fn create_template(
    db: &SqlitePool,
    scope: &str,
    workspace_id: Option<&str>,
    title: &str,
    category: &str,
    severity: &str,
    description: &str,
    remediation: &str,
    cwe: Option<&str>,
    owasp: Option<&str>,
    created_by: Option<&str>,
) -> DbResult<FindingTemplateRow> {
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO finding_templates (id, scope, workspace_id, title, category, severity,
                                         description, remediation, cwe, owasp, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(scope)
    .bind(workspace_id)
    .bind(title)
    .bind(category)
    .bind(severity)
    .bind(description)
    .bind(remediation)
    .bind(cwe)
    .bind(owasp)
    .bind(created_by)
    .bind(&now_ts)
    .execute(db)
    .await?;
    sqlx::query_as::<_, FindingTemplateRow>("SELECT * FROM finding_templates WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_templates(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    category: Option<&str>,
) -> DbResult<Vec<FindingTemplateRow>> {
    match (workspace_id, category) {
        (Some(ws), Some(cat)) => sqlx::query_as::<_, FindingTemplateRow>(
            "SELECT * FROM finding_templates
             WHERE (scope = 'public' OR workspace_id = ?) AND category = ?
             ORDER BY scope, title",
        )
        .bind(ws)
        .bind(cat)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        (Some(ws), None) => sqlx::query_as::<_, FindingTemplateRow>(
            "SELECT * FROM finding_templates WHERE scope = 'public' OR workspace_id = ?
             ORDER BY scope, title",
        )
        .bind(ws)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        (None, Some(cat)) => sqlx::query_as::<_, FindingTemplateRow>(
            "SELECT * FROM finding_templates WHERE scope = 'public' AND category = ?
             ORDER BY title",
        )
        .bind(cat)
        .fetch_all(db)
        .await
        .map_err(Into::into),
        (None, None) => sqlx::query_as::<_, FindingTemplateRow>(
            "SELECT * FROM finding_templates WHERE scope = 'public' ORDER BY title",
        )
        .fetch_all(db)
        .await
        .map_err(Into::into),
    }
}

pub async fn delete_template(db: &SqlitePool, id: &str) -> DbResult<()> {
    sqlx::query("DELETE FROM finding_templates WHERE id = ? AND scope != 'public'")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

// --- Asset Imports --------------------------------------------------------

pub async fn record_asset_import(
    db: &SqlitePool,
    workspace_id: &str,
    source: &str,
    summary: &str,
    created_count: i64,
    skipped_count: i64,
    created_by: &str,
) -> DbResult<AssetImportRow> {
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO asset_imports (id, workspace_id, source, summary, created_count,
                                     skipped_count, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(source)
    .bind(summary)
    .bind(created_count)
    .bind(skipped_count)
    .bind(created_by)
    .bind(&now_ts)
    .execute(db)
    .await?;
    sqlx::query_as::<_, AssetImportRow>("SELECT * FROM asset_imports WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_asset_imports(
    db: &SqlitePool,
    workspace_id: &str,
) -> DbResult<Vec<AssetImportRow>> {
    sqlx::query_as::<_, AssetImportRow>(
        "SELECT * FROM asset_imports WHERE workspace_id = ? ORDER BY created_at DESC",
    )
    .bind(workspace_id)
    .fetch_all(db)
    .await
    .map_err(Into::into)
}
