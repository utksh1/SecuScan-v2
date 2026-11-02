//! Finding dedup groups + false-positive memory.
//!
//! Dedup: findings with the same (workspace, plugin_id, normalized_title,
//! target_fingerprint) end up in the same `finding_groups` row. Status changes
//! on one finding propagate to all members of its group.
//!
//! FP memory: when an analyst marks a finding as `false_positive`, we record
//! a row in `fp_memory` keyed on the same fingerprint. Future scans that
//! produce a matching finding auto-mark it `false_positive` on insert.
//!
//! Target fingerprint: derived from the finding's URL or the task target.
//! For URLs we use the host:port. For bare hostnames/IPs we use the value
//! as-is. This keeps dedup stable across re-scans of the same target.

use crate::models::{FindingGroupRow, FpMemoryRow};
use crate::{new_id, now, DbResult};
use regex::Regex;
use sqlx::SqlitePool;
use std::sync::OnceLock;

fn normalize_title(s: &str) -> String {
    static RE_WS: OnceLock<Regex> = OnceLock::new();
    let re = RE_WS.get_or_init(|| Regex::new(r"\s+").unwrap());
    let lower = s.to_lowercase();
    re.replace_all(&lower, " ").trim().to_string()
}

/// Derive a stable target fingerprint from a finding's URL or a fallback
/// hostname/IP. URLs → host[:port]; bare hostnames/IPs → as-is.
pub fn target_fingerprint(url: Option<&str>, fallback_target: Option<&str>) -> String {
    if let Some(u) = url {
        if let Ok(parsed) = url::Url::parse(u) {
            if let Some(host) = parsed.host_str() {
                let port = parsed.port();
                return match port {
                    Some(p) => format!("{host}:{p}"),
                    None => host.to_string(),
                };
            }
        }
    }
    fallback_target.unwrap_or("unknown").to_string()
}

/// Find or create a dedup group for a finding. Idempotent.
pub async fn find_or_create_group(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    plugin_id: &str,
    title: &str,
    target_fingerprint: &str,
) -> DbResult<FindingGroupRow> {
    let title_norm = normalize_title(title);
    // Try to find existing.
    if let Some(row) = sqlx::query_as::<_, FindingGroupRow>(
        "SELECT * FROM finding_groups
         WHERE workspace_id IS ?
           AND plugin_id = ?
           AND title_norm = ?
           AND target_fingerprint = ?",
    )
    .bind(workspace_id)
    .bind(plugin_id)
    .bind(&title_norm)
    .bind(target_fingerprint)
    .fetch_optional(db)
    .await?
    {
        return Ok(row);
    }
    // Create new.
    let id = new_id();
    let now_ts = now();
    sqlx::query(
        "INSERT INTO finding_groups (id, workspace_id, plugin_id, title_norm, target_fingerprint, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(plugin_id)
    .bind(&title_norm)
    .bind(target_fingerprint)
    .bind(&now_ts)
    .execute(db)
    .await?;
    sqlx::query_as::<_, FindingGroupRow>("SELECT * FROM finding_groups WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

/// Set the group_id on a finding.
pub async fn attach_finding_to_group(
    db: &SqlitePool,
    finding_id: &str,
    group_id: &str,
) -> DbResult<()> {
    sqlx::query("UPDATE findings SET group_id = ? WHERE id = ?")
        .bind(group_id)
        .bind(finding_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Propagate a status change to every finding in the same group.
pub async fn propagate_status_to_group(
    db: &SqlitePool,
    group_id: &str,
    new_status: &str,
) -> DbResult<u64> {
    let result = sqlx::query("UPDATE findings SET analyst_status = ? WHERE group_id = ?")
        .bind(new_status)
        .bind(group_id)
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}

// --- FP memory ---

pub async fn remember_false_positive(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    plugin_id: &str,
    title: &str,
    target_fingerprint: &str,
    decided_by: &str,
    reason: Option<&str>,
) -> DbResult<FpMemoryRow> {
    let title_norm = normalize_title(title);
    let id = new_id();
    let now_ts = now();
    // Upsert: if a row exists, update decided_by/at/reason.
    sqlx::query(
        "INSERT INTO fp_memory (id, workspace_id, plugin_id, title_norm, target_fingerprint,
                                decided_by, decided_at, reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(workspace_id, plugin_id, title_norm, target_fingerprint)
         DO UPDATE SET decided_by = excluded.decided_by,
                       decided_at = excluded.decided_at,
                       reason = excluded.reason",
    )
    .bind(&id)
    .bind(workspace_id)
    .bind(plugin_id)
    .bind(&title_norm)
    .bind(target_fingerprint)
    .bind(decided_by)
    .bind(&now_ts)
    .bind(reason)
    .execute(db)
    .await?;
    sqlx::query_as::<_, FpMemoryRow>(
        "SELECT * FROM fp_memory
         WHERE workspace_id IS ?
           AND plugin_id = ?
           AND title_norm = ?
           AND target_fingerprint = ?",
    )
    .bind(workspace_id)
    .bind(plugin_id)
    .bind(&title_norm)
    .bind(target_fingerprint)
    .fetch_one(db)
    .await
    .map_err(Into::into)
}

/// Check if a (plugin_id, title, target_fingerprint) tuple is remembered
/// as a false positive. Used at finding-insert time to auto-mark.
pub async fn is_remembered_false_positive(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    plugin_id: &str,
    title: &str,
    target_fingerprint: &str,
) -> DbResult<Option<FpMemoryRow>> {
    let title_norm = normalize_title(title);
    sqlx::query_as::<_, FpMemoryRow>(
        "SELECT * FROM fp_memory
         WHERE workspace_id IS ?
           AND plugin_id = ?
           AND title_norm = ?
           AND target_fingerprint = ?",
    )
    .bind(workspace_id)
    .bind(plugin_id)
    .bind(&title_norm)
    .bind(target_fingerprint)
    .fetch_optional(db)
    .await
    .map_err(Into::into)
}

pub async fn forget_false_positive(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    plugin_id: &str,
    title: &str,
    target_fingerprint: &str,
) -> DbResult<()> {
    let title_norm = normalize_title(title);
    sqlx::query(
        "DELETE FROM fp_memory
         WHERE workspace_id IS ?
           AND plugin_id = ?
           AND title_norm = ?
           AND target_fingerprint = ?",
    )
    .bind(workspace_id)
    .bind(plugin_id)
    .bind(&title_norm)
    .bind(target_fingerprint)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_whitespace_and_lowercases() {
        assert_eq!(normalize_title("  SQL   Injection "), "sql injection");
        assert_eq!(normalize_title("XSS"), "xss");
    }

    #[test]
    fn target_fingerprint_extracts_host_from_url() {
        assert_eq!(
            target_fingerprint(Some("http://example.com:8080/path"), None),
            "example.com:8080"
        );
        assert_eq!(
            target_fingerprint(Some("https://example.com/"), None),
            "example.com"
        );
        assert_eq!(target_fingerprint(None, Some("1.2.3.4")), "1.2.3.4");
        assert_eq!(target_fingerprint(None, None), "unknown");
    }
}
