//! Collaboration: workspace members + finding comments + mentions.

use crate::models::{FindingCommentRow, MentionRow, WorkspaceMemberRow};
use crate::new_id;
use crate::DbResult;
use sqlx::SqlitePool;

// --- workspace members -----------------------------------------------------

pub async fn add_member(
    db: &SqlitePool,
    workspace_id: &str,
    user_id: &str,
    role: &str,
    added_by: &str,
) -> DbResult<WorkspaceMemberRow> {
    let now = crate::now();
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, role, added_at, added_by)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role",
    )
    .bind(workspace_id)
    .bind(user_id)
    .bind(role)
    .bind(&now)
    .bind(added_by)
    .execute(db)
    .await?;
    sqlx::query_as::<_, WorkspaceMemberRow>(
        "SELECT * FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
    )
    .bind(workspace_id)
    .bind(user_id)
    .fetch_one(db)
    .await
    .map_err(Into::into)
}

pub async fn remove_member(db: &SqlitePool, workspace_id: &str, user_id: &str) -> DbResult<()> {
    sqlx::query(
        "DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ? AND role != 'owner'",
    )
    .bind(workspace_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_members(
    db: &SqlitePool,
    workspace_id: &str,
) -> DbResult<Vec<WorkspaceMemberRow>> {
    sqlx::query_as::<_, WorkspaceMemberRow>(
        "SELECT * FROM workspace_members WHERE workspace_id = ? ORDER BY role, added_at",
    )
    .bind(workspace_id)
    .fetch_all(db)
    .await
    .map_err(Into::into)
}

pub async fn member_role(
    db: &SqlitePool,
    workspace_id: &str,
    user_id: &str,
) -> DbResult<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?")
            .bind(workspace_id)
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(r,)| r))
}

// --- finding comments ------------------------------------------------------

pub async fn add_comment(
    db: &SqlitePool,
    finding_id: &str,
    author_id: &str,
    body: &str,
    kind: &str,
) -> DbResult<FindingCommentRow> {
    let id = new_id();
    let now = crate::now();
    sqlx::query(
        "INSERT INTO finding_comments (id, finding_id, author_id, body, kind, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(finding_id)
    .bind(author_id)
    .bind(body)
    .bind(kind)
    .bind(&now)
    .execute(db)
    .await?;
    sqlx::query_as::<_, FindingCommentRow>("SELECT * FROM finding_comments WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_comments(db: &SqlitePool, finding_id: &str) -> DbResult<Vec<FindingCommentRow>> {
    sqlx::query_as::<_, FindingCommentRow>(
        "SELECT * FROM finding_comments WHERE finding_id = ? ORDER BY created_at",
    )
    .bind(finding_id)
    .fetch_all(db)
    .await
    .map_err(Into::into)
}

// --- mentions --------------------------------------------------------------

/// Record a mention. Caller is responsible for parsing the comment body and
/// invoking this once per `@username` found.
pub async fn add_mention(
    db: &SqlitePool,
    comment_id: &str,
    mentioned_user_id: &str,
    finding_id: &str,
    workspace_id: Option<&str>,
) -> DbResult<MentionRow> {
    let id = new_id();
    let now = crate::now();
    sqlx::query(
        "INSERT INTO mentions (id, comment_id, mentioned_user_id, finding_id, workspace_id,
                                read_at, created_at)
         VALUES (?, ?, ?, ?, ?, NULL, ?)",
    )
    .bind(&id)
    .bind(comment_id)
    .bind(mentioned_user_id)
    .bind(finding_id)
    .bind(workspace_id)
    .bind(&now)
    .execute(db)
    .await?;
    sqlx::query_as::<_, MentionRow>("SELECT * FROM mentions WHERE id = ?")
        .bind(&id)
        .fetch_one(db)
        .await
        .map_err(Into::into)
}

pub async fn list_mentions_for_user(
    db: &SqlitePool,
    user_id: &str,
    unread_only: bool,
    limit: u32,
) -> DbResult<Vec<MentionRow>> {
    let limit = limit.clamp(1, 200) as i64;
    if unread_only {
        sqlx::query_as::<_, MentionRow>(
            "SELECT * FROM mentions WHERE mentioned_user_id = ? AND read_at IS NULL
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into)
    } else {
        sqlx::query_as::<_, MentionRow>(
            "SELECT * FROM mentions WHERE mentioned_user_id = ?
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(Into::into)
    }
}

pub async fn mark_mention_read(db: &SqlitePool, mention_id: &str) -> DbResult<()> {
    let now = crate::now();
    sqlx::query("UPDATE mentions SET read_at = ? WHERE id = ?")
        .bind(&now)
        .bind(mention_id)
        .execute(db)
        .await?;
    Ok(())
}
