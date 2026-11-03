//! Collaboration HTTP routes — workspace members + finding comments + mentions.

use crate::access::{require_workspace, WorkspacePermission};
use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        // workspace members
        .route(
            "/workspaces/:id/members",
            axum::routing::get(list_members).post(add_member),
        )
        .route(
            "/workspaces/:id/members/:user_id",
            axum::routing::delete(remove_member),
        )
        // finding comments
        .route(
            "/findings/:id/comments",
            axum::routing::get(list_comments).post(add_comment),
        )
        // mentions
        .route("/mentions", axum::routing::get(list_mentions))
        .route("/mentions/:id/read", axum::routing::post(mark_mention_read))
}

// --- workspace members -----------------------------------------------------

fn member_to_json(m: &secuscan_db::models::WorkspaceMemberRow) -> Value {
    json!({
        "workspace_id": m.workspace_id,
        "user_id": m.user_id,
        "role": m.role,
        "added_at": m.added_at,
        "added_by": m.added_by,
    })
}

async fn list_members(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_workspace(&state, &_user, &id, WorkspacePermission::Read).await?;
    let rows = secuscan_db::repo::collab::list_members(&state.db, &id).await?;
    Ok(Json(json!({
        "items": rows.iter().map(member_to_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct AddMemberRequest {
    user_id: String,
    role: String,
}

async fn add_member(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if !["owner", "editor", "viewer"].contains(&req.role.as_str()) {
        return Err(ApiError::BadRequest(
            "role must be one of owner/editor/viewer".into(),
        ));
    }
    require_workspace(&state, &user, &id, WorkspacePermission::Manage).await?;
    // Verify the target user exists.
    secuscan_db::repo::users::find_by_id(&state.db, &req.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("user {}", req.user_id)))?;
    let row =
        secuscan_db::repo::collab::add_member(&state.db, &id, &req.user_id, &req.role, &user.0.id)
            .await?;
    Ok((StatusCode::CREATED, Json(member_to_json(&row))))
}

async fn remove_member(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path((id, user_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    require_workspace(&state, &user, &id, WorkspacePermission::Manage).await?;
    secuscan_db::repo::collab::remove_member(&state.db, &id, &user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- finding comments ------------------------------------------------------

fn comment_to_json(c: &secuscan_db::models::FindingCommentRow) -> Value {
    json!({
        "id": c.id,
        "finding_id": c.finding_id,
        "author_id": c.author_id,
        "body": c.body,
        "kind": c.kind,
        "created_at": c.created_at,
    })
}

#[derive(Deserialize)]
struct AddCommentRequest {
    body: String,
}

async fn list_comments(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    crate::routes::findings::load_finding_for_user(&state, &_user, &id).await?;
    let rows = secuscan_db::repo::collab::list_comments(&state.db, &id).await?;
    Ok(Json(json!({
        "items": rows.iter().map(comment_to_json).collect::<Vec<_>>(),
    })))
}

async fn add_comment(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<AddCommentRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if req.body.trim().is_empty() || req.body.len() > 4_000 {
        return Err(ApiError::BadRequest(
            "body must be 1..=4000 characters".into(),
        ));
    }
    // Verify the finding is visible, not merely present in the database.
    let finding = crate::routes::findings::load_finding_for_user(&state, &user, &id).await?;
    let task = secuscan_db::repo::tasks::get(&state.db, &finding.task_id).await?;
    crate::access::require_resource(
        &state,
        &user,
        task.workspace_id.as_deref(),
        &task.user_id,
        WorkspacePermission::Write,
    )
    .await?;
    let row =
        secuscan_db::repo::collab::add_comment(&state.db, &id, &user.0.id, &req.body, "comment")
            .await?;

    // Parse @mentions and record them. Mentions are @email or @name; we look
    // up by email first, then by exact name match.
    let mentions = parse_mentions(&req.body);
    for m in mentions {
        let target = secuscan_db::repo::users::find_by_email(&state.db, &m)
            .await
            .ok()
            .flatten();
        let target = match target {
            Some(u) => u,
            None => match secuscan_db::repo::users::find_by_name(&state.db, &m).await {
                Ok(Some(u)) => u,
                _ => continue,
            },
        };
        if target.id == user.0.id {
            continue; // don't mention yourself
        }
        let _ =
            secuscan_db::repo::collab::add_mention(&state.db, &row.id, &target.id, &id, None).await;
    }
    Ok((StatusCode::CREATED, Json(comment_to_json(&row))))
}

/// Extract @-mentions from a comment body. Returns the strings (without @).
fn parse_mentions(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric()
                    || bytes[end] == b'.'
                    || bytes[end] == b'_'
                    || bytes[end] == b'-'
                    || bytes[end] == b'@')
            {
                end += 1;
            }
            if end > start {
                if let Ok(s) = std::str::from_utf8(&bytes[start..end]) {
                    if s.contains('@') || s.len() >= 2 {
                        out.push(s.to_string());
                    }
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

// --- mentions --------------------------------------------------------------

#[derive(Deserialize, Default)]
struct MentionQuery {
    #[serde(default)]
    unread_only: Option<bool>,
    #[serde(default)]
    limit: Option<u32>,
}

async fn list_mentions(
    State(state): State<SharedState>,
    user: CurrentUser,
    Query(q): Query<MentionQuery>,
) -> ApiResult<Json<Value>> {
    let unread = q.unread_only.unwrap_or(false);
    let limit = q.limit.unwrap_or(50);
    let rows =
        secuscan_db::repo::collab::list_mentions_for_user(&state.db, &user.0.id, unread, limit)
            .await?;
    Ok(Json(json!({
        "items": rows.iter().map(|m| json!({
            "id": m.id,
            "comment_id": m.comment_id,
            "mentioned_user_id": m.mentioned_user_id,
            "finding_id": m.finding_id,
            "workspace_id": m.workspace_id,
            "read_at": m.read_at,
            "created_at": m.created_at,
        })).collect::<Vec<_>>(),
    })))
}

async fn mark_mention_read(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    // The mention row ID is not an authorization credential. Only its
    // intended recipient (or an admin) may mark it read.
    let owner: Option<(String,)> =
        sqlx::query_as("SELECT mentioned_user_id FROM mentions WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiError::Internal(format!("mention lookup: {e}")))?;
    let (recipient,) = owner.ok_or_else(|| ApiError::NotFound("not found".into()))?;
    if !user.is_admin() && recipient != user.0.id {
        return Err(ApiError::NotFound("not found".into()));
    }
    secuscan_db::repo::collab::mark_mention_read(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mentions_extracts_email_style() {
        let body = "hey @alice@example.com can you check this? also ping @bob";
        let m = parse_mentions(body);
        assert!(m.contains(&"alice@example.com".to_string()));
        assert!(m.contains(&"bob".to_string()));
    }

    #[test]
    fn parse_mentions_ignores_lone_at() {
        assert!(parse_mentions("just @ here").is_empty());
        assert!(parse_mentions("no mentions").is_empty());
    }
}
