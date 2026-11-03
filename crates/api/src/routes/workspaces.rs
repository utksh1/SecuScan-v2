//! Workspaces + registered targets.
//!
//! Workspaces group tasks and targets into project hubs (client /
//! environment scoping). Every authenticated user can view them; the
//! scanner role is required to create or modify; deletion is admin-only.

use crate::access::{require_workspace, workspace_visible, WorkspacePermission};
use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_db::models::{TargetRow, WorkspaceRow};
use secuscan_db::repo;
use secuscan_db::repo::workspaces::WorkspaceScope;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/workspaces", axum::routing::get(list))
        .route("/workspaces", axum::routing::post(create))
        .route("/workspaces/:id", axum::routing::get(get_one))
        .route("/workspaces/:id", axum::routing::patch(update))
        .route("/workspaces/:id", axum::routing::delete(delete))
        .route("/workspaces/:id/targets", axum::routing::get(list_targets))
        .route(
            "/workspaces/:id/targets",
            axum::routing::post(create_target),
        )
        .route("/targets/:id", axum::routing::patch(update_target))
        .route("/targets/:id", axum::routing::delete(delete_target))
}

/// Parse a `workspace_id` query value into a scope. `none` selects the
/// synthetic Personal workspace; any other value must reference an
/// existing workspace (404 otherwise); absent = no filtering.
pub async fn parse_workspace_scope(
    state: &SharedState,
    user: &CurrentUser,
    raw: Option<&str>,
) -> ApiResult<WorkspaceScope> {
    match raw {
        None | Some("") => Ok(WorkspaceScope::All),
        Some("none") => Ok(WorkspaceScope::Personal),
        Some(id) => {
            require_workspace(state, user, id, WorkspacePermission::Read).await?;
            Ok(WorkspaceScope::Id(id.to_string()))
        }
    }
}

fn workspace_to_json(w: &WorkspaceRow, counts: &repo::workspaces::WorkspaceCounts) -> Value {
    json!({
        "id": w.id,
        "name": w.name,
        "description": w.description,
        "access_mode": w.access_mode,
        "created_by": w.created_by,
        "created_at": w.created_at,
        "updated_at": w.updated_at,
        "vpn_profile_id": w.vpn_profile_id,
        "tasks_total": counts.tasks_total,
        "tasks_active": counts.tasks_active,
        "targets_total": counts.targets_total,
    })
}

fn target_to_json(t: &TargetRow, stats: &repo::workspaces::TargetStats) -> Value {
    json!({
        "id": t.id,
        "workspace_id": t.workspace_id,
        "name": t.name,
        "kind": t.kind,
        "description": t.description,
        "created_by": t.created_by,
        "created_at": t.created_at,
        "scans_total": stats.scans_total,
        "last_scanned_at": stats.last_scanned_at,
    })
}

fn clean_name(raw: &str, max: usize, what: &str) -> ApiResult<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{what} name must not be empty"
        )));
    }
    if name.chars().count() > max {
        return Err(ApiError::BadRequest(format!(
            "{what} name must be at most {max} characters"
        )));
    }
    Ok(name.to_string())
}

fn validate_target_name(raw: &str) -> ApiResult<String> {
    let name = clean_name(raw, 255, "target")?;
    if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ApiError::BadRequest(
            "target name must not contain whitespace or control characters".into(),
        ));
    }
    Ok(name)
}

async fn list(State(state): State<SharedState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let workspaces = repo::workspaces::list_workspaces(&state.db).await?;
    let (counts_by_id, global_personal) = repo::workspaces::all_workspace_counts(&state.db).await?;
    let mut items = Vec::new();
    for w in &workspaces {
        if !workspace_visible(&state, &user, &w.id).await? {
            continue;
        }
        let counts = counts_by_id.get(&w.id).cloned().unwrap_or_default();
        items.push(workspace_to_json(w, &counts));
    }
    // Personal is private even when the ordinary workspace mode is shared.
    let personal = if user.is_admin() {
        global_personal
    } else {
        let (total, active): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(status IN ('queued', 'running')), 0)
             FROM tasks WHERE workspace_id IS NULL AND user_id = ?",
        )
        .bind(&user.0.id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| ApiError::Internal(format!("personal workspace counts: {e}")))?;
        repo::workspaces::WorkspaceCounts {
            tasks_total: total,
            tasks_active: active,
            targets_total: 0,
        }
    };
    Ok(Json(json!({
        "items": items,
        "personal": {
            "id": null,
            "name": "Personal",
            "tasks_total": personal.tasks_total,
            "tasks_active": personal.tasks_active,
        },
    })))
}

#[derive(Deserialize)]
struct CreateWorkspaceRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// New workspaces are private by default. Admins may explicitly create
    /// shared single-team workspaces for legacy collaboration.
    #[serde(default)]
    pub access_mode: Option<String>,
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateWorkspaceRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let mode = req.access_mode.as_deref().unwrap_or("private");
    if !["shared", "private"].contains(&mode) {
        return Err(ApiError::BadRequest("access_mode must be shared or private".into()));
    }
    if mode == "shared" {
        user.require_admin()?;
    }
    let name = clean_name(&req.name, 100, "workspace")?;
    let description = req
        .description
        .trim()
        .chars()
        .take(2000)
        .collect::<String>();
    let row = repo::workspaces::create_workspace(
        &state.db,
        repo::workspaces::NewWorkspace {
            name: &name,
            description: &description,
            created_by: &user.0.id,
        },
    )
    .await?;
    if mode == "shared" {
        sqlx::query("UPDATE workspaces SET access_mode = 'shared' WHERE id = ?")
            .bind(&row.id).execute(&state.db).await
            .map_err(|e| ApiError::Internal(format!("workspace mode: {e}")))?;
    }
    let row = repo::workspaces::get_workspace(&state.db, &row.id).await?;
    let counts = repo::workspaces::workspace_counts(&state.db, &row.id).await?;
    Ok((StatusCode::CREATED, Json(workspace_to_json(&row, &counts))))
}

async fn get_one(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_workspace(&state, &_user, &id, WorkspacePermission::Read).await?;
    let w = repo::workspaces::get_workspace(&state.db, &id).await?;
    let counts = repo::workspaces::workspace_counts(&state.db, &id).await?;
    Ok(Json(workspace_to_json(&w, &counts)))
}

#[derive(Deserialize)]
struct UpdateWorkspaceRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

async fn update(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateWorkspaceRequest>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    require_workspace(&state, &user, &id, WorkspacePermission::Write).await?;
    let name = match req.name {
        Some(raw) => Some(clean_name(&raw, 100, "workspace")?),
        None => None,
    };
    let description = req
        .description
        .as_deref()
        .map(|d| d.trim().chars().take(2000).collect::<String>());
    let row = repo::workspaces::update_workspace(
        &state.db,
        &id,
        repo::workspaces::WorkspaceUpdate {
            name: name.as_deref(),
            description: description.as_deref(),
        },
    )
    .await?;
    let counts = repo::workspaces::workspace_counts(&state.db, &row.id).await?;
    Ok(Json(workspace_to_json(&row, &counts)))
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_admin()?;
    require_workspace(&state, &user, &id, WorkspacePermission::Manage).await?;
    repo::workspaces::delete_workspace(&state.db, &id)
        .await?
        .then_some(())
        .ok_or_else(|| ApiError::NotFound(format!("workspace {id}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_targets(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_workspace(&state, &_user, &id, WorkspacePermission::Read).await?;
    let targets = repo::workspaces::list_targets(&state.db, &id).await?;
    let stats = repo::workspaces::target_stats_many(&state.db, &id).await?;
    Ok(Json(json!({
        "items": targets
            .iter()
            .map(|t| {
                let ts = stats.get(&t.name).cloned().unwrap_or_default();
                target_to_json(t, &ts)
            })
            .collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct CreateTargetRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

async fn create_target(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<CreateTargetRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    require_workspace(&state, &user, &id, WorkspacePermission::Write).await?;
    let name = validate_target_name(&req.name)?;
    let description = req
        .description
        .trim()
        .chars()
        .take(2000)
        .collect::<String>();
    let row = repo::workspaces::create_target(
        &state.db,
        repo::workspaces::NewTarget {
            workspace_id: &id,
            name: &name,
            description: &description,
            created_by: &user.0.id,
        },
    )
    .await?;
    let stats = repo::workspaces::target_stats(&state.db, &row.workspace_id, &row.name).await?;
    Ok((StatusCode::CREATED, Json(target_to_json(&row, &stats))))
}

#[derive(Deserialize)]
struct UpdateTargetRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

async fn update_target(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateTargetRequest>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    let target = repo::workspaces::get_target(&state.db, &id).await?;
    require_workspace(&state, &user, &target.workspace_id, WorkspacePermission::Write).await?;
    let name = match req.name {
        Some(raw) => Some(validate_target_name(&raw)?),
        None => None,
    };
    let description = req
        .description
        .as_deref()
        .map(|d| d.trim().chars().take(2000).collect::<String>());
    let row = repo::workspaces::update_target(
        &state.db,
        &id,
        repo::workspaces::TargetUpdate {
            name: name.as_deref(),
            description: description.as_deref(),
        },
    )
    .await?;
    let stats = repo::workspaces::target_stats(&state.db, &row.workspace_id, &row.name).await?;
    Ok(Json(target_to_json(&row, &stats)))
}

async fn delete_target(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let target = repo::workspaces::get_target(&state.db, &id).await?;
    require_workspace(&state, &user, &target.workspace_id, WorkspacePermission::Write).await?;
    repo::workspaces::delete_target(&state.db, &id)
        .await?
        .then_some(())
        .ok_or_else(|| ApiError::NotFound(format!("target {id}")))?;
    Ok(StatusCode::NO_CONTENT)
}
