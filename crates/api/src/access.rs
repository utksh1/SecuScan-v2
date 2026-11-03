//! Centralized workspace/resource authorization.
//!
//! Legacy single-team workspaces retain shared access. New workspaces are
//! private; creator is owner, invited members are editor or viewer. Admins
//! bypass workspace membership. Global viewer accounts never mutate.
//! Unauthorized object IDs produce a uniform 404, preventing enumeration.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use secuscan_db::repo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspacePermission {
    Read,
    Write,
    Manage,
}

fn hidden() -> ApiError {
    ApiError::NotFound("not found".into())
}

pub fn is_owner_or_admin(user: &CurrentUser, created_by: &str) -> bool {
    user.is_admin() || created_by == user.0.id
}

pub fn require_owner(user: &CurrentUser, created_by: &str) -> ApiResult<()> {
    if is_owner_or_admin(user, created_by) {
        Ok(())
    } else {
        Err(hidden())
    }
}

/// The authoritative check shared by workspace-scoped routes.
pub async fn require_workspace(
    state: &SharedState,
    user: &CurrentUser,
    workspace_id: &str,
    permission: WorkspacePermission,
) -> ApiResult<()> {
    let ws = repo::workspaces::get_workspace(&state.db, workspace_id)
        .await
        .map_err(|e| match e {
            secuscan_db::DbError::NotFound(_) => hidden(),
            other => ApiError::from(other),
        })?;

    if user.is_admin() {
        return Ok(());
    }
    if ws.access_mode == "shared" {
        return match permission {
            WorkspacePermission::Read => Ok(()),
            WorkspacePermission::Write if user.0.role != "viewer" => Ok(()),
            WorkspacePermission::Manage if ws.created_by == user.0.id => Ok(()),
            _ => Err(hidden()),
        };
    }
    if ws.created_by == user.0.id {
        return match permission {
            WorkspacePermission::Read | WorkspacePermission::Manage => Ok(()),
            WorkspacePermission::Write if user.0.role != "viewer" => Ok(()),
            _ => Err(hidden()),
        };
    }
    let role = repo::collab::member_role(&state.db, workspace_id, &user.0.id).await?;
    match (permission, role.as_deref()) {
        (WorkspacePermission::Read, Some("owner" | "editor" | "viewer")) => Ok(()),
        (WorkspacePermission::Write, Some("owner" | "editor"))
            if user.0.role != "viewer" =>
        {
            Ok(())
        }
        _ => Err(hidden()),
    }
}

/// Enforce the workspace policy and retain the old per-user isolation for
/// globally shared workspaces and Personal resources. Private members may
/// collaborate on other members' workspace tasks/findings when authorized.
pub async fn require_resource(
    state: &SharedState,
    user: &CurrentUser,
    workspace_id: Option<&str>,
    created_by: &str,
    permission: WorkspacePermission,
) -> ApiResult<()> {
    match workspace_id {
        None => require_owner(user, created_by),
        Some(id) => {
            require_workspace(state, user, id, permission).await?;
            let ws = repo::workspaces::get_workspace(&state.db, id).await?;
            if ws.access_mode == "shared" {
                require_owner(user, created_by)?;
            }
            Ok(())
        }
    }
}

pub async fn workspace_visible(
    state: &SharedState,
    user: &CurrentUser,
    workspace_id: &str,
) -> ApiResult<bool> {
    match require_workspace(state, user, workspace_id, WorkspacePermission::Read).await {
        Ok(()) => Ok(true),
        Err(ApiError::NotFound(_)) => Ok(false),
        Err(e) => Err(e),
    }
}
