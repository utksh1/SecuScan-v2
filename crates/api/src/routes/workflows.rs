//! Workflows: ordered plugin chains, sequential execution, run history.

use crate::access::{require_workspace, WorkspacePermission};
use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::tasks::{validate_and_create_task, StartTaskRequest};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_core::models::TaskStatus;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/workflows", axum::routing::post(create))
        .route("/workflows", axum::routing::get(list))
        .route("/workflows/:id", axum::routing::get(get_one))
        .route("/workflows/:id", axum::routing::patch(update))
        .route("/workflows/:id", axum::routing::delete(delete))
        .route("/workflows/:id/run", axum::routing::post(run))
        .route("/workflows/:id/runs", axum::routing::get(list_runs))
        .route(
            "/workflows/runs/:run_id/cancel",
            axum::routing::post(cancel_run),
        )
}

#[derive(Deserialize)]
struct WorkflowStepDto {
    plugin_id: String,
    #[serde(default)]
    inputs: BTreeMap<String, Value>,
    #[serde(default)]
    preset: Option<String>,
    /// Human label shown in run history.
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct CreateWorkflowRequest {
    name: String,
    #[serde(default)]
    description: String,
    steps: Vec<WorkflowStepDto>,
}

async fn validate_steps(state: &SharedState, steps: &[WorkflowStepDto]) -> ApiResult<()> {
    if steps.is_empty() || steps.len() > 32 {
        return Err(ApiError::BadRequest(
            "workflows must have 1..=32 steps".into(),
        ));
    }
    let registry = state.registry.read().await;
    for (i, s) in steps.iter().enumerate() {
        if registry.get(&s.plugin_id).is_none() {
            return Err(ApiError::BadRequest(format!(
                "step {}: unknown plugin `{}`",
                i + 1,
                s.plugin_id
            )));
        }
    }
    Ok(())
}

fn steps_to_json(steps: &[WorkflowStepDto]) -> String {
    serde_json::to_string(
        &steps
            .iter()
            .map(|s| {
                json!({
                    "plugin_id": s.plugin_id,
                    "inputs": s.inputs,
                    "preset": s.preset,
                    "label": s.label,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".into())
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateWorkflowRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if req.name.trim().is_empty() || req.name.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 1..=120 characters".into(),
        ));
    }
    validate_steps(&state, &req.steps).await?;
    let row = repo::workflows::create(
        &state.db,
        &req.name,
        &req.description,
        &steps_to_json(&req.steps),
        &user.0.id,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(workflow_to_json(&row))))
}

fn workflow_to_json(w: &secuscan_db::models::WorkflowRow) -> Value {
    json!({
        "id": w.id,
        "name": w.name,
        "description": w.description,
        "steps": serde_json::from_str::<Value>(&w.steps_json).unwrap_or(json!([])),
        "created_by": w.created_by,
        "created_at": w.created_at,
        "updated_at": w.updated_at,
    })
}

async fn list(State(state): State<SharedState>, _user: CurrentUser) -> ApiResult<Json<Value>> {
    let rows = repo::workflows::list(&state.db).await?;
    Ok(Json(json!({
        "items": rows.iter().map(workflow_to_json).collect::<Vec<_>>(),
    })))
}

async fn get_one(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = repo::workflows::get(&state.db, &id).await?;
    let runs = repo::workflows::list_runs(&state.db, &id).await?;
    let mut visible_runs = Vec::new();
    for run in &runs {
        if workflow_run_visible(&state, &_user, run).await? {
            visible_runs.push(run_to_json(run));
        }
    }
    Ok(Json(json!({
        "workflow": workflow_to_json(&row),
        "runs": visible_runs,
    })))
}

fn run_to_json(r: &secuscan_db::models::WorkflowRunRow) -> Value {
    json!({
        "id": r.id,
        "workflow_id": r.workflow_id,
        "created_by": r.created_by,
        "workspace_id": r.workspace_id,
        "status": r.status,
        "task_ids": serde_json::from_str::<Value>(&r.task_ids_json).unwrap_or(json!([])),
        "error": r.error,
        "created_at": r.created_at,
        "finished_at": r.finished_at,
    })
}

async fn update(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<CreateWorkflowRequest>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    // Only the creator or an admin may edit.
    let existing = repo::workflows::get(&state.db, &id).await?;
    if !user.is_admin() && existing.created_by != user.0.id {
        return Err(ApiError::Forbidden(
            "only the creator or an admin can edit".into(),
        ));
    }
    validate_steps(&state, &req.steps).await?;
    repo::workflows::update(
        &state.db,
        &id,
        &req.name,
        &req.description,
        &steps_to_json(&req.steps),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let existing = repo::workflows::get(&state.db, &id).await?;
    if !user.is_admin() && existing.created_by != user.0.id {
        return Err(ApiError::Forbidden(
            "only the creator or an admin can delete".into(),
        ));
    }
    repo::workflows::delete(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct RunRequest {
    /// Workspace the workflow's tasks should be attached to.
    #[serde(default)]
    workspace_id: Option<String>,
}

async fn run(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    body: Option<Json<RunRequest>>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let wf = repo::workflows::get(&state.db, &id).await?;
    let steps: Vec<WorkflowStepDto> = serde_json::from_str(&wf.steps_json)
        .map_err(|_| ApiError::Internal("corrupt workflow steps".into()))?;
    // Validate before creating the run so an unknown workspace is a clean 404.
    let workspace_id = match body.map(|Json(b)| b).unwrap_or_default().workspace_id {
        Some(ws) => {
            require_workspace(&state, &user, &ws, WorkspacePermission::Write).await?;
            Some(ws)
        }
        None => None,
    };
    let run_row =
        repo::workflows::create_run(&state.db, &id, &user.0.id, workspace_id.as_deref()).await?;
    let run_id_spawn = run_row.id.clone();

    let state2 = state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_workflow(
            &state2,
            &user,
            &steps,
            &run_id_spawn,
            workspace_id.as_deref(),
        )
        .await
        {
            tracing::error!("workflow run {} failed: {e}", run_id_spawn);
            let _ = repo::workflows::finish_run(
                &state2.db,
                &run_id_spawn,
                TaskStatus::Failed,
                Some(&e),
            )
            .await;
        }
    });

    Ok((
        StatusCode::CREATED,
        Json(json!({ "run_id": run_row.id, "workflow_id": id })),
    ))
}

/// Sequential execution: each step runs to a terminal state before the next.
/// A failed step aborts the chain (documented behaviour).
async fn run_workflow(
    state: &SharedState,
    user: &CurrentUser,
    steps: &[WorkflowStepDto],
    run_id: &str,
    workspace_id: Option<&str>,
) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        let req = StartTaskRequest {
            plugin_id: step.plugin_id.clone(),
            inputs: step.inputs.clone(),
            preset: step.preset.clone(),
            // Starting a workflow implies consent for its steps.
            consent_granted: true,
            workspace_id: workspace_id.map(str::to_string),
            auth_profile_id: None,
        };
        let (task, manifest, inputs) =
            validate_and_create_task(state, user, &req, Some(run_id), None)
                .await
                .map_err(|e| format!("step {} ({}) rejected: {e}", i + 1, step.plugin_id))?;
        repo::workflows::append_run_task(&state.db, run_id, &task.id)
            .await
            .map_err(|e| e.to_string())?;
        state.tasks.spawn(task.clone(), manifest, inputs).await;

        // Await terminal state (bounded by the plugin timeout + slack).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(86400);
        loop {
            let t = repo::tasks::get(&state.db, &task.id)
                .await
                .map_err(|e| e.to_string())?;
            if t.status().is_terminal() {
                if t.status() != TaskStatus::Completed {
                    return Err(format!(
                        "step {} ({}) ended with status `{}`: {}",
                        i + 1,
                        step.plugin_id,
                        t.status().label(),
                        t.error.unwrap_or_default()
                    ));
                }
                break;
            }
            if std::time::Instant::now() >= deadline {
                state.tasks.cancel(&task.id).await;
                return Err(format!(
                    "step {} ({}) exceeded the 24h execution bound",
                    i + 1,
                    step.plugin_id
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    repo::workflows::finish_run(&state.db, run_id, TaskStatus::Completed, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn workflow_run_visible(
    state: &SharedState,
    user: &CurrentUser,
    run: &secuscan_db::models::WorkflowRunRow,
) -> ApiResult<bool> {
    if user.is_admin() {
        return Ok(true);
    }
    match run.workspace_id.as_deref() {
        None => Ok(run.created_by.as_deref() == Some(user.0.id.as_str())),
        Some(ws) => {
            if !crate::access::workspace_visible(state, user, ws).await? {
                return Ok(false);
            }
            let row = repo::workspaces::get_workspace(&state.db, ws).await?;
            // Shared template runs have historically been per-user; private
            // workspace members can review execution history as a team.
            Ok(row.access_mode == "private"
                || run.created_by.as_deref() == Some(user.0.id.as_str()))
        }
    }
}

async fn list_runs(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let runs = repo::workflows::list_runs(&state.db, &id).await?;
    let mut items = Vec::new();
    for run in &runs {
        if workflow_run_visible(&state, &user, run).await? {
            items.push(run_to_json(run));
        }
    }
    Ok(Json(json!({"items": items})))
}

async fn cancel_run(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(run_id): Path<String>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    let run = sqlx::query_as::<_, secuscan_db::models::WorkflowRunRow>(
        "SELECT * FROM workflow_runs WHERE id = ?",
    )
    .bind(&run_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("workflow run lookup: {e}")))?
    .ok_or_else(|| ApiError::NotFound("not found".into()))?;
    if !user.is_admin() && run.created_by.as_deref() != Some(user.0.id.as_str()) {
        return Err(ApiError::NotFound("not found".into()));
    }
    if let Some(ws) = run.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    // Cancel every task of this run that is still active.
    let tasks = repo::tasks::list(
        &state.db,
        &repo::tasks::TaskListFilters {
            workflow_run_id: Some(run_id.clone()),
            limit: 500,
            ..Default::default()
        },
    )
    .await?;
    let mut cancelled = 0;
    for t in tasks {
        if !t.status().is_terminal() && state.tasks.cancel(&t.id).await {
            cancelled += 1;
        }
    }
    repo::workflows::finish_run(&state.db, &run_id, TaskStatus::Cancelled, None).await?;
    Ok(Json(json!({ "cancelled_tasks": cancelled })))
}
