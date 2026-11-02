//! Pentest Robots HTTP routes — CRUD + run + built-in seeding.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::robot_runtime::{self, RobotGraph, RobotNode};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/robots", axum::routing::get(list).post(create))
        .route("/robots/builtin", axum::routing::get(list_builtins))
        .route(
            "/robots/:id",
            axum::routing::get(get_one).patch(update).delete(delete),
        )
        .route("/robots/:id/run", axum::routing::post(run))
        .route("/robots/runs/:run_id", axum::routing::get(get_run))
        .route(
            "/robots/runs/:run_id/cancel",
            axum::routing::post(cancel_run),
        )
}

#[derive(Deserialize)]
struct CreateRobotRequest {
    name: String,
    #[serde(default)]
    description: String,
    nodes: Vec<RobotNode>,
    #[serde(default)]
    edges: Vec<robot_runtime::RobotEdge>,
}

fn graph_to_json(nodes: &[RobotNode], edges: &[robot_runtime::RobotEdge]) -> (String, String) {
    let nodes_json = serde_json::to_string(nodes).unwrap_or_else(|_| "[]".into());
    let edges_json = serde_json::to_string(edges).unwrap_or_else(|_| "[]".into());
    (nodes_json, edges_json)
}

fn robot_to_json(r: &secuscan_db::models::RobotRow) -> Value {
    json!({
        "id": r.id,
        "name": r.name,
        "description": r.description,
        "nodes": serde_json::from_str::<Value>(&r.nodes_json).unwrap_or(json!([])),
        "edges": serde_json::from_str::<Value>(&r.edges_json).unwrap_or(json!([])),
        "source": r.source,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    })
}

fn run_to_json(r: &secuscan_db::models::RobotRunRow) -> Value {
    json!({
        "id": r.id,
        "robot_id": r.robot_id,
        "workspace_id": r.workspace_id,
        "status": r.status,
        "state": serde_json::from_str::<Value>(&r.state_json).unwrap_or(json!({})),
        "targets": serde_json::from_str::<Value>(&r.targets_json).unwrap_or(json!([])),
        "error": r.error,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "finished_at": r.finished_at,
    })
}

async fn list(State(state): State<SharedState>, _user: CurrentUser) -> ApiResult<Json<Value>> {
    let rows = repo::robots::list(&state.db).await?;
    Ok(Json(json!({
        "items": rows.iter().map(robot_to_json).collect::<Vec<_>>(),
    })))
}

async fn list_builtins(
    State(_state): State<SharedState>,
    _user: CurrentUser,
) -> ApiResult<Json<Value>> {
    let items: Vec<Value> = robot_runtime::builtin_robots()
        .iter()
        .map(|(name, desc, graph)| {
            json!({
                "name": name,
                "description": desc,
                "graph": serde_json::from_str::<Value>(graph).unwrap_or(json!({})),
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateRobotRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if req.name.trim().is_empty() || req.name.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 1..=120 characters".into(),
        ));
    }
    let graph = RobotGraph {
        nodes: req.nodes,
        edges: req.edges,
    };
    robot_runtime::validate(&graph)
        .map_err(|e| ApiError::BadRequest(format!("invalid robot graph: {e}")))?;
    let (nodes_json, edges_json) = graph_to_json(&graph.nodes, &graph.edges);
    let row = repo::robots::create(
        &state.db,
        &req.name,
        &req.description,
        &nodes_json,
        &edges_json,
        "user",
        &user.0.id,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(robot_to_json(&row))))
}

async fn get_one(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = repo::robots::get(&state.db, &id).await?;
    let runs = repo::robots::list_runs(&state.db, &id).await?;
    Ok(Json(json!({
        "robot": robot_to_json(&row),
        "runs": runs.iter().map(run_to_json).collect::<Vec<_>>(),
    })))
}

async fn update(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<CreateRobotRequest>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let existing = repo::robots::get(&state.db, &id).await?;
    if existing.source == "builtin" {
        return Err(ApiError::Forbidden(
            "builtin robots cannot be edited".into(),
        ));
    }
    if !user.is_admin() && existing.created_by != user.0.id {
        return Err(ApiError::Forbidden(
            "only the creator or an admin can edit".into(),
        ));
    }
    let graph = RobotGraph {
        nodes: req.nodes,
        edges: req.edges,
    };
    robot_runtime::validate(&graph)
        .map_err(|e| ApiError::BadRequest(format!("invalid robot graph: {e}")))?;
    let (nodes_json, edges_json) = graph_to_json(&graph.nodes, &graph.edges);
    repo::robots::update(
        &state.db,
        &id,
        &req.name,
        &req.description,
        &nodes_json,
        &edges_json,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let existing = repo::robots::get(&state.db, &id).await?;
    if existing.source == "builtin" {
        return Err(ApiError::Forbidden(
            "builtin robots cannot be deleted".into(),
        ));
    }
    if !user.is_admin() && existing.created_by != user.0.id {
        return Err(ApiError::Forbidden(
            "only the creator or an admin can delete".into(),
        ));
    }
    repo::robots::delete(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RunRobotRequest {
    /// Initial seed targets for the robot's source nodes.
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    workspace_id: Option<String>,
    /// Optional auth profile to attach to all tool nodes.
    #[serde(default)]
    auth_profile_id: Option<String>,
}

async fn run(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<RunRobotRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let robot = repo::robots::get(&state.db, &id).await?;
    if req.targets.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one target is required".into(),
        ));
    }
    if let Some(ws) = &req.workspace_id {
        repo::workspaces::get_workspace(&state.db, ws).await?;
    }
    if let Some(pid) = &req.auth_profile_id {
        repo::auth_profiles::get(&state.db, pid).await?;
    }
    let targets_json = serde_json::to_string(&req.targets).unwrap_or_else(|_| "[]".into());
    let run_row = repo::robots::create_run(
        &state.db,
        &robot.id,
        req.workspace_id.as_deref(),
        &targets_json,
        &user.0.id,
    )
    .await?;

    let state2 = state.clone();
    let user2 = user.clone();
    let run_id = run_row.id.clone();
    let ws_id = req.workspace_id.clone();
    let auth_id = req.auth_profile_id.clone();
    let targets = req.targets.clone();
    let robot_id = robot.id.clone();
    tokio::spawn(async move {
        let result = robot_runtime::run(
            &state2,
            &user2,
            &robot_id,
            &run_id,
            ws_id.as_deref(),
            auth_id.as_deref(),
            targets,
        )
        .await;
        match result {
            Ok(()) => {
                let _ = repo::robots::finish_run(&state2.db, &run_id, "completed", None).await;
            }
            Err(e) => {
                tracing::error!("robot run {run_id} failed: {e}");
                let _ = repo::robots::finish_run(&state2.db, &run_id, "failed", Some(&e)).await;
            }
        }
    });

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "run_id": run_row.id,
            "robot_id": robot.id,
            "status": "running",
        })),
    ))
}

async fn get_run(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(run_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let run = repo::robots::get_run(&state.db, &run_id).await?;
    Ok(Json(run_to_json(&run)))
}

async fn cancel_run(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(run_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let run = repo::robots::get_run(&state.db, &run_id).await?;
    let robot = repo::robots::get(&state.db, &run.robot_id).await?;
    if !user.is_admin() && robot.created_by != user.0.id {
        return Err(ApiError::Forbidden(
            "only the creator or an admin can cancel".into(),
        ));
    }
    // Cancel every task attached to this run.
    let tasks = secuscan_db::repo::tasks::list(
        &state.db,
        &secuscan_db::repo::tasks::TaskListFilters {
            limit: 500,
            ..Default::default()
        },
    )
    .await?;
    let mut cancelled = 0;
    for t in tasks {
        // Filter to those with this robot_run_id (the repo doesn't expose a filter for it yet).
        let has_robot: Option<(Option<String>,)> =
            sqlx::query_as("SELECT robot_run_id FROM tasks WHERE id = ?")
                .bind(&t.id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?;
        if let Some((Some(rid),)) = has_robot {
            if rid == run_id && !t.status().is_terminal() && state.tasks.cancel(&t.id).await {
                cancelled += 1;
            }
        }
    }
    repo::robots::finish_run(&state.db, &run_id, "cancelled", None).await?;
    Ok(Json(json!({ "cancelled_tasks": cancelled })))
}

/// Seed builtin robots on first startup. Idempotent.
pub async fn seed_builtins(state: &SharedState) -> sqlx::Result<()> {
    // Find an admin user to attribute the builtins to (FK constraint on
    // robots.created_by). Falls back to any user if no admin exists yet.
    let owner_id: Option<(String,)> =
        sqlx::query_as("SELECT id FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1")
            .fetch_optional(&state.db)
            .await?;
    let owner_id = match owner_id {
        Some((id,)) => id,
        None => {
            tracing::warn!("builtin robot seeding skipped: no admin user exists yet");
            return Ok(());
        }
    };
    for (name, desc, graph_json) in robot_runtime::builtin_robots() {
        // Check if a builtin with this name already exists.
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM robots WHERE name = ? AND source = 'builtin'")
                .bind(name)
                .fetch_optional(&state.db)
                .await?;
        if existing.is_some() {
            continue;
        }
        let graph: RobotGraph = serde_json::from_str(graph_json).unwrap_or_else(|e| {
            tracing::error!("builtin robot `{name}` not parseable: {e}");
            RobotGraph {
                nodes: vec![],
                edges: vec![],
            }
        });
        let (nodes_json, edges_json) = graph_to_json(&graph.nodes, &graph.edges);
        if let Err(e) = repo::robots::create(
            &state.db,
            name,
            desc,
            &nodes_json,
            &edges_json,
            "builtin",
            &owner_id,
        )
        .await
        {
            tracing::warn!("failed to seed builtin robot `{name}`: {e}");
        }
    }
    Ok(())
}
