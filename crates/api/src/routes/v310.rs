//! v3.1.0 routes: Sniper Auto-Exploiter + VPN profiles.

use crate::access::{require_workspace, WorkspacePermission};
use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        // Sniper
        .route("/sniper/runs", axum::routing::get(list_sniper_runs))
        .route("/sniper/run", axum::routing::post(run_sniper))
        .route("/sniper/runs/:id", axum::routing::get(get_sniper_run))
        .route(
            "/sniper/runs/:id/cancel",
            axum::routing::post(cancel_sniper_run),
        )
        // VPN profiles
        .route(
            "/vpn-profiles",
            axum::routing::get(list_vpn).post(create_vpn),
        )
        .route(
            "/vpn-profiles/:id",
            axum::routing::get(get_vpn).delete(delete_vpn),
        )
        .route(
            "/vpn-profiles/:id/connect",
            axum::routing::post(connect_vpn),
        )
        .route(
            "/vpn-profiles/:id/disconnect",
            axum::routing::post(disconnect_vpn),
        )
        .route("/vpn-profiles/:id/test", axum::routing::post(test_vpn))
        .route(
            "/workspaces/:id/vpn",
            axum::routing::get(get_workspace_vpn).put(attach_vpn_to_workspace),
        )
}

// --- Sniper ----------------------------------------------------------------

fn sniper_run_to_json(r: &secuscan_db::models::SniperRunRow) -> Value {
    json!({
        "id": r.id,
        "finding_id": r.finding_id,
        "workspace_id": r.workspace_id,
        "category": r.category,
        "target": r.target,
        "status": r.status,
        "steps": serde_json::from_str::<Value>(&r.state_json).unwrap_or(json!([])),
        "proof": r.proof,
        "outcome": r.outcome,
        "error": r.error,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "finished_at": r.finished_at,
    })
}

#[derive(Deserialize, Default)]
struct SniperListQuery {
    #[serde(default)]
    finding_id: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

async fn list_sniper_runs(
    State(state): State<SharedState>,
    user: CurrentUser,
    axum::extract::Query(q): axum::extract::Query<SniperListQuery>,
) -> ApiResult<Json<Value>> {
    let rows =
        repo::sniper::list_runs(&state.db, q.finding_id.as_deref(), q.limit.unwrap_or(50)).await?;
    let items: Vec<Value> = rows
        .iter()
        .filter(|r| crate::access::is_owner_or_admin(&user, &r.created_by))
        .map(sniper_run_to_json)
        .collect();
    Ok(Json(json!({"items": items})))
}

#[derive(Deserialize)]
struct RunSniperRequest {
    finding_id: String,
    #[serde(default)]
    workspace_id: Option<String>,
    /// Clicking Sniper in the UI is the consent act. MCP/API callers must
    /// send this flag explicitly — we do not auto-consent exploit chains.
    #[serde(default)]
    consent_granted: bool,
}

async fn run_sniper(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<RunSniperRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if !req.consent_granted {
        return Err(ApiError::BadRequest(
            "consent_granted must be true to run an exploit chain".into(),
        ));
    }
    let finding =
        crate::routes::findings::load_finding_for_user(&state, &user, &req.finding_id).await?;
    if let Some(ws) = &req.workspace_id {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    let source_task = repo::tasks::get(&state.db, &finding.task_id).await?;
    if source_task.workspace_id != req.workspace_id {
        return Err(ApiError::NotFound(
            "finding not in selected workspace".into(),
        ));
    }
    // The chain engine resolves the source task target when this URL is absent.
    let target = finding.url.clone();
    let run = repo::sniper::create_run(
        &state.db,
        &finding.id,
        req.workspace_id.as_deref(),
        &finding.category,
        target.as_deref(),
        &user.0.id,
    )
    .await?;

    let state2 = state.clone();
    let user2 = user.clone();
    let run_id = run.id.clone();
    let finding_id = finding.id.clone();
    let ws_id = req.workspace_id.clone();
    tokio::spawn(async move {
        // Reload the finding inside the spawned task.
        let result = match repo::findings::get(&state2.db, &finding_id).await {
            Ok(f) => {
                crate::sniper_engine::run_chain(&state2, &user2, &f, &run_id, ws_id.as_deref())
                    .await
            }
            Err(e) => Err(format!("reload finding: {e}")),
        };
        match result {
            Ok((outcome, proof)) => {
                // Mark the source finding validated with the proof.
                let _ = repo::sniper::validate_finding(&state2.db, &finding_id, &proof).await;
                let _ = repo::sniper::finish_run(
                    &state2.db,
                    &run_id,
                    "completed",
                    Some(&outcome),
                    Some(&proof),
                    None,
                )
                .await;
            }
            Err(e) => {
                tracing::error!("sniper run {run_id} failed: {e}");
                let _ =
                    repo::sniper::finish_run(&state2.db, &run_id, "failed", None, None, Some(&e))
                        .await;
            }
        }
    });

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "run_id": run.id,
            "finding_id": finding.id,
            "status": "running",
        })),
    ))
}

async fn get_sniper_run(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let run = repo::sniper::get_run(&state.db, &id).await?;
    crate::access::require_owner(&user, &run.created_by)?;
    Ok(Json(sniper_run_to_json(&run)))
}

async fn cancel_sniper_run(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let run = repo::sniper::get_run(&state.db, &id).await?;
    if !user.is_admin() && run.created_by != user.0.id {
        return Err(ApiError::Forbidden(
            "only the creator or an admin can cancel".into(),
        ));
    }
    // Cancel remaining active tasks of this run.
    let tasks = repo::tasks::list(
        &state.db,
        &repo::tasks::TaskListFilters {
            limit: 500,
            ..Default::default()
        },
    )
    .await?;
    let mut cancelled = 0;
    for t in tasks {
        if !t.status().is_terminal()
            && t.sniper_run_id.as_deref() == Some(&id)
            && state.tasks.cancel(&t.id).await
        {
            cancelled += 1;
        }
    }
    repo::sniper::finish_run(&state.db, &id, "cancelled", None, None, None).await?;
    Ok(Json(json!({"cancelled_tasks": cancelled})))
}

// --- VPN profiles ----------------------------------------------------------

fn vpn_to_json(v: &secuscan_db::models::VpnProfileRow, include_config: bool) -> Value {
    let mut out = json!({
        "id": v.id,
        "name": v.name,
        "status": v.status,
        "last_error": v.last_error,
        "interface": v.interface,
        "connected_at": v.connected_at,
        "created_by": v.created_by,
        "created_at": v.created_at,
        "config_size": v.config_text.len(),
        "openvpn_available": crate::vpn_manager::openvpn_available(),
    });
    if include_config {
        out["config_text"] = json!(v.config_text);
    }
    out
}

async fn list_vpn(State(state): State<SharedState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let rows = repo::vpn::list(&state.db).await?;
    let items: Vec<Value> = rows
        .iter()
        .filter(|v| crate::access::is_owner_or_admin(&user, &v.created_by))
        .map(|v| vpn_to_json(v, false))
        .collect();
    Ok(Json(json!({"items": items})))
}

#[derive(Deserialize)]
struct CreateVpnRequest {
    name: String,
    /// Raw .ovpn config text.
    config_text: String,
}

async fn create_vpn(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateVpnRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if req.name.trim().is_empty() || req.name.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 1..=120 characters".into(),
        ));
    }
    if req.config_text.len() > 512 * 1024 {
        return Err(ApiError::BadRequest("config must be <= 512KB".into()));
    }
    crate::vpn_manager::validate_ovpn_config(&req.config_text).map_err(ApiError::BadRequest)?;
    let row = repo::vpn::create(&state.db, &user.0.id, &req.name, &req.config_text).await?;
    Ok((StatusCode::CREATED, Json(vpn_to_json(&row, false))))
}

async fn get_vpn(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = repo::vpn::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.created_by)?;
    Ok(Json(vpn_to_json(&row, false)))
}

async fn delete_vpn(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let row = repo::vpn::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.created_by)?;
    if row.status == "connected" {
        let _ = crate::vpn_manager::disconnect(&state.db, &row).await;
    }
    repo::vpn::delete(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn connect_vpn(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    let row = repo::vpn::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.created_by)?;
    match crate::vpn_manager::connect(&state.db, &row).await {
        Ok(_iface) => {
            let updated = repo::vpn::get(&state.db, &id).await?;
            Ok(Json(vpn_to_json(&updated, false)))
        }
        Err(e) => {
            let updated = repo::vpn::get(&state.db, &id).await?;
            let mut out = vpn_to_json(&updated, false);
            out["error"] = json!(e);
            Ok(Json(out))
        }
    }
}

async fn disconnect_vpn(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    let row = repo::vpn::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.created_by)?;
    crate::vpn_manager::disconnect(&state.db, &row)
        .await
        .map_err(ApiError::Internal)?;
    let updated = repo::vpn::get(&state.db, &id).await?;
    Ok(Json(vpn_to_json(&updated, false)))
}

async fn test_vpn(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    let row = repo::vpn::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.created_by)?;
    let check = crate::vpn_manager::validate_ovpn_config(&row.config_text);
    let remotes = crate::vpn_manager::ovpn_remotes(&row.config_text);
    let ok = check.is_ok();
    let error = check.err();
    Ok(Json(json!({
        "id": row.id,
        "name": row.name,
        "ok": ok,
        "error": error,
        "remotes": remotes,
        "openvpn_available": crate::vpn_manager::openvpn_available(),
        "dangerous_directives_rejected": !ok,
    })))
}

#[derive(Deserialize)]
struct AttachVpnRequest {
    vpn_profile_id: Option<String>,
}

/// v3.1.1 — the VPN profile a workspace pins (null = no tunnel required).
async fn get_workspace_vpn(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_workspace(&state, &_user, &id, WorkspacePermission::Read).await?;
    let ws = repo::workspaces::get_workspace(&state.db, &id).await?;
    match ws.vpn_profile_id {
        None => Ok(Json(json!({"profile": Value::Null}))),
        Some(pid) => {
            let row = repo::vpn::get(&state.db, &pid).await?;
            Ok(Json(json!({"profile": {
                "id": row.id,
                "name": row.name,
                "status": row.status,
                "interface": row.interface,
                "last_error": row.last_error,
                "connected_at": row.connected_at,
                "openvpn_available": crate::vpn_manager::openvpn_available(),
            }})))
        }
    }
}

async fn attach_vpn_to_workspace(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<AttachVpnRequest>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    require_workspace(&state, &user, &id, WorkspacePermission::Write).await?;
    if let Some(pid) = &req.vpn_profile_id {
        let profile = repo::vpn::get(&state.db, pid).await?;
        crate::access::require_owner(&user, &profile.created_by)?;
    }
    repo::vpn::attach_to_workspace(&state.db, &id, req.vpn_profile_id.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}
