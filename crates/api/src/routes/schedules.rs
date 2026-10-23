//! Schedule routes: CRUD, run-now, run history.
//!
//! Ownership: schedules are per-user (owner or admin can mutate / run);
//! other users get a 404 so existence is not leaked. Listing follows the
//! task convention — everyone sees their own, admins see all — with the
//! same `?workspace_id=<id|none>` scoping.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::tasks::{admit_request, task_to_json, StartTaskRequest};
use crate::routes::workspaces::parse_workspace_scope;
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_core::models::add_seconds_iso;
use secuscan_db::models::ScheduleRow;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/schedules", axum::routing::post(create))
        .route("/schedules", axum::routing::get(list))
        .route("/schedules/:id", axum::routing::get(get_one))
        .route("/schedules/:id", axum::routing::patch(update))
        .route("/schedules/:id", axum::routing::delete(delete))
        .route("/schedules/:id/run", axum::routing::post(run_now))
        .route("/schedules/:id/runs", axum::routing::get(list_runs))
}

#[derive(Deserialize)]
pub struct CreateScheduleRequest {
    pub name: String,
    pub plugin_id: String,
    #[serde(default)]
    pub inputs: BTreeMap<String, Value>,
    #[serde(default)]
    pub preset: Option<String>,
    /// Seconds between automated runs (300..=31_536_000).
    pub interval_seconds: i64,
    /// Consent captured once at creation; every automated run re-checks
    /// policy but not the checkbox.
    #[serde(default)]
    pub consent_granted: bool,
    #[serde(default)]
    pub workspace_id: Option<String>,
}

fn validate_name(name: &str) -> ApiResult<()> {
    if name.trim().is_empty() || name.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 1..=120 characters".into(),
        ));
    }
    Ok(())
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateScheduleRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    validate_name(&req.name)?;
    repo::schedules::validate_interval(req.interval_seconds).map_err(ApiError::from)?;

    // Full admission pipeline (plugin/policy/consent) without persisting a
    // task — a schedule may only be created for a request that would be
    // admissible right now.
    let task_req = StartTaskRequest {
        plugin_id: req.plugin_id.clone(),
        inputs: req.inputs.clone(),
        preset: req.preset.clone(),
        consent_granted: req.consent_granted,
        workspace_id: req.workspace_id.clone(),
    };
    let admitted = admit_request(&state, &user, &task_req).await?;

    let row = repo::schedules::create(
        &state.db,
        repo::schedules::NewSchedule {
            user_id: &user.0.id,
            workspace_id: req.workspace_id.as_deref(),
            name: req.name.trim(),
            plugin_id: &admitted.manifest.plugin.id,
            inputs_json: &serde_json::to_string(&admitted.normalized)
                .unwrap_or_else(|_| "{}".into()),
            preset: req.preset.as_deref(),
            target: admitted.target.as_deref(),
            interval_seconds: req.interval_seconds,
        },
    )
    .await?;
    Ok((StatusCode::CREATED, Json(schedule_to_json(&row))))
}

pub fn schedule_to_json(s: &ScheduleRow) -> Value {
    json!({
        "id": s.id,
        "user_id": s.user_id,
        "workspace_id": s.workspace_id,
        "name": s.name,
        "plugin_id": s.plugin_id,
        "inputs": serde_json::from_str::<Value>(&s.inputs_json).unwrap_or(json!({})),
        "preset": s.preset,
        "target": s.target,
        "interval_seconds": s.interval_seconds,
        "enabled": s.enabled,
        "next_run_at": s.next_run_at,
        "last_run_at": s.last_run_at,
        "last_task_id": s.last_task_id,
        "last_error": s.last_error,
        "created_at": s.created_at,
        "updated_at": s.updated_at,
    })
}

#[derive(Deserialize, Default)]
struct ListQuery {
    /// `none` selects the Personal scope; an id must reference an existing
    /// workspace; absent = all visible schedules.
    workspace_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

async fn list(
    State(state): State<SharedState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let workspace = parse_workspace_scope(&state, q.workspace_id.as_deref()).await?;
    let filters = repo::schedules::ScheduleListFilters {
        user_id: if user.is_admin() {
            None
        } else {
            Some(user.0.id.clone())
        },
        workspace,
        limit: q.limit,
        offset: q.offset,
    };
    let items = repo::schedules::list(&state.db, &filters).await?;
    let total = repo::schedules::count(&state.db, &filters).await?;
    Ok(Json(json!({
        "items": items.iter().map(schedule_to_json).collect::<Vec<_>>(),
        "total": total,
        "limit": filters.limit,
        "offset": filters.offset,
    })))
}

/// Load a schedule enforcing ownership (admins bypass; everyone else,
/// including viewers, gets a 404 that does not leak existence).
async fn load_schedule_for_user(
    state: &SharedState,
    user: &CurrentUser,
    id: &str,
) -> ApiResult<ScheduleRow> {
    let s = repo::schedules::get(&state.db, id).await?;
    if !user.is_admin() && s.user_id != user.0.id {
        return Err(ApiError::NotFound(format!("schedule {id}")));
    }
    Ok(s)
}

async fn get_one(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let s = load_schedule_for_user(&state, &user, &id).await?;
    Ok(Json(schedule_to_json(&s)))
}

/// PATCH body. `workspace_id` / `preset` distinguish "absent" (keep) from
/// "null" (clear to Personal / no preset) via the double-Option pattern.
#[derive(Deserialize)]
struct UpdateScheduleRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    inputs: Option<BTreeMap<String, Value>>,
    #[serde(default, deserialize_with = "double_option")]
    preset: Option<Option<String>>,
    #[serde(default)]
    interval_seconds: Option<i64>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    workspace_id: Option<Option<String>>,
}

/// serde helper: absent -> None, JSON null -> Some(None), value -> Some(Some).
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    // Deserialize the *inner* Option<T> from the present value (null -> None,
    // v -> Some(v)), then mark the field as present by wrapping in Some.
    <Option<T>>::deserialize(de).map(Some)
}

async fn update(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateScheduleRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let existing = load_schedule_for_user(&state, &user, &id).await?;

    let name = req.name.clone().unwrap_or_else(|| existing.name.clone());
    validate_name(&name)?;
    if let Some(secs) = req.interval_seconds {
        repo::schedules::validate_interval(secs).map_err(ApiError::from)?;
    }

    // Workspace change: validate the target workspace up front (404 on
    // unknown) so a bad id cannot be persisted.
    let workspace_id = match req.workspace_id {
        None => existing.workspace_id.clone(),
        Some(None) => None, // explicit null -> Personal
        Some(Some(ref ws)) => {
            repo::workspaces::get_workspace(&state.db, ws).await?;
            Some(ws.clone())
        }
    };

    // Inputs/preset change: re-run the full admission pipeline so the
    // stored schedule always holds a normalized, admissible payload.
    let (inputs_json, preset, target) =
        if req.inputs.is_some() || req.preset.is_some() || req.workspace_id.is_some() {
            let task_req = StartTaskRequest {
                plugin_id: existing.plugin_id.clone(),
                inputs: req.inputs.clone().unwrap_or_else(|| {
                    serde_json::from_str(&existing.inputs_json).unwrap_or_default()
                }),
                preset: match (&req.preset, &existing.preset) {
                    (Some(p), _) => p.clone(),
                    (None, e) => e.clone(),
                },
                // Consent was captured when the schedule was created; the
                // admission pipeline only checks the flag, not its provenance.
                consent_granted: true,
                workspace_id: workspace_id.clone(),
            };
            let admitted = admit_request(&state, &user, &task_req).await?;
            (
                serde_json::to_string(&admitted.normalized).unwrap_or_else(|_| "{}".into()),
                task_req.preset,
                admitted.target,
            )
        } else {
            (
                existing.inputs_json.clone(),
                existing.preset.clone(),
                existing.target.clone(),
            )
        };

    let interval = req.interval_seconds.unwrap_or(existing.interval_seconds);
    let enabled = req.enabled.unwrap_or(existing.enabled);

    // Re-anchor when the cadence restarts: a changed interval, or a
    // disabled -> enabled transition. Other edits keep the stored anchor.
    let interval_changed = req.interval_seconds.is_some() && interval != existing.interval_seconds;
    let re_enabled = req.enabled == Some(true) && !existing.enabled;
    let next_run_at = if interval_changed || re_enabled {
        add_seconds_iso(&secuscan_db::now(), interval)
    } else {
        existing.next_run_at.clone()
    };

    let row = repo::schedules::update(
        &state.db,
        &id,
        repo::schedules::ScheduleUpdate {
            name: &name,
            inputs_json: &inputs_json,
            preset: preset.as_deref(),
            target: target.as_deref(),
            interval_seconds: interval,
            enabled,
            workspace_id: workspace_id.as_deref(),
            next_run_at: &next_run_at,
        },
    )
    .await?;
    Ok((StatusCode::OK, Json(schedule_to_json(&row))))
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    // Ownership check before delete (404 for strangers, no row leak).
    load_schedule_for_user(&state, &user, &id).await?;
    repo::schedules::delete(&state.db, &id).await?;
    // Tasks keep running to completion; their schedule_id nulls out and the
    // history stays queryable by task id.
    Ok(StatusCode::NO_CONTENT)
}

/// Launch one run immediately without disturbing the recurring anchor
/// (`next_run_at` is untouched — "run now" is an extra occurrence).
///
/// Deliberately bypasses the scheduler's overlap guard: an explicit user
/// action wins over "the previous run is still active". Admission (policy,
/// plugin availability, consent-at-creation) is still fully re-checked, and
/// a synchronous rejection is returned to the caller rather than recorded
/// as `last_error` (which is reserved for autonomous scheduler attempts).
async fn run_now(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let s = load_schedule_for_user(&state, &user, &id).await?;

    // Re-check admission: the plugin may have been disabled or the policy
    // tightened since the schedule was created.
    let task_req = StartTaskRequest {
        plugin_id: s.plugin_id.clone(),
        inputs: serde_json::from_str(&s.inputs_json).unwrap_or_default(),
        preset: s.preset.clone(),
        consent_granted: true,
        workspace_id: s.workspace_id.clone(),
    };
    let (task, manifest, inputs) =
        crate::routes::tasks::validate_and_create_task(&state, &user, &task_req, None, Some(&s.id))
            .await?;
    state.tasks.spawn(task.clone(), manifest, inputs).await;

    // Stamp the manual run but keep the automated cadence.
    repo::schedules::mark_run(&state.db, &s.id, Some(&task.id), None, &s.next_run_at).await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "task_id": task.id,
            "task": task_to_json(&task, false),
            "next_run_at": s.next_run_at,
        })),
    ))
}

async fn list_runs(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let s = load_schedule_for_user(&state, &user, &id).await?;
    let tasks = repo::tasks::list_for_schedule(&state.db, &s.id, 50).await?;
    Ok(Json(json!({
        "items": tasks.iter().map(|t| task_to_json(t, false)).collect::<Vec<_>>(),
        "total": tasks.len(),
    })))
}
