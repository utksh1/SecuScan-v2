//! Task routes: start (with the full validation pipeline), list, detail,
//! cancel, retry, delete, raw output.
//!
//! `validate_and_create_task` is shared with the workflow runner.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_core::policy::{evaluate_target, PolicyAuditEntry, TargetVerdict};
use secuscan_core::validate::normalize_inputs;
use secuscan_db::models::TaskRow;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/tasks", axum::routing::post(create))
        .route("/tasks", axum::routing::get(list))
        .route("/tasks/:id", axum::routing::get(get_one))
        .route("/tasks/:id", axum::routing::delete(delete))
        .route("/tasks/:id/cancel", axum::routing::post(cancel))
        .route("/tasks/:id/retry", axum::routing::post(retry))
        .route("/tasks/:id/result", axum::routing::get(result))
        .route("/tasks/:id/output", axum::routing::get(raw_output))
}

#[derive(Deserialize)]
pub struct StartTaskRequest {
    pub plugin_id: String,
    #[serde(default)]
    pub inputs: BTreeMap<String, Value>,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub consent_granted: bool,
}

/// The complete task admission pipeline. Returns the queued task row plus
/// the normalized inputs (needed by the executor).
pub async fn validate_and_create_task(
    state: &SharedState,
    user: &CurrentUser,
    req: &StartTaskRequest,
    workflow_run_id: Option<&str>,
) -> ApiResult<(TaskRow, Arc<secuscan_core::manifest::PluginManifest>, BTreeMap<String, Value>)> {
    // 1) plugin exists
    let manifest = {
        let registry = state.registry.read().await;
        let m = registry
            .get(&req.plugin_id)
            .ok_or_else(|| ApiError::NotFound(format!("plugin `{}`", req.plugin_id)))?;
        Arc::new(m.clone())
    };

    // 2) availability
    if !manifest.available {
        return Err(ApiError::BadRequest(format!(
            "plugin `{}` is unavailable; missing binaries: {}",
            manifest.plugin.id,
            manifest.missing_binaries.join(", ")
        )));
    }

    // 3) enabled
    let enabled = secuscan_db::repo::misc::enabled_map(&state.db)
        .await
        .unwrap_or_default();
    if !enabled.get(&manifest.plugin.id).copied().unwrap_or(true) {
        return Err(ApiError::Forbidden(format!(
            "plugin `{}` is disabled by the administrator",
            manifest.plugin.id
        )));
    }

    // 4) capability denial
    for cap in &manifest.safety.capabilities {
        if state
            .config
            .denied_capabilities
            .iter()
            .any(|d| d.eq_ignore_ascii_case(cap))
        {
            return Err(ApiError::Forbidden(format!(
                "plugin `{}` requires the `{cap}` capability, which is denied on this instance",
                manifest.plugin.id
            )));
        }
    }

    // 5) inputs (+ preset merge)
    let mut inputs = req.inputs.clone();
    if let Some(preset_name) = &req.preset {
        let preset = manifest.presets.get(preset_name).ok_or_else(|| {
            ApiError::BadRequest(format!("unknown preset `{preset_name}`"))
        })?;
        for (k, v) in preset {
            inputs.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    let normalized = normalize_inputs(&manifest, &inputs)?;

    // 6) consent
    let global_consent = repo::misc::get_require_consent(&state.db).await?;
    let needs_consent = manifest.safety.requires_consent || global_consent;
    if needs_consent && !req.consent_granted {
        return Err(ApiError::BadRequest(
            "this plugin requires explicit consent: pass consent_granted=true after confirming \
             you are authorized to scan the target"
                .into(),
        ));
    }

    // 7) target policy (global allow/deny + plugin allowed_targets)
    let target_value = normalized
        .get("target")
        .or_else(|| normalized.get("url"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let global_policy = repo::misc::get_network_policy(&state.db).await?;
    let verdict = evaluate_target(
        target_value.as_deref(),
        &manifest.safety.allowed_targets,
        &global_policy,
    );
    match verdict {
        TargetVerdict::Allowed => {}
        TargetVerdict::NoTarget => {
            // Fields named neither target nor url: allowed (policy not
            // applicable), but recorded for the audit trail.
        }
        TargetVerdict::Denied {
            reason,
            layer,
            pattern,
        } => {
            let entry = PolicyAuditEntry::denied(
                target_value.as_deref().unwrap_or(""),
                &manifest.plugin.id,
                &user.0.email,
                &reason,
                layer,
                &pattern,
            );
            let _ = repo::misc::insert_policy_audit(&state.db, &entry).await;
            return Err(ApiError::Forbidden(reason));
        }
    }

    // 8) persist + spawn
    let row = repo::tasks::create(
        &state.db,
        repo::tasks::NewTask {
            user_id: &user.0.id,
            plugin_id: &manifest.plugin.id,
            plugin_name: &manifest.plugin.name,
            target: target_value.as_deref(),
            inputs_json: &serde_json::to_string(&normalized).unwrap_or_else(|_| "{}".into()),
            options_json: &json!({
                "preset": req.preset,
                "consent_granted": req.consent_granted,
            })
            .to_string(),
            workflow_run_id,
        },
    )
    .await?;

    Ok((row, manifest, normalized))
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<StartTaskRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let (row, manifest, inputs) = validate_and_create_task(&state, &user, &req, None).await?;
    state.tasks.spawn(row.clone(), manifest, inputs).await;
    Ok((StatusCode::CREATED, Json(task_to_json(&row, false))))
}

pub fn task_to_json(t: &TaskRow, include_output: bool) -> Value {
    let mut v = json!({
        "id": t.id,
        "user_id": t.user_id,
        "plugin_id": t.plugin_id,
        "plugin_name": t.plugin_name,
        "target": t.target,
        "status": t.status,
        "inputs": serde_json::from_str::<Value>(&t.inputs_json).unwrap_or(json!({})),
        "options": serde_json::from_str::<Value>(&t.options_json).unwrap_or(json!({})),
        "exit_code": t.exit_code,
        "error": t.error,
        "stats": serde_json::from_str::<Value>(t.stats_json.as_deref().unwrap_or("null")).unwrap_or(Value::Null),
        "output_truncated": t.output_truncated,
        "workflow_run_id": t.workflow_run_id,
        "created_at": t.created_at,
        "started_at": t.started_at,
        "finished_at": t.finished_at,
    });
    if include_output {
        v["output"] = json!(t.output);
    }
    v
}

#[derive(Deserialize, Default)]
struct ListQuery {
    status: Option<String>,
    plugin_id: Option<String>,
    workflow_run_id: Option<String>,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

async fn list(
    State(state): State<SharedState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    if let Some(s) = &q.status {
        if secuscan_core::models::TaskStatus::parse(s).is_none() {
            return Err(ApiError::BadRequest(format!("unknown status `{s}`")));
        }
    }
    let filters = repo::tasks::TaskListFilters {
        user_id: if user.is_admin() { None } else { Some(user.0.id.clone()) },
        status: q.status,
        plugin_id: q.plugin_id,
        workflow_run_id: q.workflow_run_id,
        search: q.search,
        limit: q.limit,
        offset: q.offset,
    };
    let items = repo::tasks::list(&state.db, &filters).await?;
    let total = repo::tasks::count(&state.db, &filters).await?;
    Ok(Json(json!({
        "items": items.iter().map(|t| task_to_json(t, false)).collect::<Vec<_>>(),
        "total": total,
        "limit": filters.limit,
        "offset": filters.offset,
    })))
}

async fn get_one(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let t = load_task_for_user(&state, &user, &id).await?;
    Ok(Json(task_to_json(&t, false)))
}

async fn load_task_for_user(
    state: &SharedState,
    user: &CurrentUser,
    id: &str,
) -> ApiResult<TaskRow> {
    let t = repo::tasks::get(&state.db, id).await?;
    if !user.is_admin() && t.user_id != user.0.id {
        return Err(ApiError::NotFound(format!("task {id}"))); // don't leak existence
    }
    Ok(t)
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let t = load_task_for_user(&state, &user, &id).await?;
    if t.status() == secuscan_core::models::TaskStatus::Running {
        return Err(ApiError::Conflict("cancel the task before deleting it".into()));
    }
    repo::tasks::delete(&state.db, &t.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let t = load_task_for_user(&state, &user, &id).await?;
    match t.status() {
        s if s.is_terminal() => {
            return Ok(Json(json!({ "cancelled": false, "status": s.label() })));
        }
        _ => {}
    }
    let cancelled = state.tasks.cancel(&t.id).await;
    if !cancelled {
        // Not in the running map: it may have just finished.
        let fresh = repo::tasks::get(&state.db, &t.id).await?;
        return Ok(Json(json!({
            "cancelled": false,
            "status": fresh.status().label(),
        })));
    }
    Ok(Json(json!({ "cancelled": true, "status": "cancelling" })))
}

async fn retry(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    let original = load_task_for_user(&state, &user, &id).await?;
    let inputs: BTreeMap<String, Value> =
        serde_json::from_str(&original.inputs_json).unwrap_or_default();
    let options: Value =
        serde_json::from_str(&original.options_json).unwrap_or(json!({}));
    let req = StartTaskRequest {
        plugin_id: original.plugin_id.clone(),
        inputs,
        preset: options.get("preset").and_then(|v| v.as_str()).map(str::to_string),
        consent_granted: true, // consent was granted for the original task
    };
    let (row, manifest, inputs) = validate_and_create_task(&state, &user, &req, None).await?;
    state.tasks.spawn(row.clone(), manifest, inputs).await;
    Ok((StatusCode::CREATED, Json(task_to_json(&row, false))))
}

async fn result(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let t = load_task_for_user(&state, &user, &id).await?;
    let findings = repo::findings::list(
        &state.db,
        &repo::findings::FindingFilters {
            task_id: Some(t.id.clone()),
            limit: 1000,
            ..Default::default()
        },
    )
    .await?;
    let counts = repo::findings::severity_counts_for_task(&state.db, &t.id).await?;
    Ok(Json(json!({
        "task": task_to_json(&t, false),
        "findings": findings.iter().map(crate::routes::findings::finding_to_json).collect::<Vec<_>>(),
        "severity_counts": counts.into_iter().collect::<std::collections::BTreeMap<String, i64>>(),
    })))
}

async fn raw_output(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let t = load_task_for_user(&state, &user, &id).await?;
    Ok(Json(json!({
        "id": t.id,
        "output": t.output.unwrap_or_default(),
        "truncated": t.output_truncated,
    })))
}
