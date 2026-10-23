//! Notifications HTTP routes — CRUD + delivery log.

use crate::auth::extractor::CurrentUser;
use crate::error::ApiResult;
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/notifications", axum::routing::get(list).post(create))
        .route("/notifications/:id", axum::routing::get(get_one).patch(update).delete(delete))
        .route("/notifications/:id/log", axum::routing::get(list_log))
}

#[derive(Deserialize, Default)]
struct ListQuery {
    #[serde(default)]
    workspace_id: Option<String>,
}

fn rule_to_json(r: &secuscan_db::models::NotificationRuleRow) -> Value {
    json!({
        "id": r.id,
        "workspace_id": r.workspace_id,
        "name": r.name,
        "rules": serde_json::from_str::<Value>(&r.rules_json).unwrap_or(json!({})),
        "enabled": r.enabled,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    })
}

async fn list(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let rows = secuscan_db::repo::notifications::list_rules(&state.db, q.workspace_id.as_deref()).await?;
    Ok(Json(json!({
        "items": rows.iter().map(rule_to_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct CreateRuleRequest {
    #[serde(default)]
    workspace_id: Option<String>,
    name: String,
    rules: Value,
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateRuleRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if let Some(ws) = &req.workspace_id {
        secuscan_db::repo::workspaces::get_workspace(&state.db, ws).await?;
    }
    let rules_json = serde_json::to_string(&req.rules).unwrap_or_else(|_| "{}".into());
    let row = secuscan_db::repo::notifications::create_rule(
        &state.db, req.workspace_id.as_deref(), &user.0.id, &req.name, &rules_json,
    ).await?;
    Ok((StatusCode::CREATED, Json(rule_to_json(&row))))
}

async fn get_one(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::notifications::get_rule(&state.db, &id).await?;
    Ok(Json(rule_to_json(&row)))
}

#[derive(Deserialize)]
struct UpdateRuleRequest {
    name: String,
    rules: Value,
    #[serde(default)]
    enabled: bool,
}

async fn update(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateRuleRequest>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let rules_json = serde_json::to_string(&req.rules).unwrap_or_else(|_| "{}".into());
    secuscan_db::repo::notifications::update_rule(
        &state.db, &id, &req.name, &rules_json, req.enabled,
    ).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    secuscan_db::repo::notifications::delete_rule(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct ListLogQuery {
    #[serde(default)]
    limit: Option<u32>,
}

async fn list_log(
    State(state): State<SharedState>,
    _user: CurrentUser,
    Path(id): Path<String>,
    Query(q): Query<ListLogQuery>,
) -> ApiResult<Json<Value>> {
    let limit = q.limit.unwrap_or(100);
    let rows = secuscan_db::repo::notifications::list_delivery_log(&state.db, Some(&id), limit).await?;
    Ok(Json(json!({
        "items": rows.iter().map(|l| json!({
            "id": l.id,
            "rule_id": l.rule_id,
            "task_id": l.task_id,
            "finding_id": l.finding_id,
            "channel": l.channel,
            "status": l.status,
            "http_status": l.http_status,
            "error": l.error,
            "payload": serde_json::from_str::<Value>(&l.payload_json).unwrap_or(json!({})),
            "sent_at": l.sent_at,
        })).collect::<Vec<_>>(),
    })))
}
