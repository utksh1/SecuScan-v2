//! Admin routes: users, network policy + audit log, settings, plugin refresh.

use crate::auth::extractor::CurrentUser;
use crate::auth::hash_password;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use secuscan_core::policy::NetworkPolicy;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/admin/users", axum::routing::post(create_user))
        .route("/admin/users", axum::routing::get(list_users))
        .route("/admin/users/:id", axum::routing::patch(update_user))
        .route("/admin/users/:id", axum::routing::delete(delete_user))
        .route("/admin/network-policy", axum::routing::get(get_policy))
        .route("/admin/network-policy", axum::routing::put(put_policy))
        .route("/admin/audit", axum::routing::get(audit))
        .route("/admin/settings", axum::routing::put(put_settings))
        .route("/admin/plugins/refresh", axum::routing::post(refresh_plugins))
}

fn user_json(u: &secuscan_db::models::UserRow) -> Value {
    json!({
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "created_at": u.created_at,
    })
}

#[derive(Deserialize)]
struct CreateUserRequest {
    email: String,
    name: String,
    password: String,
    role: String,
}

async fn create_user(
    State(state): State<SharedState>,
    admin: CurrentUser,
    Json(req): Json<CreateUserRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    admin.require_admin()?;
    if req.name.trim().is_empty() || req.name.len() > 100 {
        return Err(ApiError::BadRequest("name must be 1..=100 characters".into()));
    }
    let hash = hash_password(&req.password)?;
    let user = repo::users::create(&state.db, &req.email, &req.name, &hash, &req.role).await?;
    Ok((StatusCode::CREATED, Json(user_json(&user))))
}

async fn list_users(
    State(state): State<SharedState>,
    admin: CurrentUser,
) -> ApiResult<Json<Value>> {
    admin.require_admin()?;
    let users = repo::users::list(&state.db).await?;
    Ok(Json(json!({
        "items": users.iter().map(user_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    role: Option<String>,
    password: Option<String>,
}

async fn update_user(
    State(state): State<SharedState>,
    admin: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<StatusCode> {
    admin.require_admin()?;
    if let Some(role) = &req.role {
        repo::users::update_role(&state.db, &id, role).await?;
    }
    if let Some(password) = &req.password {
        let hash = hash_password(password)?;
        repo::users::update_password(&state.db, &id, &hash).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_user(
    State(state): State<SharedState>,
    admin: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    admin.require_admin()?;
    if id == admin.0.id {
        return Err(ApiError::BadRequest("you cannot delete your own account".into()));
    }
    let count = repo::users::count(&state.db).await?;
    if count <= 1 {
        return Err(ApiError::Conflict("the instance must keep at least one user".into()));
    }
    let ok = repo::users::delete(&state.db, &id).await.is_ok();
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound(format!("user {id}")))
    }
}

#[derive(Deserialize)]
struct PolicyRequest {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

async fn get_policy(
    State(state): State<SharedState>,
    admin: CurrentUser,
) -> ApiResult<Json<Value>> {
    admin.require_admin()?;
    let p = repo::misc::get_network_policy(&state.db).await?;
    Ok(Json(json!({ "allow": p.allow, "deny": p.deny })))
}

async fn put_policy(
    State(state): State<SharedState>,
    admin: CurrentUser,
    Json(req): Json<PolicyRequest>,
) -> ApiResult<StatusCode> {
    admin.require_admin()?;
    for pat in req.allow.iter().chain(req.deny.iter()) {
        if pat.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "policy patterns must be non-empty (glob like 10.*.*.* or CIDR like 10.0.0.0/8)"
                    .into(),
            ));
        }
        if pat.len() > 200 {
            return Err(ApiError::BadRequest("policy pattern too long".into()));
        }
    }
    let policy = NetworkPolicy {
        allow: req.allow,
        deny: req.deny,
    };
    repo::misc::set_network_policy(&state.db, &policy).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

async fn audit(
    State(state): State<SharedState>,
    admin: CurrentUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    admin.require_admin()?;
    let rows = repo::misc::list_policy_audit(&state.db, q.limit).await?;
    Ok(Json(json!({
        "items": rows.iter().map(|r| json!({
            "id": r.id,
            "ts": r.ts,
            "user_id": r.user_id,
            "plugin_id": r.plugin_id,
            "target": r.target,
            "verdict": r.verdict,
            "layer": r.layer,
            "pattern": r.pattern,
            "reason": r.reason,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct SettingsRequest {
    require_consent: Option<bool>,
}

async fn put_settings(
    State(state): State<SharedState>,
    admin: CurrentUser,
    Json(req): Json<SettingsRequest>,
) -> ApiResult<StatusCode> {
    admin.require_admin()?;
    if let Some(rc) = req.require_consent {
        repo::misc::set_require_consent(&state.db, rc).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn refresh_plugins(
    State(state): State<SharedState>,
    admin: CurrentUser,
) -> ApiResult<Json<Value>> {
    admin.require_admin()?;
    let mut registry = state.registry.write().await;
    registry.refresh_availability();
    let available = registry.all().iter().filter(|p| p.available).count();
    Ok(Json(json!({
        "total": registry.len(),
        "available": available,
    })))
}
