//! Authentication profiles — reusable credentials/cookies/headers for
//! authenticated web scans.

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
        .route("/auth-profiles", axum::routing::get(list).post(create))
        .route(
            "/auth-profiles/:id",
            axum::routing::get(get_one).patch(update).delete(delete),
        )
}

#[derive(Deserialize, Default)]
struct ListQuery {
    #[serde(default)]
    workspace_id: Option<String>,
}

fn profile_to_json(p: &secuscan_db::models::AuthProfileRow) -> Value {
    json!({
        "id": p.id,
        "workspace_id": p.workspace_id,
        "name": p.name,
        "method": p.method,
        "config": serde_json::from_str::<Value>(&p.config_json).unwrap_or(json!({})),
        "notes": p.notes,
        "created_by": p.created_by,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    })
}

#[derive(Deserialize)]
struct CreateProfileRequest {
    #[serde(default)]
    workspace_id: Option<String>,
    name: String,
    method: String,
    #[serde(default)]
    config: Value,
    #[serde(default)]
    notes: String,
}

async fn list(
    State(state): State<SharedState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let rows = secuscan_db::repo::auth_profiles::list(&state.db, q.workspace_id.as_deref()).await?;
    let items: Vec<Value> = rows
        .iter()
        .filter(|p| crate::access::is_owner_or_admin(&user, &p.created_by))
        .map(profile_to_json)
        .collect();
    Ok(Json(json!({ "items": items })))
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateProfileRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    validate_method(&req.method, &req.config)?;
    if req.name.trim().is_empty() || req.name.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 1..=120 characters".into(),
        ));
    }
    if let Some(ws) = &req.workspace_id {
        secuscan_db::repo::workspaces::get_workspace(&state.db, ws).await?;
    }
    let config_json = serde_json::to_string(&req.config).unwrap_or_else(|_| "{}".into());
    let row = secuscan_db::repo::auth_profiles::create(
        &state.db,
        req.workspace_id.as_deref(),
        &req.name,
        &req.method,
        &config_json,
        &req.notes,
        &user.0.id,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(profile_to_json(&row))))
}

async fn get_one(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::auth_profiles::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.created_by)?;
    Ok(Json(profile_to_json(&row)))
}

async fn update(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<CreateProfileRequest>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let existing = secuscan_db::repo::auth_profiles::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &existing.created_by)?;
    validate_method(&req.method, &req.config)?;
    let config_json = serde_json::to_string(&req.config).unwrap_or_else(|_| "{}".into());
    secuscan_db::repo::auth_profiles::update(
        &state.db,
        &id,
        &req.name,
        &req.method,
        &config_json,
        &req.notes,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let existing = secuscan_db::repo::auth_profiles::get(&state.db, &id).await?;
    crate::access::require_owner(&user, &existing.created_by)?;
    secuscan_db::repo::auth_profiles::delete(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Validate that `config` matches the chosen `method`. Returns BadRequest on
/// any structural problem (missing required keys).
fn validate_method(method: &str, config: &Value) -> ApiResult<()> {
    match method {
        "cookie" => {
            let cookies = config
                .get("cookies")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "cookie method requires `cookies` array of {name, value}".into(),
                    )
                })?;
            if cookies.is_empty() {
                return Err(ApiError::BadRequest("cookies array is empty".into()));
            }
            for c in cookies {
                if c.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .is_empty()
                    || c.get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err(ApiError::BadRequest(
                        "each cookie requires non-empty `name` and `value`".into(),
                    ));
                }
            }
        }
        "header" => {
            let headers = config
                .get("headers")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "header method requires `headers` array of {name, value}".into(),
                    )
                })?;
            if headers.is_empty() {
                return Err(ApiError::BadRequest("headers array is empty".into()));
            }
        }
        "form" => {
            let login_url = config
                .get("login_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if login_url.is_empty() {
                return Err(ApiError::BadRequest(
                    "form method requires `login_url`".into(),
                ));
            }
            if config
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            {
                return Err(ApiError::BadRequest(
                    "form method requires `username`".into(),
                ));
            }
            if config
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            {
                return Err(ApiError::BadRequest(
                    "form method requires `password`".into(),
                ));
            }
        }
        "recorded" => {
            let steps = config
                .get("steps")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    ApiError::BadRequest("recorded method requires `steps` array".into())
                })?;
            if steps.is_empty() {
                return Err(ApiError::BadRequest("recorded steps array is empty".into()));
            }
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown method `{other}`; must be cookie/header/form/recorded"
            )))
        }
    }
    Ok(())
}
