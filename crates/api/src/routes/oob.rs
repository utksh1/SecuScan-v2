//! OOB (out-of-band) callback HTTP routes.
//!
//! Two route groups:
//!   * `/oob/:secret` — the public callback receiver (no auth; anyone with
//!     the secret can hit it). Captures the full request as JSON and stores it.
//!   * `/api/v1/oob-handlers` — CRUD for handlers (auth required).

use crate::auth::extractor::CurrentUser;
use crate::access::{require_workspace, workspace_visible, WorkspacePermission};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    // Public callback receiver (no auth).
    let public = axum::Router::new().route("/oob/:secret", axum::routing::any(receive_callback));

    // Authed CRUD.
    let authed = axum::Router::new()
        .route("/oob-handlers", axum::routing::get(list).post(create))
        .route(
            "/oob-handlers/:id",
            axum::routing::get(get_one).delete(delete),
        )
        .route("/oob-handlers/:id/hits", axum::routing::get(list_hits))
        .route(
            "/oob-handlers/:id/hits/clear",
            axum::routing::post(clear_hits),
        );

    public.merge(authed)
}

fn handler_to_json(h: &secuscan_db::models::OobHandlerRow, include_secret: bool) -> Value {
    let mut out = json!({
        "id": h.id,
        "workspace_id": h.workspace_id,
        "user_id": h.user_id,
        "name": h.name,
        "kind": h.kind,
        "config": serde_json::from_str::<Value>(&h.config_json).unwrap_or(json!({})),
        "callback_url": format!("/api/v1/oob/{}", h.secret),
        "expires_at": h.expires_at,
        "created_at": h.created_at,
        "hit_count": h.hit_count,
        "last_hit_at": h.last_hit_at,
    });
    if include_secret {
        out["secret"] = json!(h.secret);
    }
    out
}

fn hit_to_json(h: &secuscan_db::models::OobHitRow) -> Value {
    json!({
        "id": h.id,
        "handler_id": h.handler_id,
        "task_id": h.task_id,
        "payload": serde_json::from_str::<Value>(&h.payload_json).unwrap_or(json!({})),
        "received_at": h.received_at,
    })
}

#[derive(Deserialize, Default)]
struct ListQuery {
    #[serde(default)]
    workspace_id: Option<String>,
}

async fn list(
    State(state): State<SharedState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    if let Some(ws) = q.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Read).await?;
    }
    let rows = secuscan_db::repo::oob::list_handlers(&state.db, q.workspace_id.as_deref()).await?;
    let mut items = Vec::new();
    for h in &rows {
        if !crate::access::is_owner_or_admin(&user, &h.user_id) { continue; }
        if let Some(ws) = h.workspace_id.as_deref() {
            if !workspace_visible(&state, &user, ws).await? { continue; }
        }
        items.push(handler_to_json(h, false));
    }
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
struct CreateHandlerRequest {
    #[serde(default)]
    workspace_id: Option<String>,
    name: String,
    kind: String,
    #[serde(default)]
    config: Value,
    /// TTL in seconds (default 60 days = 5184000).
    #[serde(default)]
    ttl_seconds: Option<i64>,
}

async fn create(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<CreateHandlerRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if let Some(ws) = &req.workspace_id {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    let config_json = serde_json::to_string(&req.config).unwrap_or_else(|_| "{}".into());
    let ttl = req.ttl_seconds.unwrap_or(60 * 24 * 3600);
    let row = secuscan_db::repo::oob::create_handler(
        &state.db,
        req.workspace_id.as_deref(),
        &user.0.id,
        &req.name,
        &req.kind,
        &config_json,
        ttl,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(handler_to_json(&row, true))))
}

async fn get_one(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.user_id)?;
    if let Some(ws) = row.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Read).await?;
    }
    Ok(Json(handler_to_json(&row, true)))
}

async fn delete(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let row = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &row.user_id)?;
    if let Some(ws) = row.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    secuscan_db::repo::oob::delete_handler(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct ListHitsQuery {
    #[serde(default)]
    limit: Option<u32>,
}

async fn list_hits(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Query(q): Query<ListHitsQuery>,
) -> ApiResult<Json<Value>> {
    let handler = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &handler.user_id)?;
    if let Some(ws) = handler.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Read).await?;
    }
    let limit = q.limit.unwrap_or(100);
    let rows = secuscan_db::repo::oob::list_hits(&state.db, &id, limit).await?;
    Ok(Json(json!({
        "items": rows.iter().map(hit_to_json).collect::<Vec<_>>(),
    })))
}

async fn clear_hits(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require_scanner()?;
    let handler = secuscan_db::repo::oob::get_handler(&state.db, &id).await?;
    crate::access::require_owner(&user, &handler.user_id)?;
    if let Some(ws) = handler.workspace_id.as_deref() {
        require_workspace(&state, &user, ws, WorkspacePermission::Write).await?;
    }
    secuscan_db::repo::oob::clear_hits(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- public callback receiver ---------------------------------------------

async fn receive_callback(
    State(state): State<SharedState>,
    Path(secret): Path<String>,
    req: Request,
) -> ApiResult<StatusCode> {
    // Look up the handler by secret.
    let handler = secuscan_db::repo::oob::get_handler_by_secret(&state.db, &secret)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such OOB handler".into()))?;
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&handler.expires_at) {
        if exp.with_timezone(&chrono::Utc) < chrono::Utc::now() {
            return Err(ApiError::NotFound("OOB handler expired".into()));
        }
    }

    // Capture request data.
    let (parts, body) = req.into_parts();
    let body_bytes: Bytes = axum::body::to_bytes(body, 256 * 1024)
        .await
        .map_err(|e| ApiError::BadRequest(format!("read body: {e}")))?;
    let method = parts.method.as_str().to_string();
    let uri = parts.uri.to_string();
    let headers: serde_json::Map<String, Value> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(v.to_str().unwrap_or("").to_string()),
            )
        })
        .collect();
    let source_ip = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .or_else(|| {
            parts
                .headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_default();
    let user_agent = parts
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Try to extract the OOB marker from query/body to correlate with a task.
    let marker = extract_marker(&uri, &body_bytes);
    let task_id: Option<String> = if let Some(ref m) = marker {
        sqlx::query_scalar::<_, Option<String>>("SELECT id FROM tasks WHERE oob_marker = ? LIMIT 1")
            .bind(m)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .flatten()
    } else {
        None
    };

    let payload = json!({
        "source_ip": source_ip,
        "method": method,
        "url": uri,
        "headers": Value::Object(headers),
        "body": String::from_utf8_lossy(&body_bytes).to_string(),
        "user_agent": user_agent,
        "marker": marker,
    });
    let payload_json = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());

    secuscan_db::repo::oob::record_hit(&state.db, &handler.id, task_id.as_deref(), &payload_json)
        .await?;

    Ok(StatusCode::OK)
}

fn extract_marker(uri: &str, body: &[u8]) -> Option<String> {
    // Look for "ptt" followed by 12 hex chars in the URL or body.
    let re = regex::Regex::new(r"ptt[0-9a-f]{12}").ok()?;
    let uri_match = re.find(uri).map(|m| m.as_str().to_string());
    if uri_match.is_some() {
        return uri_match;
    }
    let body_str = std::str::from_utf8(body).ok()?;
    re.find(body_str).map(|m| m.as_str().to_string())
}
