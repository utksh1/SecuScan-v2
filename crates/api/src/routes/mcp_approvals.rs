//! Out-of-band, one-use human authorization for MCP-initiated scans.
//! The MCP tool catalogue does NOT expose approval creation. An admin must
//! approve the exact scanner user and request through the authenticated API.
use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::tasks::{
    admit_request, task_to_json, validate_and_create_task, Admitted, StartTaskRequest,
};
use crate::state::SharedState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use secuscan_db::repo;
use secuscan_db::{generate_token, new_id, now, sha256_hex};
use serde::Deserialize;
use serde_json::{json, Value};

const APPROVAL_TTL_SECS: i64 = 300;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/mcp/scan-approvals", axum::routing::post(approve))
        .route("/mcp/scans", axum::routing::post(start))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveRequest {
    /// Must be a different, non-viewer user account from the approver.
    issued_to_user_id: String,
    scan: StartTaskRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartApprovedRequest {
    approval_token: String,
    scan: StartTaskRequest,
}

fn request_hash(req: &StartTaskRequest, admitted: &Admitted) -> String {
    // Hash the normalized inputs and every scope-affecting request dimension.
    // Keys are stable (BTreeMap), so map insertion order does not change the hash.
    let document = json!({
        "plugin_id": req.plugin_id,
        "plugin_version": admitted.manifest.plugin.version,
        "engine": format!("{:?}", admitted.manifest.engine),
        "safety_level": admitted.manifest.safety.level.label(),
        "capabilities": admitted.manifest.safety.capabilities,
        "requires_consent": admitted.manifest.safety.requires_consent,
        "allowed_targets": admitted.manifest.safety.allowed_targets,
        "inputs": admitted.normalized,
        "target": admitted.target,
        "preset": req.preset,
        "workspace_id": req.workspace_id,
        "auth_profile_id": req.auth_profile_id,
    });
    sha256_hex(&document.to_string())
}

async fn approve(
    State(state): State<SharedState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_admin()?;
    // API keys are meant for automation. Approval must use the interactive
    // human's authenticated JWT, not an unattended API key.
    let has_bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));
    if !has_bearer || headers.contains_key("x-api-key") {
        return Err(ApiError::Forbidden(
            "MCP approvals require an interactive administrator JWT".into(),
        ));
    }
    if !req.scan.consent_granted {
        return Err(ApiError::BadRequest(
            "human approval requires consent_granted=true for the exact scan".into(),
        ));
    }
    if req.issued_to_user_id == user.0.id {
        return Err(ApiError::Forbidden(
            "approver and MCP scanner must use distinct accounts".into(),
        ));
    }
    let scanner = repo::users::find_by_id(&state.db, &req.issued_to_user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("MCP scanner account not found".into()))?;
    if scanner.role == "viewer" {
        return Err(ApiError::Forbidden(
            "MCP scanner account must have the scanner role".into(),
        ));
    }
    let scanner = CurrentUser(scanner);
    // Evaluate against the intended scanner identity, not the approver.
    let admitted = admit_request(&state, &scanner, &req.scan).await?;
    let target = admitted
        .target
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest("MCP approvals require a concrete scan target".into())
        })?;
    if let Some(profile_id) = req.scan.auth_profile_id.as_deref() {
        let profile = repo::auth_profiles::get(&state.db, profile_id).await?;
        crate::access::require_owner(&scanner, &profile.created_by)?;
    }

    let fingerprint = request_hash(&req.scan, &admitted);
    let approval_id = new_id();
    let token = generate_token("mcpap");
    let expires_at_epoch = chrono::Utc::now().timestamp() + APPROVAL_TTL_SECS;
    sqlx::query(
        "INSERT INTO mcp_scan_approvals
         (id, token_hash, approved_by, issued_to_user_id, request_hash,
          plugin_id, target, workspace_id, created_at, expires_at_epoch)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .bind(&approval_id)
    .bind(sha256_hex(&token))
    .bind(&user.0.id)
    .bind(&scanner.0.id)
    .bind(fingerprint)
    .bind(&req.scan.plugin_id)
    .bind(target)
    .bind(&req.scan.workspace_id)
    .bind(now())
    .bind(expires_at_epoch)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("failed to store approval: {e}")))?;

    // Raw token is returned only once. Never include it in audit logs.
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "approval_id": approval_id,
            "approval_token": token,
            "expires_at_epoch": expires_at_epoch,
            "issued_to_user_id": scanner.0.id,
            "plugin_id": req.scan.plugin_id,
            "target": target,
            "single_use": true
        })),
    ))
}

async fn start(
    State(state): State<SharedState>,
    user: CurrentUser,
    Json(req): Json<StartApprovedRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require_scanner()?;
    if !req.scan.consent_granted {
        return Err(ApiError::Forbidden(
            "MCP scan requires explicit consent and an out-of-band approval".into(),
        ));
    }
    if !req.approval_token.starts_with("mcpap_") || req.approval_token.len() != 70 {
        return Err(ApiError::Forbidden(
            "missing or invalid MCP approval token".into(),
        ));
    }

    // Re-run the full normal admission policy at consumption time: admin may
    // have disabled a capability or changed target restrictions since approval.
    let admitted = admit_request(&state, &user, &req.scan).await?;
    let fingerprint = request_hash(&req.scan, &admitted);
    // One statement atomically consumes one valid, not-expired grant. Concurrent
    // replay attempts cannot both succeed.
    let consumed = sqlx::query(
        "UPDATE mcp_scan_approvals SET consumed_at = ?1
         WHERE token_hash = ?2 AND issued_to_user_id = ?3 AND request_hash = ?4
           AND consumed_at IS NULL AND expires_at_epoch > ?5",
    )
    .bind(now())
    .bind(sha256_hex(&req.approval_token))
    .bind(&user.0.id)
    .bind(fingerprint)
    .bind(chrono::Utc::now().timestamp())
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("approval verification failed: {e}")))?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::Forbidden(
            "MCP approval expired, already used, wrong user, or request scope changed".into(),
        ));
    }

    let token_hash = sha256_hex(&req.approval_token);
    let (task, manifest, inputs) =
        validate_and_create_task(&state, &user, &req.scan, None, None).await?;
    // Persist audit linkage before starting the actual scan.
    let approval_id: String =
        sqlx::query_scalar("SELECT id FROM mcp_scan_approvals WHERE token_hash = ?1")
            .bind(&token_hash)
            .fetch_one(&state.db)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to fetch audit link: {e}")))?;
    let mut options: Value = serde_json::from_str(&task.options_json).unwrap_or(json!({}));
    options["origin"] = json!("mcp");
    options["mcp_approval_id"] = json!(approval_id);
    sqlx::query("UPDATE tasks SET options_json = ?1 WHERE id = ?2")
        .bind(options.to_string())
        .bind(&task.id)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to record task audit: {e}")))?;
    sqlx::query("UPDATE mcp_scan_approvals SET task_id = ?1 WHERE token_hash = ?2")
        .bind(&task.id)
        .bind(&token_hash)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to link approval to task: {e}")))?;
    state.tasks.spawn(task.clone(), manifest, inputs).await;
    let mut result = task_to_json(&task, false);
    result["options"] = options;
    Ok((StatusCode::CREATED, Json(result)))
}
