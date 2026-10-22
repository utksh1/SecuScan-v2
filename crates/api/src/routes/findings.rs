//! Findings explorer + triage.

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::workspaces::parse_workspace_scope;
use crate::state::SharedState;
use axum::extract::{Path, RawQuery, State};
use axum::Json;
use secuscan_core::models::AnalystStatus;
use secuscan_db::models::FindingRow;
use secuscan_db::repo;
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/findings", axum::routing::get(list))
        .route("/findings/:id", axum::routing::get(get_one))
        .route("/findings/:id/triage", axum::routing::patch(triage))
}

pub fn finding_to_json(f: &FindingRow) -> Value {
    json!({
        "id": f.id,
        "task_id": f.task_id,
        "plugin_id": f.plugin_id,
        "severity": f.severity,
        "kind": f.kind,
        "analyst_status": f.analyst_status,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "remediation": f.remediation,
        "proof": f.proof,
        "url": f.url,
        "metadata": serde_json::from_str::<Value>(&f.metadata_json).unwrap_or(json!({})),
        "created_at": f.created_at,
    })
}

/// Parsed query string supporting repeated keys (e.g.
/// `?severity=critical&severity=high`). serde_urlencoded rejects duplicate
/// keys for struct fields, so we parse the raw query ourselves.
#[derive(Default)]
struct ListQuery {
    task_id: Option<String>,
    severity: Vec<String>,
    kind: Option<String>,
    analyst_status: Option<String>,
    category: Option<String>,
    search: Option<String>,
    workspace_id: Option<String>,
    limit: i64,
    offset: i64,
}

impl ListQuery {
    fn parse(raw: Option<&str>) -> Self {
        let mut q = ListQuery {
            limit: 100,
            ..Default::default()
        };
        if let Some(raw) = raw {
            for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
                let v = v.to_string();
                match k.as_ref() {
                    "task_id" => q.task_id = Some(v),
                    "severity" => q.severity.push(v),
                    "kind" => q.kind = Some(v),
                    "analyst_status" => q.analyst_status = Some(v),
                    "category" => q.category = Some(v),
                    "search" => q.search = Some(v),
                    "workspace_id" => q.workspace_id = Some(v),
                    "limit" => q.limit = v.parse().unwrap_or(100),
                    "offset" => q.offset = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        q
    }
}

fn validate_enums(q: &ListQuery) -> ApiResult<()> {
    for s in &q.severity {
        if secuscan_core::models::Severity::parse(s).is_none() {
            return Err(ApiError::BadRequest(format!("unknown severity `{s}`")));
        }
    }
    if let Some(k) = &q.kind {
        if secuscan_core::models::FindingKind::parse(k).is_none() {
            return Err(ApiError::BadRequest(format!("unknown kind `{k}`")));
        }
    }
    if let Some(s) = &q.analyst_status {
        if AnalystStatus::parse(s).is_none() {
            return Err(ApiError::BadRequest(format!(
                "unknown analyst_status `{s}`"
            )));
        }
    }
    Ok(())
}

async fn list(
    State(state): State<SharedState>,
    user: CurrentUser,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Value>> {
    let q = ListQuery::parse(raw.as_deref());
    validate_enums(&q)?;
    let workspace = parse_workspace_scope(&state, q.workspace_id.as_deref()).await?;
    // Access control: non-admins are scoped to their own tasks via the join.
    let filters = repo::findings::FindingFilters {
        task_id: q.task_id,
        user_id: if user.is_admin() {
            None
        } else {
            Some(user.0.id.clone())
        },
        severity: q.severity.clone(),
        kind: q.kind,
        analyst_status: q.analyst_status,
        category: q.category,
        search: q.search,
        workspace,
        limit: q.limit,
        offset: q.offset,
    };
    let items = repo::findings::list(&state.db, &filters).await?;
    let total = repo::findings::count(&state.db, &filters).await?;
    Ok(Json(json!({
        "items": items.iter().map(finding_to_json).collect::<Vec<_>>(),
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
    let f = load_finding_for_user(&state, &user, &id).await?;
    Ok(Json(finding_to_json(&f)))
}

async fn load_finding_for_user(
    state: &SharedState,
    user: &CurrentUser,
    id: &str,
) -> ApiResult<FindingRow> {
    let f = repo::findings::get(&state.db, id).await?;
    let task = repo::tasks::get(&state.db, &f.task_id).await?;
    if !user.is_admin() && task.user_id != user.0.id {
        return Err(ApiError::NotFound(format!("finding {id}")));
    }
    Ok(f)
}

#[derive(Deserialize)]
struct TriageRequest {
    analyst_status: String,
}

async fn triage(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<TriageRequest>,
) -> ApiResult<Json<Value>> {
    user.require_scanner()?;
    let status = AnalystStatus::parse(&req.analyst_status).ok_or_else(|| {
        ApiError::BadRequest(format!("unknown analyst_status `{}`", req.analyst_status))
    })?;
    load_finding_for_user(&state, &user, &id).await?;
    let updated = repo::findings::update_analyst_status(&state.db, &id, status).await?;
    Ok(Json(finding_to_json(&updated)))
}
