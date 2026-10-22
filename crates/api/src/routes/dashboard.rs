//! Dashboard summary + health.

use crate::auth::extractor::CurrentUser;
use crate::error::ApiResult;
use crate::routes::tasks::task_to_json;
use crate::routes::workspaces::parse_workspace_scope;
use crate::state::SharedState;
use axum::extract::{RawQuery, State};
use axum::Json;
use secuscan_db::repo;
use serde_json::{json, Value};

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new()
        .route("/dashboard/summary", axum::routing::get(summary))
        .route("/health", axum::routing::get(health))
}

async fn health() -> Json<Value> {
    json_health()
}

fn json_health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Default)]
struct SummaryQuery {
    workspace_id: Option<String>,
}

impl SummaryQuery {
    fn parse(raw: Option<&str>) -> Self {
        let mut q = SummaryQuery::default();
        if let Some(raw) = raw {
            for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
                if k == "workspace_id" {
                    q.workspace_id = Some(v.to_string());
                }
            }
        }
        q
    }
}

async fn summary(
    State(state): State<SharedState>,
    user: CurrentUser,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Value>> {
    let q = SummaryQuery::parse(raw.as_deref());
    let workspace = parse_workspace_scope(&state, q.workspace_id.as_deref()).await?;
    let scope_user = if user.is_admin() {
        None
    } else {
        Some(user.0.id.as_str())
    };
    let s = repo::misc::dashboard_summary(&state.db, scope_user, &workspace).await?;
    let recent = repo::tasks::recent_scoped(&state.db, scope_user, &workspace, 10).await?;
    let registry = state.registry.read().await;
    let available = registry.all().iter().filter(|p| p.available).count();
    let enabled = secuscan_db::repo::misc::enabled_map(&state.db)
        .await
        .unwrap_or_default();
    let enabled_count = registry
        .all()
        .iter()
        .filter(|p| *enabled.get(&p.plugin.id).unwrap_or(&true))
        .count();
    Ok(Json(json!({
        "tasks": {
            "total": s.tasks_total,
            "running": s.tasks_running,
            "queued": s.tasks_queued,
            "completed": s.tasks_completed,
            "failed": s.tasks_failed,
            "cancelled": s.tasks_cancelled,
        },
        "findings": {
            "critical": s.findings_critical,
            "high": s.findings_high,
            "medium": s.findings_medium,
            "low": s.findings_low,
            "info": s.findings_info,
            "new": s.findings_new,
        },
        "plugins": {
            "total": registry.len(),
            "available": available,
            "enabled": enabled_count,
            "load_issues": registry.issues().len(),
        },
        "users_total": s.users_total,
        "workflows_total": s.workflows_total,
        "recent_tasks": recent.iter().map(|t| task_to_json(t, false)).collect::<Vec<_>>(),
    })))
}
