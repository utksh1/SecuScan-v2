//! Dashboard summary + health.

use crate::auth::extractor::CurrentUser;
use crate::error::ApiResult;
use crate::routes::tasks::task_to_json;
use crate::state::SharedState;
use axum::extract::State;
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

async fn summary(
    State(state): State<SharedState>,
    user: CurrentUser,
) -> ApiResult<Json<Value>> {
    let s = repo::misc::dashboard_summary(&state.db).await?;
    let scope_user = if user.is_admin() { None } else { Some(user.0.id.as_str()) };
    let recent = repo::tasks::recent(&state.db, scope_user, 10).await?;
    let registry = state.registry.read().await;
    let available = registry.all().iter().filter(|p| p.available).count();
    let enabled = secuscan_db::repo::misc::enabled_map(&state.db).await.unwrap_or_default();
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
