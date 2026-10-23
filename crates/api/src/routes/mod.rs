//! Route assembly: everything mounts under `/api/v1`.

pub mod admin;
pub mod attack_surface;
pub mod auth;
pub mod auth_profiles;
pub mod branding;
pub mod collab;
pub mod dashboard;
pub mod diff;
pub mod findings;
pub mod notifications;
pub mod oob;
pub mod plugins;
pub mod reports;
pub mod robots;
pub mod schedules;
pub mod sse;
pub mod tasks;
pub mod v300_misc;
pub mod workflows;
pub mod workspaces;

use crate::state::SharedState;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

pub fn api_router() -> axum::Router<SharedState> {
    axum::Router::new()
        .merge(auth::router())
        .merge(plugins::router())
        .merge(tasks::router())
        .merge(sse::router())
        .merge(findings::router())
        .merge(reports::router())
        .merge(workflows::router())
        .merge(workspaces::router())
        .merge(diff::router())
        .merge(schedules::router())
        .merge(dashboard::router())
        .merge(admin::router())
        // v2.6.0 feature routes
        .merge(robots::router())
        .merge(attack_surface::router())
        .merge(auth_profiles::router())
        .merge(collab::router())
        .merge(branding::router())
        // v3.0.0 feature routes
        .merge(oob::router())
        .merge(notifications::router())
        .merge(v300_misc::router())
        .fallback(fallback_404)
}

async fn fallback_404() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": { "code": 404, "message": "no such API route" }
        })),
    )
}
