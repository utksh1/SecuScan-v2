//! SecuScan v2 API server library (used by the binary and integration tests).

pub mod auth;
pub mod attack_surface_aggregator;
pub mod config;
pub mod error;
pub mod manager;
pub mod report_jobs;
pub mod reports_render;
pub mod robot_runtime;
pub mod routes;
pub mod scheduler;
pub mod seed;
pub mod state;
pub mod static_files;

use crate::state::SharedState;
use axum::http::{header, Method};
use tower_http::trace::TraceLayer;

/// Build the full application (API + static SPA) — also used by tests.
pub fn build_app(state: SharedState) -> axum::Router {
    let mut app = axum::Router::new()
        .nest("/api/v1", routes::api_router())
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1 MiB JSON bodies
        .layer(TraceLayer::new_for_http());

    if let Some(origin) = state.config.cors_origin.clone() {
        let mut cors = tower_http::cors::CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PATCH,
                Method::PUT,
                Method::DELETE,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::HeaderName::from_static("x-api-key"),
            ])
            .allow_credentials(true);
        if let Ok(value) = origin.parse::<header::HeaderValue>() {
            cors = cors.allow_origin(tower_http::cors::AllowOrigin::exact(value));
        }
        app = app.layer(cors);
    }

    let frontend_dir = state.config.frontend_dir.clone();
    app.with_state(state)
        .merge(static_files::spa_service(&frontend_dir))
}
