//! Shared application state.

use crate::config::Config;
use crate::manager::TaskManager;
use secuscan_core::PluginRegistry;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub config: Arc<Config>,
    pub registry: Arc<RwLock<PluginRegistry>>,
    pub tasks: Arc<TaskManager>,
    /// Per-identity API rate limiter (Max-Parity Sprint 1.3, task 3.7).
    pub rate_limiter: crate::rate_limit::RateLimiter,
}

pub type SharedState = Arc<AppState>;
