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
}

pub type SharedState = Arc<AppState>;
