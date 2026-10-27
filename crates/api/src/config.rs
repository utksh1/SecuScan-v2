//! Environment-driven server configuration.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub addr: SocketAddr,
    pub db_url: String,
    pub jwt_secret: String,
    pub plugins_dir: std::path::PathBuf,
    /// Built frontend bundle served as the SPA.
    pub frontend_dir: std::path::PathBuf,
    pub data_dir: std::path::PathBuf,
    /// Where async report-job artifacts are written.
    pub reports_dir: std::path::PathBuf,
    pub admin_email: String,
    pub admin_password: Option<String>,
    /// Capabilities that no plugin may require (e.g. `docker,cloud`).
    pub denied_capabilities: Vec<String>,
    pub allow_register: bool,
    /// Optional CORS origin (e.g. `http://localhost:5173` for split dev).
    pub cors_origin: Option<String>,
    /// Set the Secure attribute on auth cookies (enable when serving HTTPS).
    pub cookie_secure: bool,
    /// Global cap on simultaneously *running* tasks.
    pub max_concurrent_tasks: usize,
    /// How often the recurring-scan scheduler wakes to process due
    /// schedules (seconds).
    pub schedule_tick_secs: u64,
    /// Phase 0 (Max-Parity Plan) — provider-agnostic LLM endpoint. Parsed
    /// now, consumed by the Phase 3 AI layer (enrichment, classifier,
    /// Mini-Specter). Unused until then.
    pub ai_base_url: Option<String>,
    /// Phase 0 — API key for the LLM endpoint. Never logged.
    pub ai_api_key: Option<String>,
    /// Optional explicit at-rest encryption key; when unset a key file is
    /// generated under `data_dir` (see `secuscan_core::crypto`).
    pub enc_key: Option<String>,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

impl Config {
    pub fn from_env() -> Config {
        let data_dir = std::path::PathBuf::from(env_or("SECUSCAN_DATA_DIR", "./data"));
        let reports_dir = std::env::var("SECUSCAN_REPORTS_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| data_dir.join("reports"));
        let db_url = env_or(
            "SECUSCAN_DB_URL",
            &format!(
                "sqlite://{}?mode=rwc",
                data_dir.join("secuscan.db").display()
            ),
        );
        let jwt_secret = match std::env::var("SECUSCAN_JWT_SECRET") {
            Ok(s) if !s.trim().is_empty() => s,
            _ => {
                let secret = secuscan_db::generate_token("jwtsecret");
                tracing::warn!(
                    "SECUSCAN_JWT_SECRET is not set; generated an ephemeral secret \
                     (sessions will not survive restarts). Set it for production use."
                );
                secret
            }
        };
        Config {
            addr: env_or("SECUSCAN_ADDR", "0.0.0.0:8080")
                .parse()
                .expect("SECUSCAN_ADDR must be a valid socket address"),
            db_url,
            jwt_secret,
            plugins_dir: std::path::PathBuf::from(env_or("SECUSCAN_PLUGINS_DIR", "./plugins")),
            frontend_dir: std::path::PathBuf::from(env_or(
                "SECUSCAN_FRONTEND_DIR",
                "./frontend/dist",
            )),
            data_dir,
            reports_dir,
            admin_email: env_or("SECUSCAN_ADMIN_EMAIL", "admin@secuscan.local"),
            admin_password: std::env::var("SECUSCAN_ADMIN_PASSWORD")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            denied_capabilities: std::env::var("SECUSCAN_DENIED_CAPABILITIES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            allow_register: env_or("SECUSCAN_ALLOW_REGISTER", "false") == "true",
            cors_origin: std::env::var("SECUSCAN_CORS_ORIGIN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            cookie_secure: env_or("SECUSCAN_COOKIE_SECURE", "false") == "true",
            max_concurrent_tasks: env_or("SECUSCAN_MAX_CONCURRENT_TASKS", "8")
                .parse()
                .unwrap_or(8),
            schedule_tick_secs: env_or("SECUSCAN_SCHEDULE_TICK_SECS", "30")
                .parse()
                .unwrap_or(30),
            ai_base_url: std::env::var("SECUSCAN_AI_BASE_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            ai_api_key: std::env::var("SECUSCAN_AI_API_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            enc_key: std::env::var("SECUSCAN_ENC_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        }
    }
}
