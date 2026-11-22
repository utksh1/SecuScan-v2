//! SecuScan v2 API server entrypoint.

use secuscan_api::config::Config;
use secuscan_api::{build_app, seed, state::AppState};
use secuscan_core::PluginRegistry;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    secuscan_exec::init_tls();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secuscan=info,tower_http=warn".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => Arc::new(config),
        Err(error) => {
            tracing::error!("configuration error: {error}");
            std::process::exit(1);
        }
    };

    // Ensure the data dir exists before opening the DB.
    let db_path = config
        .db_url
        .strip_prefix("sqlite://")
        .unwrap_or(&config.db_url)
        .split('?')
        .next()
        .unwrap_or(&config.db_url)
        .to_string();
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let db = match secuscan_db::open(&config.db_url).await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("failed to open database `{}`: {e}", config.db_url);
            std::process::exit(1);
        }
    };

    seed::seed_admin(&db, &config).await;

    // Tasks left queued/running by a previous process cannot resume — fail
    // them explicitly so the UI never shows zombie scans.
    match secuscan_db::repo::tasks::fail_orphans(
        &db,
        "server restarted while the task was queued or running",
    )
    .await
    {
        Ok(n) if n > 0 => tracing::warn!("marked {n} orphaned task(s) as failed at startup"),
        Ok(_) => {}
        Err(e) => tracing::error!("orphan sweep failed: {e}"),
    }

    // Same recovery for async report jobs, plus the artifacts dir.
    if let Err(e) = std::fs::create_dir_all(&config.reports_dir) {
        tracing::error!(
            "cannot create reports dir {}: {e}",
            config.reports_dir.display()
        );
        std::process::exit(1);
    }
    match secuscan_db::repo::reports::fail_interrupted(
        &db,
        "server restarted while the report job was queued or rendering",
    )
    .await
    {
        Ok(n) if n > 0 => tracing::warn!("marked {n} interrupted report job(s) as failed"),
        Ok(_) => {}
        Err(e) => tracing::error!("report job recovery failed: {e}"),
    }

    let registry = PluginRegistry::load_dir(&config.plugins_dir);
    for issue in registry.issues() {
        tracing::warn!("plugin load issue [{}]: {}", issue.file, issue.error);
    }
    tracing::info!(
        "plugin registry: {} loaded, {} available, {} issue(s)",
        registry.len(),
        registry.all().iter().filter(|p| p.available).count(),
        registry.issues().len()
    );

    let tasks = secuscan_api::manager::TaskManager::start(db.clone(), config.clone());

    // v3.0.0 — register the DB pool with the native scanner runtime so
    // OOB-handler-creating scanners (http_request_logger, xss_exploiter)
    // can persist their handlers.
    secuscan_exec::native::set_db_pool(db.clone());

    // Max-Parity Sprint 1.1 — encryption at rest for credential-bearing
    // columns (auth profiles, VPN configs). Key comes from SECUSCAN_ENC_KEY
    // or an auto-generated key file in the data dir.
    match secuscan_core::crypto::init_from_env_or_file(&config.data_dir) {
        Ok(source) => tracing::info!("at-rest encryption enabled (key source: {source})"),
        Err(e) => {
            tracing::error!("failed to initialize at-rest encryption: {e}");
            std::process::exit(1);
        }
    }

    // v3.1.0 — reconcile VPN profile statuses (detect tunnels that died
    // while the server was down).
    secuscan_api::vpn_manager::reconcile(&db).await;

    // Sprint 4 (#34) — distributed execution bookkeeping: release claims
    // held by dead workers and prune the fleet registry.
    if let Err(e) = secuscan_db::repo::tasks::release_stale_claims(&db, 120).await {
        tracing::warn!("stale claim release failed: {e}");
    }
    if let Err(e) = secuscan_db::repo::misc::prune_dead_workers(&db, 120).await {
        tracing::warn!("worker prune failed: {e}");
    }
    let state = Arc::new(AppState {
        rate_limiter: secuscan_api::rate_limit::RateLimiter::from_env(),
        db,
        config: config.clone(),
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        tasks,
    });

    // Recurring-scan scheduler: one background worker processing due
    // schedules on a fixed tick.
    {
        let state = Arc::clone(&state);
        let tick = config.schedule_tick_secs;
        tokio::spawn(async move {
            secuscan_api::scheduler::run_loop(state, tick).await;
        });
    }

    // Seed builtin Pentest Robots (idempotent — skips names that already exist).
    if let Err(e) = secuscan_api::routes::robots::seed_builtins(&state).await {
        tracing::warn!("builtin robot seeding failed: {e}");
    }

    let app = build_app(state);

    let listener = match tokio::net::TcpListener::bind(&config.addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind {}: {e}", config.addr);
            std::process::exit(1);
        }
    };
    tracing::info!(
        "SecuScan v{} listening on http://{}",
        env!("CARGO_PKG_VERSION"),
        config.addr
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
