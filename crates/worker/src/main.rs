//! `secuscan-worker` — an out-of-process scan executor (Max-Parity Sprint 4,
//! issue #34).
//!
//! Workers share the API's SQLite database and claim queued tasks with an
//! atomic `BEGIN IMMEDIATE` transaction, so several workers (or the API's
//! own in-process TaskManager) can run side by side without double-claiming.
//! Each worker:
//!
//! * registers with a name + JSON capability tags + a max-concurrency cap,
//! * heartbeats every 10 s (the API prunes workers and releases claims
//!   whose heartbeat lapsed),
//! * claims → executes (the same `execute_task` path as the API) → persists
//!   findings → releases the claim,
//! * exits when `SECUSCAN_WORKER_IDLE_EXIT=secs` elapses without work (for
//!   autoscaled/CI workers).
//!
//! Configuration: `SECUSCAN_DB_URL`, `SECUSCAN_WORKER_NAME`, `SECUSCAN_WORKER_TAGS`
//! (comma-separated), `SECUSCAN_WORKER_MAX_CONCURRENT`, `SECUSCAN_ENC_KEY`,
//! `SECUSCAN_PLUGINS_DIR`. One worker per host needs nothing else; the
//! single-node default (no workers registered) keeps the API's in-process
//! execution.

use secuscan_db::repo;
use std::time::Duration;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Encryption: same key file/env contract as the API, so a worker can
    // decrypt credential-bearing columns.
    // Same contract as the API: init_from_env_or_file checks
    // SECUSCAN_ENC_KEY first, then the shared data-dir key file.
    let _ = secuscan_core::crypto::init_from_env_or_file(std::path::Path::new(&env_or(
        "SECUSCAN_DATA_DIR",
        "./data",
    )));
    secuscan_exec::init_tls();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let db_url = env_or("SECUSCAN_DB_URL", "sqlite://./data/secuscan.db?mode=rwc");
    let pool = secuscan_db::open(&db_url).await?;
    secuscan_exec::native::set_db_pool(pool.clone());

    let worker_id = uuid::Uuid::new_v4().to_string();
    let name = env_or("SECUSCAN_WORKER_NAME", &format!("worker-{}", &worker_id[..8]));
    let tags: Vec<String> = env_or("SECUSCAN_WORKER_TAGS", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let max_concurrent: i64 = env_or("SECUSCAN_WORKER_MAX_CONCURRENT", "4").parse().unwrap_or(4);
    let poll_interval = Duration::from_secs(
        env_or("SECUSCAN_WORKER_POLL_SECS", "2").parse().unwrap_or(2).max(1),
    );
    let idle_exit_secs: Option<u64> = std::env::var("SECUSCAN_WORKER_IDLE_EXIT")
        .ok()
        .and_then(|v| v.parse().ok());
    let heartbeat_secs: u64 = 10;

    repo::misc::register_worker(
        &pool,
        &worker_id,
        &name,
        &serde_json::to_string(&tags).unwrap_or_else(|_| "[]".into()),
        max_concurrent,
    )
    .await?;
    tracing::info!(
        "worker {name} ({worker_id}) registered: tags={tags:?} max_concurrent={max_concurrent}"
    );

    let mut last_heartbeat = tokio::time::Instant::now();
    let mut last_work = tokio::time::Instant::now();
    let mut active: usize = 0;

    loop {
        tokio::time::sleep(poll_interval).await;

        // Heartbeat every 10 s.
        if last_heartbeat.elapsed() >= Duration::from_secs(heartbeat_secs) {
            last_heartbeat = tokio::time::Instant::now();
            if let Err(e) = repo::misc::heartbeat_worker(&pool, &worker_id).await {
                tracing::warn!("heartbeat failed: {e}");
            }
        }

        // Capacity check: never exceed the worker's own cap.
        if active >= max_concurrent as usize {
            continue;
        }

        match repo::tasks::claim_next(&pool, &worker_id).await {
            Ok(Some(task)) => {
                last_work = tokio::time::Instant::now();
                let _ = repo::misc::bump_worker_claims(&pool, &worker_id, 1).await;
                tracing::info!("claimed task {} ({})", task.id, task.plugin_id);
                active += 1;
                tokio::spawn(run_task(pool.clone(), worker_id.clone(), task));
            }
            Ok(None) => {
                // Idle: optionally exit (CI/autoscaled workers).
                if let Some(idle) = idle_exit_secs {
                    if last_work.elapsed() >= Duration::from_secs(idle) {
                        tracing::info!("idle for {idle}s — worker exiting");
                        break;
                    }
                }
            }
            Err(e) => tracing::error!("claim failed: {e}"),
        }
    }
    Ok(())
}

/// Execute one claimed task: same `execute_task` path as the API's manager.
async fn run_task(
    pool: sqlx::SqlitePool,
    worker_id: String,
    task: secuscan_db::models::TaskRow,
) {
    let started = std::time::Instant::now();
    let _ = repo::tasks::mark_running(&pool, &task.id).await;

    // Load the manifest from the shared plugins dir.
    let plugins_dir = env_or("SECUSCAN_PLUGINS_DIR", "./plugins");
    let manifest = match secuscan_core::PluginRegistry::load_dir(std::path::Path::new(&plugins_dir))
        .get(&task.plugin_id)
        .cloned()
    {
        Some(m) => m,
        None => {
            let _ = repo::tasks::finish(
                &pool,
                &task.id,
                repo::tasks::FinishTask {
                    status: secuscan_core::models::TaskStatus::Failed,
                    exit_code: None,
                    error: Some(&format!("plugin `{}` not available on this worker", task.plugin_id)),
                    stats_json: "{}",
                    output: "",
                    output_truncated: false,
                    status_detail: Some("plugin_unavailable_on_worker"),
                },
            )
            .await;
            finish_worker_bookkeeping(&pool, &worker_id, &task.id).await;
            return;
        }
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<secuscan_exec::EventEnvelope>(4096);
    let sink = secuscan_exec::EventSink::new(
        uuid::Uuid::new_v4(),
        tx,
    );
    // Persist events exactly like the API's recorder (task_events table).
    let rec_pool = pool.clone();
    let rec_ts = secuscan_db::now();
    let recorder = tokio::spawn(async move {
        while let Some(env) = rx.recv().await {
            let level = match &env.event {
                secuscan_exec::TaskEvent::Error(_) => "error",
                secuscan_exec::TaskEvent::Warn(_) => "warn",
                _ => "info",
            };
            let _ = sqlx::query(
                "INSERT INTO task_events (task_id, ts, level, payload_json) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(env.task_id.to_string())
            .bind(&rec_ts)
            .bind(level)
            .bind(&serde_json::to_string(&env.event).unwrap_or_default())
            .execute(&rec_pool)
            .await;
        }
    });

    let cancel = tokio_util::sync::CancellationToken::new();
    let inputs: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&task.inputs_json).unwrap_or_default();

    let outcome = secuscan_exec::execute_task(
        &manifest,
        &inputs,
        &sink,
        cancel,
        None, // auth profiles resolve on the API side; workers run unauthenticated
        None, // OOB context: the receiver lives in the API process
        None, // max_scan_time: the API's manager caps when it spawns locally
    )
    .await;
    drop(sink);
    let _ = recorder.await;

    let _ = repo::tasks::finish(
        &pool,
        &task.id,
        repo::tasks::FinishTask {
            status: outcome.status,
            exit_code: outcome.exit_code.map(|c| c as i64),
            error: outcome.error.as_deref(),
            stats_json: &serde_json::json!({
                "findings": outcome.findings.len(),
                "duration_ms": outcome.duration_ms,
                "worker": worker_id,
            })
            .to_string(),
            output: &outcome.output,
            output_truncated: outcome.output_truncated,
            status_detail: None,
        },
    )
    .await;

    // Persist findings through the standard pipeline (FP memory, dedup).
    if !outcome.findings.is_empty() {
        if let Err(e) = repo::findings::insert_many_with_provenance(
            &pool,
            &task.id,
            &task.plugin_id,
            Some(manifest.plugin.version.as_str()),
            &outcome.findings,
        )
        .await
        {
            tracing::error!("failed to persist findings for task {}: {e}", task.id);
        }
    }

    finish_worker_bookkeeping(&pool, &worker_id, &task.id).await;
    tracing::info!(
        "task {} finished: {:?} ({} findings, {:.1?})",
        task.id,
        outcome.status,
        outcome.findings.len(),
        started.elapsed()
    );
}

async fn finish_worker_bookkeeping(pool: &sqlx::SqlitePool, worker_id: &str, _task_id: &str) {
    let _ = repo::misc::bump_worker_claims(pool, worker_id, -1).await;
}
