//! Task orchestration: spawns executions, records events, fans out SSE.

use crate::config::Config;
use secuscan_core::manifest::PluginManifest;
use secuscan_core::models::TaskStatus;
use secuscan_db::repo;
use secuscan_db::models::TaskRow;
use secuscan_exec::events::{EventEnvelope, EventSink, TaskEvent};
use secuscan_exec::{execute_task, LimitVerdict, PluginLimiter};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;

/// SSE broadcast frame (JSON-encoded `data:` payload with DB id for replay
/// cursoring).
#[derive(Debug, Clone)]
pub struct SseFrame {
    pub task_id: String,
    pub id: i64,
    pub ts: String,
    pub payload_json: String,
}

pub struct TaskManager {
    pub pool: SqlitePool,
    pub limiter: Arc<PluginLimiter>,
    pub config: Arc<Config>,
    events_tx: mpsc::Sender<EventEnvelope>,
    broadcast: broadcast::Sender<SseFrame>,
    running: Mutex<HashMap<String, CancellationToken>>,
    /// Global running-task cap.
    global: tokio::sync::Semaphore,
}

impl TaskManager {
    /// Build the manager and spawn the event recorder task.
    pub fn start(pool: SqlitePool, config: Arc<Config>) -> Arc<Self> {
        let (events_tx, events_rx) = mpsc::channel::<EventEnvelope>(4096);
        let (broadcast, _) = broadcast::channel::<SseFrame>(1024);
        let mgr = TaskManager {
            pool: pool.clone(),
            limiter: Arc::new(PluginLimiter::new()),
            config: config.clone(),
            events_tx,
            broadcast: broadcast.clone(),
            running: Mutex::new(HashMap::new()),
            global: tokio::sync::Semaphore::new(config.max_concurrent_tasks.max(1)),
        };
        tokio::spawn(recorder(events_rx, pool, broadcast));
        Arc::new(mgr)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SseFrame> {
        self.broadcast.subscribe()
    }

    pub async fn is_running(&self, task_id: &str) -> bool {
        self.running.lock().await.contains_key(task_id)
    }

    /// Request cancellation of a running (or queued) task.
    pub async fn cancel(&self, task_id: &str) -> bool {
        let running = self.running.lock().await;
        match running.get(task_id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    /// Spawn execution for a task row that has passed validation.
    pub async fn spawn(
        self: &Arc<Self>,
        task: TaskRow,
        manifest: Arc<PluginManifest>,
        inputs: std::collections::BTreeMap<String, serde_json::Value>,
    ) {
        let mgr = Arc::clone(self);
        let task_id = task.id.clone();
        let cancel = CancellationToken::new();
        self.running.lock().await.insert(task_id.clone(), cancel.clone());
        let sink = EventSink::new(
            uuid::Uuid::parse_str(&task_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            self.events_tx.clone(),
        );
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            // Wait for the global slot and the plugin slot, cancellably.
            let _global_permit = loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        mgr.finish_task(
                            &task, TaskStatus::Cancelled, None, None, &[], "", false, "cancelled before start",
                        ).await;
                        mgr.cleanup(&task_id).await;
                        return;
                    }
                    permit = mgr.global.acquire() => break permit.expect("global semaphore never closes"),
                }
            };
            let verdict = loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        mgr.finish_task(
                            &task, TaskStatus::Cancelled, None, None, &[], "", false, "cancelled while queued",
                        ).await;
                        mgr.limiter.release_hourly(&manifest.plugin.id);
                        mgr.cleanup(&task_id).await;
                        return;
                    }
                    v = mgr.limiter.acquire(&manifest) => break v,
                }
            };
            let _permit = match verdict {
                LimitVerdict::Acquired(p) => p,
                LimitVerdict::Rejected { reason } => {
                    mgr.finish_task(
                        &task, TaskStatus::Failed, None, None, &[], "", false, &reason,
                    ).await;
                    mgr.limiter.release_hourly(&manifest.plugin.id);
                    mgr.cleanup(&task_id).await;
                    return;
                }
            };

            let _ = repo::tasks::mark_running(&mgr.pool, &task.id).await;
            let outcome = execute_task(&manifest, &inputs, &sink, cancel.clone()).await;
            let outcome = secuscan_exec::with_duration(outcome, started);

            mgr.finish_task(
                &task,
                outcome.status,
                outcome.exit_code.map(|c| c as i64),
                outcome.error.as_deref(),
                &outcome.findings,
                &outcome.output,
                outcome.output_truncated,
                &serde_json::json!({
                    "findings": outcome.findings.len(),
                    "duration_ms": outcome.duration_ms,
                    "tool_exit_nonzero": outcome.tool_exit_nonzero,
                })
                .to_string(),
            )
            .await;
            mgr.cleanup(&task_id).await;
        });
    }

    async fn finish_task(
        &self,
        task: &TaskRow,
        status: TaskStatus,
        exit_code: Option<i64>,
        error: Option<&str>,
        findings: &[secuscan_core::models::Finding],
        output: &str,
        output_truncated: bool,
        stats_json: &str,
    ) {
        if let Err(e) =
            repo::findings::insert_many(&self.pool, &task.id, &task.plugin_id, findings).await
        {
            tracing::error!("failed to persist findings for task {}: {e}", task.id);
        }
        if let Err(e) = repo::tasks::finish(
            &self.pool,
            &task.id,
            status,
            exit_code,
            error,
            stats_json,
            output,
            output_truncated,
        )
        .await
        {
            tracing::error!("failed to finalize task {}: {e}", task.id);
        }
    }

    async fn cleanup(&self, task_id: &str) {
        self.running.lock().await.remove(task_id);
    }
}

/// Recorder: persists every envelope, then broadcasts an SSE frame carrying
/// the DB row id (so live subscribers and DB replay can be de-duplicated).
async fn recorder(
    mut rx: mpsc::Receiver<EventEnvelope>,
    pool: SqlitePool,
    broadcast: broadcast::Sender<SseFrame>,
) {
    while let Some(env) = rx.recv().await {
        let payload_json = serde_json::to_string(&env.event).unwrap_or_else(|_| "{}".into());
        let level = event_level(&env.event);
        let res = sqlx::query(
            "INSERT INTO task_events (task_id, ts, level, payload_json) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&env.task_id.to_string())
        .bind(&env.ts)
        .bind(level)
        .bind(&payload_json)
        .execute(&pool)
        .await;
        let id = match res {
            Ok(r) => r.last_insert_rowid(),
            Err(e) => {
                tracing::error!("event persist failed: {e}");
                continue;
            }
        };
        let _ = broadcast.send(SseFrame {
            task_id: env.task_id.to_string(),
            id,
            ts: env.ts,
            payload_json,
        });
    }
}

fn event_level(e: &TaskEvent) -> &'static str {
    match e {
        TaskEvent::Phase(_) => "phase",
        TaskEvent::LogLine { .. } => "log",
        TaskEvent::Info(_) => "info",
        TaskEvent::Warn(_) => "warn",
        TaskEvent::Error(_) => "error",
        TaskEvent::Progress { .. } => "progress",
        TaskEvent::Finished { .. } => "finished",
    }
}
