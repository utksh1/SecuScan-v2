//! Task orchestration: spawns executions, records events, fans out SSE.

use crate::config::Config;
use secuscan_core::manifest::PluginManifest;
use secuscan_core::models::TaskStatus;
use secuscan_db::models::TaskRow;
use secuscan_db::repo;
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

/// Everything needed to finalize a task, bundled to keep signatures small.
struct FinishOutcome<'a> {
    status: TaskStatus,
    exit_code: Option<i64>,
    error: Option<&'a str>,
    findings: &'a [secuscan_core::models::Finding],
    output: &'a str,
    output_truncated: bool,
    stats_json: String,
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

impl<'a> FinishOutcome<'a> {
    fn cancelled(reason: &'a str) -> Self {
        FinishOutcome {
            status: TaskStatus::Cancelled,
            exit_code: None,
            error: Some(reason),
            findings: &[],
            output: "",
            output_truncated: false,
            stats_json: String::new(),
        }
    }
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
        self.running
            .lock()
            .await
            .insert(task_id.clone(), cancel.clone());
        let sink = EventSink::new(
            uuid::Uuid::parse_str(&task_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            self.events_tx.clone(),
        );
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            // Wait for the global slot and the plugin slot, cancellably.
            let _global_permit = tokio::select! {
                _ = cancel.cancelled() => {
                    mgr.finish_task(&task, FinishOutcome::cancelled("cancelled before start")).await;
                    mgr.cleanup(&task_id).await;
                    return;
                }
                permit = mgr.global.acquire() => permit.expect("global semaphore never closes"),
            };
            let verdict = tokio::select! {
                _ = cancel.cancelled() => {
                    mgr.finish_task(&task, FinishOutcome::cancelled("cancelled while queued")).await;
                    mgr.limiter.release_hourly(&manifest.plugin.id);
                    mgr.cleanup(&task_id).await;
                    return;
                }
                v = mgr.limiter.acquire(&manifest) => v,
            };
            let _permit = match verdict {
                LimitVerdict::Acquired(p) => p,
                LimitVerdict::Rejected { reason } => {
                    // NOTE: no release_hourly() here — a rejected acquire never
                    // reserved an hourly slot (the cap check failed first),
                    // so releasing would erode a *different* task's slot.
                    mgr.finish_task(
                        &task,
                        FinishOutcome {
                            status: TaskStatus::Failed,
                            error: Some(reason.as_str()),
                            findings: &[],
                            output: "",
                            output_truncated: false,
                            exit_code: None,
                            stats_json: String::new(),
                        },
                    )
                    .await;
                    mgr.cleanup(&task_id).await;
                    return;
                }
            };

            let _ = repo::tasks::mark_running(&mgr.pool, &task.id).await;

            // Max-Parity Sprint 1.1 (1.4) — resolve the task's auth profile
            // into concrete request material BEFORE execution. A task that
            // explicitly attached a profile but can't be authenticated must
            // fail loudly: silently scanning unauthenticated would produce
            // misleading results (login-page findings on an authed app).
            let auth = match secuscan_exec::native::resolve_for_task(
                &mgr.pool,
                task.auth_profile_id.as_deref(),
                &sink,
            )
            .await
            {
                Ok(a) => a,
                Err(e) => {
                    let err = format!("auth profile resolution failed: {e}");
                    sink.emit(TaskEvent::Error(err.clone())).await;
                    mgr.finish_task(
                        &task,
                        FinishOutcome {
                            status: TaskStatus::Failed,
                            error: Some(err.as_str()),
                            findings: &[],
                            output: "",
                            output_truncated: false,
                            exit_code: None,
                            stats_json: String::new(),
                        },
                    )
                    .await;
                    mgr.cleanup(&task_id).await;
                    return;
                }
            };

            // Max-Parity Sprint 1.2 (2.4) — arm OOB for this task when the
            // deployment has a public URL. Scanners embed the per-task marker
            // in blind payloads; hits echoing it are auto-correlated back to
            // this task by the /oob receiver and open findings.
            let oob = secuscan_exec::native::OobCtx {
                task_id: task.id.clone(),
                workspace_id: task.workspace_id.clone(),
                marker: task.oob_marker.clone(),
                public_url: mgr.config.public_url.clone(),
            };

            let outcome =
                execute_task(&manifest, &inputs, &sink, cancel.clone(), auth, Some(oob)).await;
            let outcome = secuscan_exec::with_duration(outcome, started);

            mgr.finish_task(
                &task,
                FinishOutcome {
                    status: outcome.status,
                    exit_code: outcome.exit_code.map(|c| c as i64),
                    error: outcome.error.as_deref(),
                    findings: &outcome.findings,
                    output: &outcome.output,
                    output_truncated: outcome.output_truncated,
                    stats_json: serde_json::json!({
                        "findings": outcome.findings.len(),
                        "duration_ms": outcome.duration_ms,
                        "tool_exit_nonzero": outcome.tool_exit_nonzero,
                    })
                    .to_string(),
                },
            )
            .await;
            mgr.cleanup(&task_id).await;
        });
    }

    async fn finish_task(&self, task: &TaskRow, o: FinishOutcome<'_>) {
        // v3.0.0 — apply FP memory: auto-mark findings that were previously
        // marked false positive on the same (target_fingerprint, plugin_id, title).
        let findings_with_status: Vec<(secuscan_core::models::Finding, String)> = {
            let mut out = Vec::with_capacity(o.findings.len());
            for f in o.findings {
                let fp = secuscan_db::repo::finding_dedup::is_remembered_false_positive(
                    &self.pool,
                    task.workspace_id.as_deref(),
                    &task.plugin_id,
                    &f.title,
                    &secuscan_db::repo::finding_dedup::target_fingerprint(
                        f.url.as_deref(),
                        task.target.as_deref(),
                    ),
                )
                .await
                .ok()
                .flatten();
                let status = if fp.is_some() {
                    "false_positive"
                } else {
                    "new"
                };
                out.push((f.clone(), status.to_string()));
            }
            out
        };

        let inserted_ids =
            match repo::findings::insert_many(&self.pool, &task.id, &task.plugin_id, o.findings)
                .await
            {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::error!("failed to persist findings for task {}: {e}", task.id);
                    Vec::new()
                }
            };

        // v3.0.0 — apply dedup grouping + FP-memory status overrides.
        // Max-Parity Sprint 1.1 fix: rows are attached via the ids
        // `insert_many` returned (index-aligned with findings_with_status).
        // The previous `UPDATE … ORDER BY … LIMIT 1` form is not supported
        // by SQLite and silently never attached group_id — group
        // propagation was dead until the Sprint 1.1 triage wiring exposed it.
        for (idx, (f, status)) in findings_with_status.iter().enumerate() {
            let fp_target = secuscan_db::repo::finding_dedup::target_fingerprint(
                f.url.as_deref(),
                task.target.as_deref(),
            );
            // Find or create the dedup group.
            if let Ok(group) = secuscan_db::repo::finding_dedup::find_or_create_group(
                &self.pool,
                task.workspace_id.as_deref(),
                &task.plugin_id,
                &f.title,
                &fp_target,
            )
            .await
            {
                if let Some(row_id) = inserted_ids.get(idx) {
                    let _ = sqlx::query("UPDATE findings SET group_id = ? WHERE id = ?")
                        .bind(&group.id)
                        .bind(row_id)
                        .execute(&self.pool)
                        .await;
                    // Sprint 2.1 (#24): a regenerated finding inherits the
                    // group's analyst decisions (status/override/risk/
                    // verified) so overrides survive re-scans.
                    if status != "false_positive" {
                        let _ = secuscan_db::repo::findings::inherit_group_triage(
                            &self.pool, &group.id, row_id,
                        )
                        .await;
                    }
                    if status == "false_positive" {
                        let _ = sqlx::query(
                            "UPDATE findings SET analyst_status = 'false_positive' WHERE id = ?",
                        )
                        .bind(row_id)
                        .execute(&self.pool)
                        .await;
                    }
                }
            }
        }

        // v2.6.0 — auto-aggregate findings into the Attack Surface inventory.
        // Best-effort: errors are logged inside the aggregator.
        crate::attack_surface_aggregator::aggregate_for_task(
            &self.pool,
            task.workspace_id.as_deref(),
            &task.id,
            &task.plugin_id,
            o.findings,
        )
        .await;

        // v3.0.0 — fire notification rules for this task + its findings.
        if let Err(e) =
            crate::notifications_engine::fire_for_task(&self.pool, task, o.findings).await
        {
            tracing::warn!("notification dispatch for task {} failed: {e}", task.id);
        }

        // Sprint 2.1 (#24): scan-completion callback (push instead of poll).
        // Configured at launch via `report_callback`; delivered with the
        // same HMAC-signing + SSRF guard as notification webhooks.
        if let Ok(opts) =
            serde_json::from_str::<serde_json::Value>(&task.options_json)
        {
            if let Some(cb) = opts.get("report_callback").filter(|v| !v.is_null()) {
                let pool = self.pool.clone();
                let cb = cb.clone();
                let task_id = task.id.clone();
                tokio::spawn(async move {
                    // Findings are already persisted at this point — load the
                    // rows so the callback carries DB truth (incl. triage).
                    let findings = secuscan_db::repo::findings::list_all_for_task(&pool, &task_id)
                        .await
                        .unwrap_or_default();
                    if let Err(e) =
                        crate::report_callback::deliver(&pool, &task_id, &cb, &findings).await
                    {
                        tracing::warn!("report_callback for task {task_id} failed: {e}");
                    }
                });
            }
        }

        if let Err(e) = repo::tasks::finish(
            &self.pool,
            &task.id,
            repo::tasks::FinishTask {
                status: o.status,
                exit_code: o.exit_code,
                error: o.error,
                stats_json: &o.stats_json,
                output: o.output,
                output_truncated: o.output_truncated,
            },
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

/// Hard cap on persisted events per task; beyond this, log lines are only
/// broadcast live (not stored) so a chatty tool cannot bloat the database.
const MAX_PERSISTED_EVENTS_PER_TASK: usize = 10_000;

/// Recorder: persists every envelope (subject to the per-task cap), then
/// broadcasts an SSE frame carrying the DB row id (so live subscribers and
/// DB replay can be de-duplicated). Events beyond the cap are broadcast
/// with a synthetic id above any DB id but never persisted.
async fn recorder(
    mut rx: mpsc::Receiver<EventEnvelope>,
    pool: SqlitePool,
    broadcast: broadcast::Sender<SseFrame>,
) {
    let mut persisted: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut synthetic_id: i64 = i64::MAX / 2;
    while let Some(env) = rx.recv().await {
        let payload_json = serde_json::to_string(&env.event).unwrap_or_else(|_| "{}".into());
        let level = event_level(&env.event);
        let task_key = env.task_id.to_string();

        // A finished event is always the last one for a task — drop the
        // counter so the map cannot grow without bound.
        if level == "finished" {
            persisted.remove(&task_key);
        }
        let count = persisted.entry(task_key.clone()).or_insert(0);
        if *count < MAX_PERSISTED_EVENTS_PER_TASK {
            let res = sqlx::query(
                "INSERT INTO task_events (task_id, ts, level, payload_json) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&task_key)
            .bind(&env.ts)
            .bind(level)
            .bind(&payload_json)
            .execute(&pool)
            .await;
            *count += 1;
            match res {
                Ok(r) => {
                    let id = r.last_insert_rowid();
                    let _ = broadcast.send(SseFrame {
                        task_id: task_key,
                        id,
                        ts: env.ts,
                        payload_json,
                    });
                }
                Err(e) => {
                    tracing::error!("event persist failed: {e}");
                }
            }
        } else {
            // Cap reached: broadcast only, with a synthetic always-increasing
            // id so live dedup logic still works.
            synthetic_id += 1;
            let _ = broadcast.send(SseFrame {
                task_id: task_key,
                id: synthetic_id,
                ts: env.ts,
                payload_json,
            });
        }
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
