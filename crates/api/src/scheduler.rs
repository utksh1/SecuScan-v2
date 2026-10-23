//! Recurring-scan scheduler: a background worker that launches tasks from
//! due schedules. `run_due` is a pure "process everything due now" pass so
//! tests can drive it deterministically; the production loop just calls it
//! on a fixed tick.
//!
//! Design invariants:
//! * Every launch goes through the full task admission pipeline
//!   (`validate_and_create_task`) — plugin availability, enabled flags,
//!   capability denials, target policy and consent are re-evaluated on
//!   *every* occurrence, so tightening policy after a schedule was created
//!   stops future runs instead of blind-firing them.
//! * Missed occurrences are skipped, never replayed: the anchor is always
//!   re-anchored to `now + interval` (a schedule that was disabled or whose
//!   server was down for a day does not fire a burst of catch-up scans).
//! * An occurrence whose previous task is still queued/running is skipped
//!   (overlap guard) — one scan of a target at a time per schedule. The
//!   run-now endpoint intentionally bypasses this guard (explicit user
//!   action), so a manual run can briefly overlap the automated one.
//! * Admission failures are recorded on the schedule (`last_error`) and the
//!   anchor still advances: the next interval retries automatically.

use crate::auth::extractor::CurrentUser;
use crate::routes::tasks::{validate_and_create_task, StartTaskRequest};
use crate::state::SharedState;
use secuscan_core::models::add_seconds_iso;
use secuscan_db::models::ScheduleRow;
use secuscan_db::repo;
use std::collections::BTreeMap;

/// Outcome of processing one due schedule — returned (and logged) so tests
/// and operators can see exactly what a pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DueOutcome {
    /// A task was launched (schedule id, task id).
    Launched(String, String),
    /// Skipped because the previous run is still active (schedule id).
    OverlapSkipped(String),
    /// Admission failed (schedule id, error message).
    Rejected(String, String),
}

/// Process every due schedule once. Returns one outcome per processed
/// schedule, in due order.
pub async fn run_due(state: &SharedState) -> Vec<DueOutcome> {
    let now_ts = secuscan_db::now();
    let due = match repo::schedules::list_due(&state.db, &now_ts).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("scheduler: due query failed: {e}");
            return Vec::new();
        }
    };

    let mut outcomes = Vec::with_capacity(due.len());
    for s in due {
        let outcome = process_one(state, &s, &now_ts).await;
        tracing::info!(
            "scheduler: schedule {} ({}) -> {}",
            s.id,
            s.name,
            match &outcome {
                DueOutcome::Launched(_, task) => format!("launched task {task}"),
                DueOutcome::OverlapSkipped(_) => "skipped (previous run still active)".into(),
                DueOutcome::Rejected(_, err) => format!("rejected: {err}"),
            }
        );
        outcomes.push(outcome);
    }
    outcomes
}

async fn process_one(state: &SharedState, s: &ScheduleRow, now_ts: &str) -> DueOutcome {
    let next_anchor = add_seconds_iso(now_ts, s.interval_seconds);

    // Overlap guard: never run two instances of the same schedule at once.
    match repo::tasks::schedule_has_active_task(&state.db, &s.id).await {
        Ok(true) => {
            if let Err(e) =
                repo::schedules::mark_run(&state.db, &s.id, None, None, &next_anchor).await
            {
                tracing::error!("scheduler: failed to postpone schedule {}: {e}", s.id);
            }
            return DueOutcome::OverlapSkipped(s.id.clone());
        }
        Err(e) => tracing::error!("scheduler: overlap check failed for {}: {e}", s.id),
        Ok(false) => {}
    }

    // The owner row must still exist — schedules cascade away with their
    // user, but a deleted-mid-flight race is handled defensively.
    let user = match repo::users::find_by_id(&state.db, &s.user_id).await {
        Ok(Some(u)) => CurrentUser(u),
        Ok(None) => {
            // Schedule outlived its user (should be impossible via FK) —
            // disable it so it stops firing every tick.
            tracing::error!("scheduler: schedule {} has no owner; disabling", s.id);
            let _ = repo::schedules::update(
                &state.db,
                &s.id,
                repo::schedules::ScheduleUpdate {
                    name: &s.name,
                    inputs_json: &s.inputs_json,
                    preset: s.preset.as_deref(),
                    target: s.target.as_deref(),
                    interval_seconds: s.interval_seconds,
                    enabled: false,
                    workspace_id: s.workspace_id.as_deref(),
                    next_run_at: &next_anchor,
                },
            )
            .await;
            return DueOutcome::Rejected(s.id.clone(), "schedule owner no longer exists".into());
        }
        Err(e) => {
            tracing::error!("scheduler: owner lookup failed for {}: {e}", s.id);
            return DueOutcome::Rejected(s.id.clone(), "owner lookup failed".into());
        }
    };

    let inputs: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&s.inputs_json).unwrap_or_default();
    let req = StartTaskRequest {
        plugin_id: s.plugin_id.clone(),
        inputs,
        preset: s.preset.clone(),
        // Consent was captured when the schedule was created.
        consent_granted: true,
        workspace_id: s.workspace_id.clone(),
        auth_profile_id: None,
    };

    match validate_and_create_task(state, &user, &req, None, Some(&s.id)).await {
        Ok((task, manifest, inputs)) => {
            state.tasks.spawn(task.clone(), manifest, inputs).await;
            if let Err(e) =
                repo::schedules::mark_run(&state.db, &s.id, Some(&task.id), None, &next_anchor)
                    .await
            {
                tracing::error!("scheduler: failed to record run for {}: {e}", s.id);
            }
            DueOutcome::Launched(s.id.clone(), task.id.clone())
        }
        Err(e) => {
            let msg = e.to_string();
            if let Err(db_err) =
                repo::schedules::mark_run(&state.db, &s.id, None, Some(&msg), &next_anchor).await
            {
                tracing::error!(
                    "scheduler: failed to record rejection for {}: {db_err}",
                    s.id
                );
            }
            DueOutcome::Rejected(s.id.clone(), msg)
        }
    }
}

/// Production loop: process due schedules on a fixed tick. Spawned once from
/// `main`; integration tests drive `run_due` directly instead.
pub async fn run_loop(state: SharedState, tick_secs: u64) {
    let tick = std::time::Duration::from_secs(tick_secs.max(1));
    loop {
        tokio::time::sleep(tick).await;
        run_due(&state).await;
    }
}
