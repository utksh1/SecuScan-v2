//! Async report job runner: renders report artifacts in the background and
//! delivers signed webhook callbacks (pentest-tools.com parity).
//!
//! Lifecycle: `waiting` → `in_progress` → `finished` | `failed`. The job row
//! is created by the API route (`waiting`); this module owns everything after
//! that. A crash between states is repaired at startup by
//! [`repo::reports::fail_interrupted`].

use crate::reports_render;
use crate::state::SharedState;
use hmac::{Hmac, Mac};
use secuscan_db::models::ReportJobRow;
use secuscan_db::repo;
use serde_json::json;
use sha2::Sha256;

/// Per-user admission cap: a user cannot queue more than this many jobs at
/// once (prevents trivially flooding the reports dir).
pub const MAX_ACTIVE_JOBS_PER_USER: i64 = 20;

/// Retention: how many *finished* jobs a user keeps before the oldest are
/// pruned (with their artifacts).
pub const RETAINED_FINISHED_JOBS: i64 = 100;

/// Webhook delivery: 3 attempts, backing off 1s then 4s.
const WEBHOOK_MAX_ATTEMPTS: u32 = 3;
const WEBHOOK_BACKOFF_MS: [u64; 2] = [1_000, 4_000];
const WEBHOOK_TIMEOUT_SECS: u64 = 10;

/// JSON representation shared by the API routes and webhook payloads.
/// Never includes `webhook_secret`.
pub fn job_to_json(j: &ReportJobRow) -> serde_json::Value {
    json!({
        "id": j.id,
        "task_id": j.task_id,
        "format": j.format,
        "severity_filter": j.severity_filter,
        "status": j.status,
        "error": j.error,
        "file_bytes": j.file_bytes,
        "webhook_url": j.webhook_url,
        "webhook_attempts": j.webhook_attempts,
        "created_at": j.created_at,
        "started_at": j.started_at,
        "finished_at": j.finished_at,
        "download_path": if j.status == "finished" {
            Some(format!("/api/v1/reports/{}/download", j.id))
        } else {
            None
        },
    })
}

/// Kick off background processing for a freshly created `waiting` job.
pub fn spawn_job(state: SharedState, job: ReportJobRow) {
    tokio::spawn(async move {
        run_job(&state, job).await;
    });
}

async fn run_job(state: &SharedState, job: ReportJobRow) {
    let job_id = job.id.clone();
    if let Err(e) = repo::reports::mark_running(&state.db, &job_id).await {
        tracing::error!("report job {job_id}: cannot mark running: {e}");
        return;
    }

    match render_job(state, &job).await {
        Ok((file_path, file_bytes)) => {
            match repo::reports::finish(
                &state.db,
                &job_id,
                repo::reports::FinishReport {
                    file_path: Some(file_path.clone()),
                    file_bytes: Some(file_bytes),
                    error: None,
                },
            )
            .await
            {
                // The job was deleted mid-run: the row is gone, so remove
                // the orphaned artifact instead of leaking it on disk.
                Ok(0) => {
                    let _ = std::fs::remove_file(&file_path);
                }
                Ok(_) => {}
                Err(e) => tracing::error!("report job {job_id}: cannot record success: {e}"),
            }
        }
        Err(msg) => {
            tracing::warn!("report job {job_id} failed: {msg}");
            if let Err(e) = repo::reports::finish(
                &state.db,
                &job_id,
                repo::reports::FinishReport {
                    file_path: None,
                    file_bytes: None,
                    error: Some(msg),
                },
            )
            .await
            {
                tracing::error!("report job {job_id}: cannot record failure: {e}");
            }
        }
    }

    // Refresh the row (status/timestamps) for the callback, then deliver.
    let fresh = repo::reports::get(&state.db, &job_id).await.ok();
    if let Some(fresh) = fresh.filter(|j| j.webhook_url.is_some()) {
        deliver_webhook(state, &fresh).await;
    }
}

/// Render the artifact and write it to disk. Returns `(path, size)`.
async fn render_job(state: &SharedState, job: &ReportJobRow) -> Result<(String, i64), String> {
    let task = repo::tasks::get(&state.db, &job.task_id)
        .await
        .map_err(|e| format!("task no longer available: {e}"))?;
    let findings = repo::findings::list_all_for_task(&state.db, &task.id)
        .await
        .map_err(|e| format!("cannot load findings: {e}"))?;
    let filtered = reports_render::filter_min_severity(&findings, job.severity_filter.as_deref());
    let owned: Vec<_> = filtered.into_iter().cloned().collect();

    let brand = reports_render::load_branding(&state.db).await;
    let rendered = reports_render::render(&task, &owned, &job.format, &brand)?;

    let dir = &state.config.reports_dir;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create reports dir: {e}"))?;
    let final_path = dir.join(format!("{}.{}", job.id, rendered.ext));
    let tmp_path = dir.join(format!("{}.{}.tmp", job.id, rendered.ext));
    // Write-then-rename so a download never observes a half-written file.
    std::fs::write(&tmp_path, &rendered.bytes)
        .map_err(|e| format!("cannot write artifact: {e}"))?;
    std::fs::rename(&tmp_path, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("cannot finalize artifact: {e}")
    })?;
    let bytes = rendered.bytes.len() as i64;
    Ok((
        final_path
            .to_str()
            .ok_or("reports dir is not valid UTF-8")?
            .to_string(),
        bytes,
    ))
}

/// HMAC-SHA256 signature over the raw body, hex-encoded — the same scheme
/// GitHub uses (`sha256=<hex>`), so receivers can reuse familiar verifier
/// code.
pub fn webhook_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Deliver the `report.finished` callback. Delivery failures are logged and
/// recorded in `webhook_attempts` but never fail the job itself.
async fn deliver_webhook(state: &SharedState, job: &ReportJobRow) {
    let url = job.webhook_url.clone().unwrap_or_default();
    let secret = job.webhook_secret.clone();
    let body = serde_json::to_vec(&json!({
        "event": "report.finished",
        "report": job_to_json(job),
    }))
    .unwrap_or_else(|_| b"{}".to_vec());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
        .build()
        .unwrap_or_default();

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let mut req = client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-secuscan-event", "report.finished")
            .header("x-secuscan-delivery", &job.id);
        if let Some(secret) = &secret {
            req = req.header("x-secuscan-signature", webhook_signature(secret, &body));
        }
        match req.body(body.clone()).send().await {
            Ok(resp) if resp.status().is_success() => break,
            Ok(resp) => {
                tracing::warn!(
                    "webhook for report {} attempt {}/{} got HTTP {}",
                    job.id,
                    attempt,
                    WEBHOOK_MAX_ATTEMPTS,
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "webhook for report {} attempt {}/{} failed: {e}",
                    job.id,
                    attempt,
                    WEBHOOK_MAX_ATTEMPTS
                );
            }
        }
        let _ = repo::reports::record_webhook_attempts(&state.db, &job.id, attempt as i64).await;
        if attempt >= WEBHOOK_MAX_ATTEMPTS {
            break;
        }
        let backoff = WEBHOOK_BACKOFF_MS
            .get((attempt - 1) as usize)
            .copied()
            .unwrap_or(1_000);
        tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
    }
    let _ = repo::reports::record_webhook_attempts(&state.db, &job.id, attempt as i64).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_signature_is_hmac_sha256_hex() {
        // RFC 4231 test vector: key "key", data "The quick brown fox jumps over the lazy dog"
        let sig = webhook_signature("key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            sig,
            "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn signature_is_stable_and_input_sensitive() {
        let a = webhook_signature("s3cret", b"body");
        let b = webhook_signature("s3cret", b"body");
        let c = webhook_signature("s3cret", b"body2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sha256="));
        assert_eq!(a.len(), "sha256=".len() + 64);
    }
}
