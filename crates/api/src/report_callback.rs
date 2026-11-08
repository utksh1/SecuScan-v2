//! Scan-completion callbacks (Max-Parity Sprint 2.1, issue #24).
//!
//! `POST /tasks` accepts `report_callback {url, format, secret}`; on task
//! finish the manager spawns delivery here. Payloads are HMAC-SHA256-signed
//! with the caller's secret into `X-SecuScan-Signature` (same scheme as
//! notification-rule webhooks) and destinations are validated by the same
//! SSRF guard (`webhook_url_allowed`).
//!
//! Formats:
//!   * `raw_status` (default) — `{task_id, status, severity_counts}`
//!   * `raw_json` — the full task + findings JSON
//!   * `pdf_report` — `raw_status` plus `report_b64` (branded PDF artifact)

use crate::state::SharedState;
use secuscan_db::models::FindingRow;
use serde_json::{json, Value};
use sqlx::SqlitePool;

pub async fn deliver(
    pool: &SqlitePool,
    task_id: &str,
    cb: &Value,
    findings: &[FindingRow],
) -> Result<(), String> {
    let url = cb
        .get("url")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "callback url missing".to_string())?;
    crate::notifications_engine::webhook_url_allowed(url)?;
    let format = cb.get("format").and_then(Value::as_str).unwrap_or("raw_status");
    let secret = cb.get("secret").and_then(Value::as_str).unwrap_or("");

    let task = secuscan_db::repo::tasks::get(pool, task_id)
        .await
        .map_err(|e| format!("task load: {e}"))?;

    let counts = json!({
        "critical": findings.iter().filter(|f| f.severity == "critical").count(),
        "high": findings.iter().filter(|f| f.severity == "high").count(),
        "medium": findings.iter().filter(|f| f.severity == "medium").count(),
        "low": findings.iter().filter(|f| f.severity == "low").count(),
        "info": findings.iter().filter(|f| f.severity == "info").count(),
    });
    let mut payload = json!({
        "event": "task.finished",
        "task_id": task.id,
        "plugin_id": task.plugin_id,
        "status": task.status,
        "target": task.target,
        "findings_count": findings.len(),
        "severity_counts": counts,
    });

    if format == "raw_json" {
        payload["task"] = crate::routes::tasks::task_to_json(&task, false);
        payload["findings"] = json!(
            findings.iter().map(crate::routes::findings::finding_to_json).collect::<Vec<_>>()
        );
    } else if format == "pdf_report" {
        let brand = crate::reports_render::load_branding(pool).await;
        let findings_owned: Vec<FindingRow> = findings.to_vec();
        let rendered = crate::reports_render::render(
            &task,
            &findings_owned,
            "pdf",
            &brand,
        )?;
        use base64::Engine as _;
        payload["report_b64"] = json!(base64::engine::general_purpose::STANDARD.encode(&rendered.bytes));
        payload["report_filename"] = json!(crate::reports_render::report_filename(&task, rendered.ext));
    }

    let payload_json = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    // Sprint 2.3 (#8): connect-time destination check + no redirects.
    if let Some(host) = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)) {
        let mut policy = secuscan_core::net_scope::OutboundPolicy::from_env();
        if std::env::var("SECUSCAN_WEBHOOK_ALLOW_PRIVATE").ok().as_deref() == Some("true") {
            policy.allow_private = true;
        }
        let h = host.clone();
        let checked = tokio::task::spawn_blocking(move || policy.resolve_and_check(&h))
            .await
            .map_err(|e| e.to_string())?;
        if let Err(e) = checked {
            return Err(format!("callback destination rejected: {e}"));
        }
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .body(payload_json.clone());
    if !secret.is_empty() {
        let sig = crate::notifications_engine::hmac_sha256_hex(secret, &payload_json);
        req = req.header("X-SecuScan-Signature", format!("sha256={sig}"));
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("callback receiver returned {}", resp.status()));
    }
    // Bounded response read: a hostile receiver cannot make us buffer
    // gigabytes acking a callback.
    if let Some(len) = resp.content_length() {
        if len > 1024 * 1024 {
            return Err(format!(
                "callback receiver response too large ({len} bytes)"
            ));
        }
    }
    tracing::info!("report_callback delivered for task {task_id} (format {format})");
    Ok(())
}
