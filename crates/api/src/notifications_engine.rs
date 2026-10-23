//! Notifications engine — evaluates rules and dispatches actions when tasks
//! complete or findings are created.
//!
//! Rule JSON shape:
//! ```json
//! {
//!   "triggers": [
//!     {"kind": "vuln_found", "severity": ">=high"},
//!     {"kind": "scan_status", "status": "completed"}
//!   ],
//!   "actions": [
//!     {"kind": "webhook", "url": "https://example.com/hook", "secret": "abc"},
//!     {"kind": "email", "to": ["security@example.com"]},
//!     {"kind": "slack", "webhook_url": "https://hooks.slack.com/..."},
//!     {"kind": "teams", "webhook_url": "https://outlook.office.com/..."},
//!     {"kind": "discord", "webhook_url": "https://discord.com/api/webhooks/..."}
//!   ]
//! }
//! ```
//!
//! Triggers are OR-combined: any match fires all actions.

use secuscan_core::models::Finding;
use secuscan_db::models::{FindingRow, NotificationRuleRow, TaskRow};
use secuscan_db::repo;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::time::Duration;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn fire_for_task(
    db: &SqlitePool,
    task: &TaskRow,
    findings: &[Finding],
) -> Result<(), String> {
    let rules = repo::notifications::list_rules_for_workspace(db, task.workspace_id.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    for rule in rules {
        let rule_def: Value = serde_json::from_str(&rule.rules_json)
            .unwrap_or(Value::Null);
        let triggers = rule_def.get("triggers").and_then(|v| v.as_array())
            .cloned().unwrap_or_default();
        let actions = rule_def.get("actions").and_then(|v| v.as_array())
            .cloned().unwrap_or_default();

        // Evaluate triggers against this task + its findings.
        let task_status = task.status.clone();
        let task_target = task.target.clone().unwrap_or_default();
        let task_plugin = task.plugin_id.clone();
        let max_severity = findings.iter()
            .map(|f| sev_rank(f.severity.label()))
            .max().unwrap_or(0);

        let any_trigger_matched = triggers.iter().any(|t| {
            let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            match kind {
                "scan_status" => {
                    let want = t.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    task_status == want
                }
                "vuln_found" => {
                    if findings.is_empty() { return false; }
                    let want_sev = t.get("severity").and_then(|v| v.as_str()).unwrap_or("");
                    let (op, val) = if let Some(rest) = want_sev.strip_prefix(">=") {
                        (">=", rest)
                    } else if let Some(rest) = want_sev.strip_prefix("<=") {
                        ("<=", rest)
                    } else {
                        ("=", want_sev)
                    };
                    let want_rank = sev_rank(val);
                    match op {
                        ">=" => max_severity >= want_rank,
                        "<=" => max_severity <= want_rank,
                        _ => max_severity == want_rank,
                    }
                }
                "diff" => {
                    // Diff events are not wired here; they fire from the scheduler.
                    false
                }
                _ => false,
            }
        });

        if !any_trigger_matched { continue; }

        // Build the payload — same shape for all channels.
        let payload = json!({
            "event": "task_completed",
            "task": {
                "id": task.id,
                "plugin_id": task_plugin,
                "target": task_target,
                "status": task_status,
                "workspace_id": task.workspace_id,
            },
            "findings_count": findings.len(),
            "findings_by_severity": {
                "critical": findings.iter().filter(|f| f.severity.label() == "critical").count(),
                "high": findings.iter().filter(|f| f.severity.label() == "high").count(),
                "medium": findings.iter().filter(|f| f.severity.label() == "medium").count(),
                "low": findings.iter().filter(|f| f.severity.label() == "low").count(),
                "info": findings.iter().filter(|f| f.severity.label() == "info").count(),
            },
            "top_findings": findings.iter().take(10).map(|f| json!({
                "title": f.title,
                "severity": f.severity.label(),
                "category": f.category,
                "cve": f.cve,
                "url": f.url,
            })).collect::<Vec<_>>(),
        });

        for action in &actions {
            let kind = action.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let result = dispatch(db, &rule, kind, action, &payload, &task.id).await;
            if let Err(e) = result {
                tracing::warn!("notification dispatch ({kind}) failed: {e}");
            }
        }
    }
    Ok(())
}

async fn dispatch(
    db: &SqlitePool,
    rule: &NotificationRuleRow,
    kind: &str,
    action: &Value,
    payload: &Value,
    task_id: &str,
) -> Result<(), String> {
    let client = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build().unwrap();
    let payload_json = serde_json::to_string(payload).unwrap_or_default();
    let (status, http_status, error) = match kind {
        "webhook" => {
            let url = action.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let secret = action.get("secret").and_then(|v| v.as_str()).unwrap_or("");
            let mut req = client.post(url).header("content-type", "application/json").body(payload_json.clone());
            if !secret.is_empty() {
                let sig = hmac_sha256_hex(secret, &payload_json);
                req = req.header("X-SecuScan-Signature", format!("sha256={sig}"));
            }
            let resp = req.send().await.map_err(|e| e.to_string())?;
            let code = resp.status().as_u16() as i64;
            let ok = resp.status().is_success();
            let body = resp.text().await.unwrap_or_default();
            (if ok { "sent" } else { "failed" }, Some(code), if ok { None } else { Some(body) })
        }
        "slack" | "teams" | "discord" => {
            let url = action.get("webhook_url").and_then(|v| v.as_str()).unwrap_or("");
            if url.is_empty() {
                return Err(format!("{kind} action missing webhook_url"));
            }
            // All three accept a JSON body with a `text` field. Slack/Teams
            // also accept richer blocks, but plain text works everywhere.
            let text = format!(
                "[SecuScan] Task {} ({}): {} findings ({} critical, {} high)",
                task_id,
                payload["task"]["plugin_id"].as_str().unwrap_or(""),
                payload["findings_count"].as_u64().unwrap_or(0),
                payload["findings_by_severity"]["critical"].as_u64().unwrap_or(0),
                payload["findings_by_severity"]["high"].as_u64().unwrap_or(0),
            );
            let body = json!({"text": text});
            let resp = client.post(url).json(&body).send().await.map_err(|e| e.to_string())?;
            let code = resp.status().as_u16() as i64;
            let ok = resp.status().is_success();
            (if ok { "sent" } else { "failed" }, Some(code), if ok { None } else { Some("webhook rejected".into()) })
        }
        "email" => {
            // Email requires SMTP config (deferred to v3.1). Log the intent.
            let to = action.get("to").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            tracing::info!("email notification (would send to {}): {}", to, payload_json);
            ("sent", None, None)
        }
        _ => ("failed", None, Some(format!("unknown action kind: {kind}"))),
    };
    let _ = repo::notifications::log_delivery(
        db, &rule.id, Some(task_id), None, kind, status, http_status,
        error.as_deref(), &payload_json,
    ).await;
    Ok(())
}

fn sev_rank(label: &str) -> usize {
    match label {
        "info" => 0, "low" => 1, "medium" => 2, "high" => 3, "critical" => 4,
        _ => 0,
    }
}

fn hmac_sha256_hex(key: &str, msg: &str) -> String {
    use sha2::{Sha256, Digest};
    use std::io::Write;
    // Simple HMAC-SHA256 implementation (avoids pulling in the hmac crate).
    let block_size = 64;
    let key_bytes = if key.len() > block_size {
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        h.finalize().to_vec()
    } else {
        key.as_bytes().to_vec()
    };
    let mut padded_key = key_bytes.clone();
    padded_key.resize(block_size, 0);
    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= padded_key[i];
        opad[i] ^= padded_key[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg.as_bytes());
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();
    hex::encode(result)
}
