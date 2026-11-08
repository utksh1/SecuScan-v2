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
use secuscan_db::models::{NotificationRuleRow, TaskRow};
use secuscan_db::repo;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::time::Duration;

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Sprint 2.2 (#25): fire notification rules whose trigger kind is "diff" —
/// the previously dead stub now wired from the scheduler's auto-diff path.
/// Called only when a scheduled run's diff shows new or regressed findings.
pub async fn fire_diff_rules(
    db: &SqlitePool,
    task: &TaskRow,
    diff_summary: &Value,
) -> Result<(), String> {
    let rules = repo::notifications::list_rules_for_workspace(db, task.workspace_id.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    for rule in rules {
        let rule_def: Value = serde_json::from_str(&rule.rules_json).unwrap_or(Value::Null);
        let triggers = rule_def
            .get("triggers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        eprintln!(
            "DEBUG fire_diff_rules: rule {} enabled={} triggers={:?}",
            rule.id, rule.enabled, triggers
        );
        if !triggers.iter().any(|t| t.get("kind").and_then(|k| k.as_str()) == Some("diff")) {
            continue;
        }
        let actions = rule_def
            .get("actions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let payload = json!({
            "event": "scan.diff",
            "task_id": task.id,
            "plugin_id": task.plugin_id,
            "target": task.target,
            "schedule_id": task.schedule_id,
            "diff": diff_summary,
        });
        for action in &actions {
            let kind = action.get("kind").and_then(Value::as_str).unwrap_or("");
            if let Err(e) = dispatch(db, &rule, kind, action, &payload, &task.id).await {
                tracing::warn!("diff rule {} action {kind} failed: {e}", rule.id);
            }
        }
    }
    Ok(())
}

pub async fn fire_for_task(
    db: &SqlitePool,
    task: &TaskRow,
    findings: &[Finding],
) -> Result<(), String> {
    let rules = repo::notifications::list_rules_for_workspace(db, task.workspace_id.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    for rule in rules {
        let rule_def: Value = serde_json::from_str(&rule.rules_json).unwrap_or(Value::Null);
        let triggers = rule_def
            .get("triggers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let actions = rule_def
            .get("actions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Evaluate triggers against this task + its findings.
        let task_status = task.status.clone();
        let task_target = task.target.clone().unwrap_or_default();
        let task_plugin = task.plugin_id.clone();
        let max_severity = findings
            .iter()
            .map(|f| sev_rank(f.severity.label()))
            .max()
            .unwrap_or(0);

        let any_trigger_matched = triggers.iter().any(|t| {
            let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            match kind {
                "scan_status" => {
                    let want = t.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    task_status == want
                }
                "vuln_found" => {
                    if findings.is_empty() {
                        return false;
                    }
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

        if !any_trigger_matched {
            continue;
        }

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
    // Sprint 2.3 (#8): webhooks never follow redirects — a redirect target
    // is not re-validated and could walk the delivery to another host.
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let payload_json = serde_json::to_string(payload).unwrap_or_default();
    let (status, http_status, error) = match kind {
        "webhook" => {
            let url = action.get("url").and_then(|v| v.as_str()).unwrap_or("");
            webhook_url_allowed(url)?;
            // Sprint 2.3 (#8): connect-time check — the hostname must not
            // resolve to a private/loopback/metadata address (rebinding
            // defense), and webhooks do not follow redirects. The
            // webhook-specific opt-out (SECUSCAN_WEBHOOK_ALLOW_PRIVATE,
            // local-first receivers) joins the general outbound policy. A
            // rejection here is a FAILED DELIVERY and must be logged.
            let dest_failure: Option<String> =
                if let Some(host) = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)) {
                    let mut policy = secuscan_core::net_scope::OutboundPolicy::from_env();
                    if std::env::var("SECUSCAN_WEBHOOK_ALLOW_PRIVATE").ok().as_deref()
                        == Some("true")
                    {
                        policy.allow_private = true;
                    }
                    let h = host.clone();
                    match tokio::task::spawn_blocking(move || policy.resolve_and_check(&h))
                        .await
                        .map_err(|e| e.to_string())
                    {
                        Ok(Ok(_)) => None,
                        Ok(Err(e)) => Some(format!("webhook destination rejected: {e}")),
                        Err(e) => return Err(e),
                    }
                } else {
                    None
                };
            let send_result = if let Some(msg) = dest_failure {
                ("failed", None, Some(msg))
            } else {
                let secret = action.get("secret").and_then(|v| v.as_str()).unwrap_or("");
                let mut req = client
                    .post(url)
                    .header("content-type", "application/json")
                    .body(payload_json.clone());
                if !secret.is_empty() {
                    let sig = hmac_sha256_hex(secret, &payload_json);
                    req = req.header("X-SecuScan-Signature", format!("sha256={sig}"));
                }
                // Issue #25 — a failed SEND (DNS, timeout, refused) is a failed
                // delivery and must be logged, not silently dropped: the `?`
                // here previously skipped log_delivery entirely, so unreachable
                // receivers left no trace in the delivery log.
                match req.send().await {
                    Ok(resp) => {
                        let code = resp.status().as_u16() as i64;
                        let ok = resp.status().is_success();
                        // Bounded read (#8): cap captured error bodies at 4 KiB.
                        let body = if let Some(len) = resp.content_length() {
                            if len > 4096 {
                                format!("[{len} bytes truncated]").into_bytes()
                            } else {
                                resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default()
                            }
                        } else {
                            resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default()
                        };
                        let body = String::from_utf8_lossy(&body).to_string();
                        (
                            if ok { "sent" } else { "failed" },
                            Some(code),
                            if ok { None } else { Some(body) },
                        )
                    }
                    Err(e) => ("failed", None, Some(e.to_string())),
                }
            };
            send_result
        }
        "slack" | "teams" | "discord" => {
            let url = action
                .get("webhook_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if url.is_empty() {
                return Err(format!("{kind} action missing webhook_url"));
            }
            webhook_url_allowed(url)?;
            // All three accept a JSON body with a `text` field. Slack/Teams
            // also accept richer blocks, but plain text works everywhere.
            let text = format!(
                "[SecuScan] Task {} ({}): {} findings ({} critical, {} high)",
                task_id,
                payload["task"]["plugin_id"].as_str().unwrap_or(""),
                payload["findings_count"].as_u64().unwrap_or(0),
                payload["findings_by_severity"]["critical"]
                    .as_u64()
                    .unwrap_or(0),
                payload["findings_by_severity"]["high"]
                    .as_u64()
                    .unwrap_or(0),
            );
            let body = json!({"text": text});
            let resp = client
                .post(url)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let code = resp.status().as_u16() as i64;
            let ok = resp.status().is_success();
            (
                if ok { "sent" } else { "failed" },
                Some(code),
                if ok {
                    None
                } else {
                    Some("webhook rejected".into())
                },
            )
        }
        "email" => {
            // Email requires SMTP config (deferred to v3.1). Log the intent.
            let to = action
                .get("to")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            tracing::info!(
                "email notification (would send to {}): {}",
                to,
                payload_json
            );
            ("sent", None, None)
        }
        _ => ("failed", None, Some(format!("unknown action kind: {kind}"))),
    };
    let _ = repo::notifications::log_delivery(
        db,
        &rule.id,
        Some(task_id),
        None,
        kind,
        status,
        http_status,
        error.as_deref(),
        &payload_json,
    )
    .await;
    Ok(())
}

/// Block server-side requests to loopback, link-local, and RFC1918.
/// Default-deny wrapper: private/loopback destinations are rejected unless
/// `SECUSCAN_WEBHOOK_ALLOW_PRIVATE=true` (local-first deployments, CI on the
/// same host). Sprint 2.1 scan-completion callbacks share this policy.
pub fn webhook_url_allowed(url: &str) -> Result<(), String> {
    let allow_private =
        std::env::var("SECUSCAN_WEBHOOK_ALLOW_PRIVATE").ok().as_deref() == Some("true");
    webhook_url_allowed_with(url, allow_private)
}

pub fn webhook_url_allowed_with(url: &str, allow_private: bool) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "webhook URL is not valid".to_string())?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err("webhook URL must be http or https".into());
    }
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host == "metadata.google.internal"
    {
        return Err("webhook URL host is not allowed".into());
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !ip_is_public(ip) && !allow_private {
            return Err("webhook URL must not target a private or loopback address".into());
        }
    }
    Ok(())
}

fn ip_is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_unspecified()
                || (o[0] == 169 && o[1] == 254)
                || o[0] == 0)
        }
        std::net::IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified()),
    }
}

fn sev_rank(label: &str) -> usize {
    match label {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

pub fn hmac_sha256_hex(key: &str, msg: &str) -> String {
    use sha2::{Digest, Sha256};
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
    outer.update(inner_hash);
    let result = outer.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_blocks_private_and_loopback() {
        assert!(webhook_url_allowed("http://127.0.0.1/hook").is_err());
        assert!(webhook_url_allowed("http://localhost/hook").is_err());
        assert!(webhook_url_allowed("http://192.168.1.10/hook").is_err());
        assert!(webhook_url_allowed("http://169.254.169.254/latest").is_err());
        assert!(webhook_url_allowed("https://hooks.slack.com/services/x").is_ok());
    }
}
