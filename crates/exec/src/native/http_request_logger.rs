//! HTTP Request Logger — creates an OOB callback handler via the DB.
//!
//! This "scanner" creates an OOB handler row in the database and returns the
//! marker-correlated callback URL as a finding. The handler then receives
//! callbacks at /oob/<secret> (handled by the API layer), where hits that
//! echo the task's marker are auto-correlated and opened as findings
//! (Max-Parity Sprint 1.2).
//!
//! Requires `SECUSCAN_PUBLIC_URL`: blind callbacks must be reachable from the
//! target, and a dead `secuscan.local` URL would silently prove nothing.

use super::{get_i64_or, get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;

pub struct HttpRequestLogger;

#[async_trait]
impl NativeScanner for HttpRequestLogger {
    fn id(&self) -> &'static str {
        "http_request_logger"
    }
    fn name(&self) -> &'static str {
        "HTTP Request Logger (OOB)"
    }
    fn description(&self) -> &'static str {
        "Out-of-band callback handler for SSRF/XXE/blind-SQLi/command-injection detection"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let name = get_str(inputs, "target")?;
        let ttl_hours = get_i64_or(inputs, "ttl_hours", 1440);
        let ttl_seconds = ttl_hours * 3600;

        // Fail loudly (Sprint 1.2 acceptance): a blind-callback tool without
        // a reachable public URL cannot detect anything, and handing out the
        // old dead `secuscan.local` URL would mislead operators.
        let oob = ctx.oob.as_ref().ok_or_else(|| {
            "SECUSCAN_PUBLIC_URL is not configured — OOB callbacks are unreachable \
             and blind-vulnerability detection cannot work. Set it to this \
             deployment's externally reachable base URL."
                .to_string()
        })?;
        if oob.public_url.is_none() {
            return Err("SECUSCAN_PUBLIC_URL is not configured — OOB callbacks are \
                        unreachable and blind-vulnerability detection cannot work. \
                        Set it to this deployment's externally reachable base URL."
                .to_string());
        }

        let pool = super::current_db_pool()
            .ok_or_else(|| "DB pool not available in native scanner context".to_string())?;

        let handler = secuscan_db::repo::oob::create_handler(
            pool,
            oob.workspace_id.as_deref(),
            "system",
            name,
            "http_logger",
            "{}",
            ttl_seconds,
        )
        .await
        .map_err(|e| format!("create handler: {e}"))?;

        let callback_url = oob
            .callback_url(&handler.secret)
            .expect("public_url checked above");

        let marker_note = oob
            .marker
            .as_deref()
            .map(|m| format!("\n\nTask marker `{m}` is embedded in the URL, so any callback is automatically correlated to this scan and opened as a finding."))
            .unwrap_or_default();

        Ok(vec![Finding {
            title: format!("OOB callback handler created: {name}"),
            category: "OOB Handler".into(),
            severity: Severity::Info,
            kind: FindingKind::Observation,
            description: format!(
                "Handler `{name}` is live. Embed the callback URL in payloads to detect blind vulnerabilities (SSRF, XXE, blind SQLi, command injection).\n\nCallback URL: {callback_url}\n\nUse cases:\n- SSRF: embed in webhook/API parameters\n- XXE: DOCTYPE entity pointing at the URL\n- Blind SQLi: PostgreSQL COPY TO PROGRAM with curl; MySQL LOAD_FILE with UNC path\n- Command injection: curl/wget the URL\n\nExpires in {ttl_hours} hours. Hits are queryable via GET /oob-handlers/{}/hits.{marker_note}",
                handler.id
            ),
            remediation: format!("After the engagement, delete the handler via DELETE /oob-handlers/{}.", handler.id),
            proof: format!("Handler ID: {}, secret: {}, callback URL: {}", handler.id, handler.secret, callback_url),
            url: Some(callback_url.clone()),
            metadata: json!({
                "handler_id": handler.id,
                "secret": handler.secret,
                "callback_path": callback_url,
                "task_marker": oob.marker,
                "ttl_hours": ttl_hours,
            }),
            ..Default::default()
        }])
    }
}
