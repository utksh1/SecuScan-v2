//! HTTP Request Logger — creates an OOB callback handler via the DB.
//!
//! This "scanner" creates an OOB handler row in the database and returns the
//! callback URL as a finding. The handler then receives callbacks at
//! /oob/<secret> (handled by the API layer).

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
        _ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let name = get_str(inputs, "target")?;
        let ttl_hours = get_i64_or(inputs, "ttl_hours", 1440);
        let ttl_seconds = ttl_hours * 3600;

        let pool = super::current_db_pool()
            .ok_or_else(|| "DB pool not available in native scanner context".to_string())?;

        let handler = secuscan_db::repo::oob::create_handler(
            pool,
            None, // workspace_id — set by runtime via task workspace
            "system",
            name,
            "http_logger",
            "{}",
            ttl_seconds,
        )
        .await
        .map_err(|e| format!("create handler: {e}"))?;

        let callback_url = format!("/api/v1/oob/{}", handler.secret);
        let absolute_url = format!("https://secuscan.local{}", callback_url);

        Ok(vec![Finding {
            title: format!("OOB callback handler created: {name}"),
            category: "OOB Handler".into(),
            severity: Severity::Info,
            kind: FindingKind::Observation,
            description: format!(
                "Handler `{name}` is live. Embed the callback URL in payloads to detect blind vulnerabilities (SSRF, XXE, blind SQLi, command injection).\n\nCallback URL: {absolute_url}\n\nUse cases:\n- SSRF: embed in webhook/API parameters\n- XXE: DOCTYPE entity pointing at the URL\n- Blind SQLi: PostgreSQL COPY TO PROGRAM with curl; MySQL LOAD_FILE with UNC path\n- Command injection: curl/wget the URL\n\nExpires in {ttl_hours} hours. Hits are queryable via GET /oob-handlers/{}/hits.",
                handler.id
            ),
            remediation: format!("After the engagement, delete the handler via DELETE /oob-handlers/{}.", handler.id),
            proof: format!("Handler ID: {}, secret: {}, callback URL: {}", handler.id, handler.secret, callback_url),
            url: Some(absolute_url),
            metadata: json!({
                "handler_id": handler.id,
                "secret": handler.secret,
                "callback_path": callback_url,
                "ttl_hours": ttl_hours,
            }),
            ..Default::default()
        }])
    }
}
