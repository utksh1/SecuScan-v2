//! Hidden-parameter discovery (x8-class), native Rust.
//!
//! Baseline the URL, then replay with one extra parameter at a time from a
//! compact common-name list. A reflection of the canary, a status change,
//! or a large body-length delta is reported. Bounded, detection-only.

use super::website_scanner::append_query;
use super::{get_i64_or, get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

/// Common parameter names used by x8-style hunters (subset, not a dump).
const PARAMS: &[&str] = &[
    "id", "uid", "user", "user_id", "account", "page", "p", "q", "query", "search",
    "s", "keyword", "file", "path", "dir", "folder", "doc", "document", "url",
    "uri", "src", "dest", "redirect", "next", "return", "callback", "cb", "jsonp",
    "token", "key", "api_key", "access_token", "auth", "debug", "test", "admin",
    "edit", "action", "cmd", "exec", "command", "ping", "host", "ip", "port",
    "lang", "locale", "theme", "view", "format", "callback_url", "webhook",
    "email", "from", "to", "template", "include", "ref", "referer", "sort",
    "order", "filter", "limit", "offset", "size", "count", "tab", "step",
    "download", "export", "preview", "print", "raw", "callbackUri",
];

pub struct ParamFinder;

#[async_trait]
impl NativeScanner for ParamFinder {
    fn id(&self) -> &'static str { "param_finder" }
    fn name(&self) -> &'static str { "Hidden Parameter Finder" }
    fn description(&self) -> &'static str {
        "x8-class hidden parameter discovery: canary reflection and response deltas"
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let target = super::http_headers::normalize_url(get_str(inputs, "target")?)?;
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 8_000).clamp(1_000, 30_000) as u64,
        );
        let max = get_i64_or(inputs, "max_params", 80).clamp(10, PARAMS.len() as i64) as usize;
        let client = super::http_headers::build_client(true, timeout)?;
        let canary = format!("ptt{}", now_hex());

        ctx.sink
            .emit(crate::events::TaskEvent::Info(format!(
                "param-finder baseline {target} then {max} names (canary={canary})"
            )))
            .await;

        let (base_status, base_len, _) = fetch(&client, &target).await?;
        let mut findings = Vec::new();

        for name in PARAMS.iter().take(max) {
            if ctx.cancel.is_cancelled() { break; }
            let url = append_query(&target, name, &canary);
            let Ok((status, len, body)) = fetch(&client, &url).await else { continue };
            let reflected = body.contains(&canary);
            let status_changed = status != base_status;
            let len_delta = (len as i64 - base_len as i64).abs();
            if !reflected && !status_changed && len_delta < 40 {
                continue;
            }
            findings.push(Finding {
                title: format!("Interesting parameter `{name}`"),
                category: "Web".into(),
                severity: if reflected { Severity::Medium } else { Severity::Low },
                kind: FindingKind::Observation,
                description: format!(
                    "Adding `{name}={canary}` changed the response (status {base_status}→{status}, size {base_len}→{len}{}).",
                    if reflected { ", canary reflected" } else { "" }
                ),
                remediation: "Document and authorize every accepted parameter; reject unknown keys.".into(),
                proof: format!("GET {url} → {status} ({len} B); baseline {base_status}/{base_len} B"),
                url: Some(url),
                metadata: json!({ "param": name, "reflected": reflected, "status": status, "len": len }),
                cwe: Some("CWE-20".into()),
                owasp: Some("A03:2021-Injection".into()),
                confidence: Some("uncertain".into()),
                ..Default::default()
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: format!("No hidden parameters reacted on {target}"),
                category: "Web".into(),
                severity: Severity::Info,
                kind: FindingKind::Observation,
                description: format!("Tried {max} common names; no reflection or material delta."),
                remediation: String::new(),
                proof: format!("baseline {base_status}/{base_len} B"),
                url: Some(target),
                ..Default::default()
            });
        }
        Ok(findings)
    }
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<(u16, usize, String), String> {
    let resp = client.get(url).header("user-agent", "SecuScan-2.0 (param-finder)").send().await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body.len(), body))
}

fn now_hex() -> String {
    format!("{:x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() % 0xffff_ffff)
        .unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_bounded() {
        assert!(PARAMS.len() >= 40);
        assert!(PARAMS.contains(&"redirect"));
        assert!(PARAMS.contains(&"callback"));
    }
}
