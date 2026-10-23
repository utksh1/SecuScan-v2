//! Attack Surface aggregator: derives asset inventory rows from findings.
//!
//! Called by the task manager right after findings are inserted. Walks the
//! findings, extracts asset-like metadata (hostname / IP / port / service /
//! technology), and upserts into `attack_surface_assets`.
//!
//! Heuristic-driven (not parser-specific) so every plugin contributes
//! without bespoke wiring. A finding contributes if any of:
//!   * it has a `url` (web findings → host asset)
//!   * its `metadata.hostname` / `metadata.ip` is set
//!   * its `metadata.ports` array is set (port scan findings)
//!   * its `metadata.technologies` array is set (recon findings)

use secuscan_core::models::Finding;
use secuscan_db::repo;
use secuscan_db::DbResult;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use url::Url;

/// Aggregate `findings` for `task_id` into the attack surface. Best-effort:
/// errors are logged and swallowed so a flaky aggregation never breaks the
/// task completion path.
pub async fn aggregate_for_task(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    task_id: &str,
    plugin_id: &str,
    findings: &[Finding],
) {
    if let Err(e) = try_aggregate(db, workspace_id, task_id, plugin_id, findings).await {
        tracing::warn!("attack-surface aggregation for task {task_id} failed: {e}");
    }
}

async fn try_aggregate(
    db: &SqlitePool,
    workspace_id: Option<&str>,
    task_id: &str,
    plugin_id: &str,
    findings: &[Finding],
) -> DbResult<()> {
    // Group asset contributions by hostname (or ip if no hostname) so a
    // single scan producing 50 open ports on the same host yields ONE
    // upsert call (with all 50 ports in metadata) rather than 50.
    let mut by_asset: std::collections::BTreeMap<String, AssetContribution> = Default::default();

    for f in findings {
        let meta = &f.metadata;
        let hostname = string_field(meta, "hostname")
            .or_else(|| string_field(meta, "host"))
            .or_else(|| string_field(meta, "domain"))
            .or_else(|| f.url.as_deref().and_then(extract_host));
        let ip = string_field(meta, "ip")
            .or_else(|| string_field(meta, "ip_address"))
            .or_else(|| string_field(meta, "address"))
            // dns_lookup findings list IPs as the title — if metadata has
            // no IP field but title looks like an IP, use it.
            .or_else(|| {
                let t = &f.title;
                if t.parse::<std::net::IpAddr>().is_ok() {
                    Some(t.clone())
                } else {
                    None
                }
            });
        let url = f.url.clone()
            .or_else(|| string_field(meta, "url"))
            .or_else(|| string_field(meta, "final"))
            .or_else(|| string_field(meta, "original"));

        // Skip if no asset-identifying info at all.
        if hostname.is_none() && ip.is_none() && url.is_none() {
            continue;
        }

        let key = hostname.clone()
            .or_else(|| ip.clone())
            .or_else(|| url.clone())
            .unwrap_or_default();

        let entry = by_asset.entry(key.clone()).or_default();
        entry.hostname = entry.hostname.take().or(hostname);
        entry.ip = entry.ip.take().or(ip);
        entry.url = entry.url.take().or(url);

        // Merge ports — accept both `ports: [...]` (port-scanner array form)
        // and `port: <n>` (single-port form).
        if let Some(ports) = meta.get("ports").and_then(|v| v.as_array()) {
            for p in ports {
                entry.ports.push(p.clone());
            }
        } else if let Some(p) = meta.get("port").and_then(|v| v.as_u64()) {
            let proto = string_field(meta, "protocol").unwrap_or_else(|| "tcp".to_string());
            entry.ports.push(json!({ "port": p, "proto": proto }));
        }
        // Merge technologies.
        if let Some(techs) = meta.get("technologies").and_then(|v| v.as_array()) {
            for t in techs {
                entry.technologies.push(t.clone());
            }
        }
        // Merge services (from port scan with product/version).
        if let Some(svc) = meta.get("service").and_then(|v| v.as_object()) {
            entry.services.push(Value::Object(svc.clone()));
        }
        // Risk flags from severity.
        if f.severity.label() == "high" || f.severity.label() == "critical" {
            entry.risks.push(Value::String(format!("{}: {}", f.severity.label(), f.title)));
        }
        // Track contributing scan.
        entry.contributed_by.push(Value::String(plugin_id.to_string()));
        entry.last_scan_id = Some(task_id.to_string());
    }

    // Upsert each unique asset.
    for (_, c) in by_asset {
        let metadata = json!({
            "ports": dedup_values(c.ports),
            "technologies": dedup_values(c.technologies),
            "services": dedup_values(c.services),
            "risks": dedup_values(c.risks),
            "contributed_by": dedup_values(c.contributed_by),
            "last_scan_id": c.last_scan_id,
        });
        let metadata_str = serde_json::to_string(&metadata).unwrap_or_default();
        repo::attack_surface::upsert_asset(
            db,
            workspace_id,
            c.hostname.as_deref(),
            c.ip.as_deref(),
            c.url.as_deref(),
            &metadata_str,
        )
        .await?;
    }
    Ok(())
}

#[derive(Default)]
struct AssetContribution {
    hostname: Option<String>,
    ip: Option<String>,
    url: Option<String>,
    ports: Vec<Value>,
    technologies: Vec<Value>,
    services: Vec<Value>,
    risks: Vec<Value>,
    contributed_by: Vec<Value>,
    last_scan_id: Option<String>,
}

fn string_field(meta: &Value, name: &str) -> Option<String> {
    meta.get(name).and_then(|v| v.as_str()).map(str::to_string)
}

fn extract_host(url: &str) -> Option<String> {
    Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string))
}

/// Deduplicate JSON values by their string representation, preserving order.
fn dedup_values(values: Vec<Value>) -> Vec<Value> {
    let mut seen: std::collections::HashSet<String> = Default::default();
    let mut out = Vec::new();
    for v in values {
        let key = v.to_string();
        if seen.insert(key) {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use secuscan_core::models::{FindingKind, Severity};

    fn make_finding(title: &str, url: Option<&str>, meta: Value) -> Finding {
        Finding {
            title: title.into(),
            category: "test".into(),
            severity: Severity::Info,
            kind: FindingKind::Observation,
            description: String::new(),
            remediation: String::new(),
            proof: String::new(),
            url: url.map(str::to_string),
            metadata: meta,
        }
    }

    #[test]
    fn extract_host_strips_scheme_and_path() {
        assert_eq!(extract_host("http://example.com:8080/foo"), Some("example.com".into()));
        assert_eq!(extract_host("https://1.2.3.4/"), Some("1.2.3.4".into()));
        assert_eq!(extract_host("not a url"), None);
    }

    #[test]
    fn dedup_preserves_first_occurrence() {
        let v = dedup_values(vec![
            Value::String("a".into()),
            Value::String("b".into()),
            Value::String("a".into()),
        ]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], Value::String("a".into()));
    }
}
