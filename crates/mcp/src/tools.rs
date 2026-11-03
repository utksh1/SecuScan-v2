//! MCP tool definitions + dispatch. Each tool wraps one or two REST calls.

use crate::client::SecuScanClient;
use crate::proto::{error_codes, JsonRpcRequest, JsonRpcResponse};
use serde_json::{json, Value};
use std::time::Duration;

/// Return the MCP tool catalogue.
pub fn list_tools(req: JsonRpcRequest) -> JsonRpcResponse {
    let tools = json!({ "tools": [
        tool("list_plugins", "List all available scanners and their availability status", json!({})),
        tool("start_scan", "Start a scan only with a separate administrator-issued, single-use scoped approval token; polls until completion.",
            json!({
                "type": "object",
                "properties": {
                    "plugin_id": { "type": "string", "description": "Plugin id (e.g. nmap, nikto, nuclei)" },
                    "target": { "type": "string", "description": "Target IP/hostname/URL" },
                    "inputs": { "type": "object", "description": "Additional plugin inputs (key-value)" },
                    "workspace_id": { "type": "string" },
                    "timeout_seconds": { "type": "integer", "default": 600 },
                    "consent_granted": { "type": "boolean", "description": "Must be explicitly true" },
                    "approval_token": { "type": "string", "description": "One-time approval from the SecuScan admin API, bound to this scanner user and exact scan inputs" },
                    "preset": { "type": "string" },
                    "auth_profile_id": { "type": "string" }
                },
                "required": ["plugin_id", "target", "consent_granted", "approval_token"]
            })),
        tool("list_tasks", "List recent tasks", json!({
            "type": "object",
            "properties": { "limit": { "type": "integer", "default": 50 } }
        })),
        tool("get_task", "Get a task by id (includes output)", json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"]
        })),
        tool("list_findings", "List findings with optional filters", json!({
            "type": "object",
            "properties": {
                "severity": { "type": "array", "items": { "type": "string" }, "description": "Filter by severity (critical/high/medium/low/info)" },
                "limit": { "type": "integer", "default": 100 }
            }
        })),
        tool("get_finding", "Get a finding by id", json!({
            "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"]
        })),
        tool("triage_finding", "Update a finding's analyst status", json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "status": { "type": "string", "enum": ["new", "confirmed", "needs_review", "false_positive", "accepted_risk", "fixed"] }
            },
            "required": ["id", "status"]
        })),
        tool("list_workspaces", "List workspaces", json!({})),
        tool("create_workspace", "Create a workspace", json!({
            "type": "object",
            "properties": { "name": { "type": "string" }, "description": { "type": "string" } },
            "required": ["name"]
        })),
        tool("list_targets", "List targets in a workspace", json!({
            "type": "object",
            "properties": { "workspace_id": { "type": "string" } },
            "required": ["workspace_id"]
        })),
        tool("add_target", "Register a target in a workspace", json!({
            "type": "object",
            "properties": {
                "workspace_id": { "type": "string" },
                "name": { "type": "string", "description": "IP, hostname, or URL" },
                "description": { "type": "string" }
            },
            "required": ["workspace_id", "name"]
        })),
        tool("list_robots", "List available Pentest Robots (DAG workflows)", json!({})),
        tool("get_robot_run", "Get the status of a robot run", json!({
            "type": "object",
            "properties": { "run_id": { "type": "string" } },
            "required": ["run_id"]
        })),
        tool("list_attack_surface", "List assets in the Attack Surface inventory", json!({
            "type": "object",
            "properties": {
                "workspace_id": { "type": "string" },
                "q": { "type": "string", "description": "Filter by hostname/IP/URL substring" },
                "limit": { "type": "integer", "default": 100 }
            }
        })),
        tool("create_report", "Generate a report for a task", json!({
            "type": "object",
            "properties": {
                "task_id": { "type": "string" },
                "format": { "type": "string", "enum": ["md", "json", "csv", "html", "sarif"] }
            },
            "required": ["task_id", "format"]
        })),
        tool("list_reports", "List recent report jobs", json!({})),
        tool("get_sniper_run", "Get a Sniper run by id", json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"]
        })),
        tool("list_vpn_profiles", "List OpenVPN profiles owned by the caller", json!({})),
        tool("test_vpn_profile", "Validate an OpenVPN profile without connecting", json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"]
        })),
        tool("start_people_hunter", "Start People Hunter only with a separate scoped one-use approval", json!({
            "type": "object",
            "properties": {
                "target": { "type": "string" },
                "workspace_id": { "type": "string" },
                "consent_granted": { "type": "boolean" },
                "approval_token": { "type": "string" }
            },
            "required": ["target", "consent_granted", "approval_token"]
        })),
    ]});
    JsonRpcResponse::ok(req.id, tools)
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": schema })
}

pub async fn call_tool(client: &SecuScanClient, req: JsonRpcRequest) -> JsonRpcResponse {
    let params = match req.params {
        Some(p) => p,
        None => {
            return JsonRpcResponse::error(req.id, error_codes::INVALID_PARAMS, "missing params")
        }
    };
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let id = req.id.clone();
    let result = dispatch_call(client, name, args).await;
    match result {
        Ok(text) => JsonRpcResponse::ok(
            id,
            json!({
                "content": [{ "type": "text", "text": text }]
            }),
        ),
        Err(e) => JsonRpcResponse::ok(
            id,
            json!({
                "isError": true,
                "content": [{ "type": "text", "text": format!("error: {e}") }]
            }),
        ),
    }
}

/// Build the dedicated server-approved request. No MCP caller can set
/// consent implicitly, and the opaque token is checked again by the API.
fn approved_scan_payload(args: &Value, plugin_id: &str, inputs: Value) -> Result<Value, String> {
    if args.get("consent_granted").and_then(Value::as_bool) != Some(true) {
        return Err("explicit consent_granted=true is required for each MCP scan".into());
    }
    let approval = args
        .get("approval_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("an administrator-issued approval_token is required")?;
    if !inputs.is_object() {
        return Err("scan inputs must be an object".into());
    }
    let mut scan = json!({
        "plugin_id": plugin_id,
        "inputs": inputs,
        "consent_granted": true,
    });
    for key in ["workspace_id", "preset", "auth_profile_id"] {
        if let Some(value) = args.get(key) {
            scan[key] = value.clone();
        }
    }
    Ok(json!({ "approval_token": approval, "scan": scan }))
}

async fn dispatch_call(client: &SecuScanClient, name: &str, args: Value) -> Result<String, String> {
    match name {
        "list_plugins" => {
            let v = client
                .get("/api/v1/plugins")
                .await
                .map_err(|e| e.to_string())?;
            let items = v
                .get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut lines = vec!["Available plugins:".to_string()];
            for p in items {
                let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let avail = p
                    .get("available")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let status = if avail { "AVAILABLE" } else { "MISSING" };
                lines.push(format!("  - {id:<20} [{status}] {name}"));
            }
            Ok(lines.join("\n"))
        }
        "start_scan" => {
            let plugin_id = args
                .get("plugin_id")
                .and_then(|v| v.as_str())
                .ok_or("missing plugin_id")?
                .to_string();
            let target = args
                .get("target")
                .and_then(|v| v.as_str())
                .ok_or("missing target")?
                .to_string();
            let timeout = args
                .get("timeout_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(600);
            let mut inputs = args.get("inputs").cloned().unwrap_or(json!({}));
            if let Value::Object(ref mut m) = inputs {
                m.insert("target".into(), Value::String(target.clone()));
            }
            let body = approved_scan_payload(&args, &plugin_id, inputs)?;
            let task = client
                .post("/api/v1/mcp/scans", body)
                .await
                .map_err(|e| e.to_string())?;
            let task_id = task
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("no task id in response")?
                .to_string();
            // Poll for completion.
            let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
            loop {
                if std::time::Instant::now() >= deadline {
                    return Err(format!("task {task_id} did not complete within {timeout}s"));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                let t = client
                    .get(&format!("/api/v1/tasks/{task_id}"))
                    .await
                    .map_err(|e| e.to_string())?;
                let status = t.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if status == "completed" || status == "failed" || status == "cancelled" {
                    let findings = client
                        .get(&format!("/api/v1/tasks/{task_id}/findings"))
                        .await
                        .map_err(|e| e.to_string())?;
                    let count = findings
                        .get("items")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    return Ok(format!("Task {task_id} finished with status `{status}`. Findings: {count}\nTask detail: {t:#?}"));
                }
            }
        }
        "list_tasks" => {
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50);
            let v = client
                .get(&format!("/api/v1/tasks?limit={limit}"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "get_task" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("missing id")?;
            let v = client
                .get(&format!("/api/v1/tasks/{id}"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "list_findings" => {
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100);
            let mut path = format!("/api/v1/findings?limit={limit}");
            if let Some(sevs) = args.get("severity").and_then(|v| v.as_array()) {
                let joined = sevs
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                if !joined.is_empty() {
                    path.push_str(&format!("&severity={joined}"));
                }
            }
            let v = client.get(&path).await.map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "get_finding" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("missing id")?;
            let v = client
                .get(&format!("/api/v1/findings/{id}"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "triage_finding" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("missing id")?;
            let status = args
                .get("status")
                .and_then(|v| v.as_str())
                .ok_or("missing status")?;
            let v = client
                .patch(
                    &format!("/api/v1/findings/{id}"),
                    json!({"analyst_status": status}),
                )
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "list_workspaces" => {
            let v = client
                .get("/api/v1/workspaces")
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "create_workspace" => {
            let name = args
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("missing name")?;
            let desc = args
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let v = client
                .post(
                    "/api/v1/workspaces",
                    json!({"name": name, "description": desc}),
                )
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "list_targets" => {
            let ws = args
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .ok_or("missing workspace_id")?;
            let v = client
                .get(&format!("/api/v1/workspaces/{ws}/targets"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "add_target" => {
            let ws = args
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .ok_or("missing workspace_id")?;
            let name = args
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("missing name")?;
            let desc = args
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let v = client
                .post(
                    &format!("/api/v1/workspaces/{ws}/targets"),
                    json!({"name": name, "description": desc}),
                )
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "list_robots" => {
            let v = client
                .get("/api/v1/robots")
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "get_robot_run" => {
            let run_id = args
                .get("run_id")
                .and_then(|v| v.as_str())
                .ok_or("missing run_id")?;
            let v = client
                .get(&format!("/api/v1/robots/runs/{run_id}"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "list_attack_surface" => {
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100);
            let mut path = format!("/api/v1/attack-surface?limit={limit}");
            if let Some(ws) = args.get("workspace_id").and_then(|v| v.as_str()) {
                path.push_str(&format!("&workspace_id={ws}"));
            }
            if let Some(q) = args.get("q").and_then(|v| v.as_str()) {
                path.push_str(&format!("&q={q}"));
            }
            let v = client.get(&path).await.map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "create_report" => {
            let task_id = args
                .get("task_id")
                .and_then(|v| v.as_str())
                .ok_or("missing task_id")?;
            let format = args
                .get("format")
                .and_then(|v| v.as_str())
                .ok_or("missing format")?;
            let v = client
                .post(
                    &format!("/api/v1/tasks/{task_id}/reports"),
                    json!({"format": format}),
                )
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "list_reports" => {
            let v = client
                .get("/api/v1/reports")
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "get_sniper_run" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("missing id")?;
            let v = client
                .get(&format!("/api/v1/sniper/runs/{id}"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "list_vpn_profiles" => {
            let v = client
                .get("/api/v1/vpn-profiles")
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "test_vpn_profile" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("missing id")?;
            let v = client
                .post(&format!("/api/v1/vpn-profiles/{id}/test"), json!({}))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "start_people_hunter" => {
            let target = args
                .get("target")
                .and_then(Value::as_str)
                .ok_or("missing target")?;
            let body = approved_scan_payload(
                &args,
                "people-hunter",
                json!({ "target": target }),
            )?;
            let v = client
                .post("/api/v1/mcp/scans", body)
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::JsonRpcRequest;

    fn catalogue() -> Value {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/list".into(),
            params: None,
        };
        list_tools(req).result.unwrap()
    }

    #[test]
    fn mcp_catalogue_requires_approval_and_excludes_unscoped_exploit_paths() {
        let v = catalogue();
        let items = v["tools"].as_array().unwrap();
        for name in ["start_scan", "start_people_hunter"] {
            let t = items.iter().find(|x| x["name"] == name).unwrap();
            let required = t["inputSchema"]["required"].as_array().unwrap();
            assert!(required.contains(&json!("approval_token")));
            assert!(required.contains(&json!("consent_granted")));
        }
        assert!(!items.iter().any(|x| x["name"] == "run_sniper"));
        assert!(!items.iter().any(|x| x["name"] == "run_robot"));
    }

    #[test]
    fn no_consent_or_approval_cannot_build_scan_request() {
        let request = json!({ "target": "127.0.0.1" });
        assert!(approved_scan_payload(&request, "port-scanner", json!({"target":"127.0.0.1"})).is_err());
        let no_approval = json!({"consent_granted":true});
        assert!(approved_scan_payload(&no_approval, "port-scanner", json!({"target":"127.0.0.1"})).is_err());
        let refused = json!({"consent_granted":false,"approval_token":"mcpap_test"});
        assert!(approved_scan_payload(&refused, "port-scanner", json!({"target":"127.0.0.1"})).is_err());
    }

    #[test]
    fn approved_scan_preserves_exact_scope_and_preset() {
        let args = json!({
            "consent_granted": true,
            "approval_token": "mcpap_test",
            "workspace_id": "workspace-1",
            "preset": "deep",
        });
        let request = approved_scan_payload(&args, "port-scanner", json!({"target": "127.0.0.1"})).unwrap();
        assert_eq!(request["approval_token"], "mcpap_test");
        assert_eq!(request["scan"]["plugin_id"], "port-scanner");
        assert_eq!(request["scan"]["workspace_id"], "workspace-1");
        assert_eq!(request["scan"]["preset"], "deep");
    }
}
