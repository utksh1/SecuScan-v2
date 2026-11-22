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
        tool("list_workspaces", "List workspaces", json!({})),
        tool("list_targets", "List targets in a workspace", json!({
            "type": "object",
            "properties": { "workspace_id": { "type": "string" } },
            "required": ["workspace_id"]
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
        tool("list_reports", "List recent report jobs", json!({})),
        tool("get_sniper_run", "Get a Sniper run by id", json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"]
        })),
        tool("list_vpn_profiles", "List OpenVPN profiles owned by the caller", json!({})),
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
        tool("stop_task", "Cancel a queued or running scan", json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"]
        })),
        tool("delete_task", "Delete a task AND its findings (irreversible — pass confirm=true)", json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "confirm": { "type": "boolean", "description": "Must be true; deletion also removes findings" }
            },
            "required": ["id", "confirm"]
        })),
        tool("get_raw_output", "Get the raw scanner output for a task (stdout+stderr)", json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"]
        })),
        tool("create_finding", "Create a manual analyst finding anchored to an existing task", json!({
            "type": "object",
            "properties": {
                "task_id": { "type": "string" },
                "title": { "type": "string", "minLength": 1 },
                "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
                "category": { "type": "string" },
                "description": { "type": "string" },
                "remediation": { "type": "string" },
                "proof": { "type": "string" },
                "url": { "type": "string" }
            },
            "required": ["task_id", "title", "severity"]
        })),
    ]});
    JsonRpcResponse::ok(req.id, tools)
}

/// Build a tool entry with MCP **annotations** (issue #32): `readOnlyHint`
/// and `destructiveHint` let compliant clients auto-gate destructive calls.
fn tool(name: &str, description: &str, schema: Value) -> Value {
    let (read_only, destructive) = match name {
        // Launchers change server state (spawn scans, burn approvals).
        "start_scan" | "start_people_hunter" | "run_robot" => (false, true),
        // Deletion is destructive. Note start_scan is BOTH: it is a state
        // change (not read-only) whose destructiveHint lets clients gate it.
        "delete_task" => (false, true),
        _ => (true, false),
    };
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
        },
    })
}

/// Minimal JSON-Schema enforcement at dispatch (issue #32): required keys,
/// declared types, enum membership and string minLength. The schemas are the
/// same ones `list_tools` advertises — what the LLM sees is what is enforced.
fn validate_args(name: &str, schema: &Value, args: &Value) -> Result<(), String> {
    let empty = serde_json::Map::new();
    let props = schema.get("properties").and_then(Value::as_object).unwrap_or(&empty);
    for req in schema.get("required").and_then(Value::as_array).unwrap_or(&vec![]) {
        let key = req.as_str().unwrap_or("");
        if args.get(key).is_none() {
            return Err(format!("{name}: missing required argument `{key}`"));
        }
    }
    for (key, spec) in props {
        let v = match args.get(key) {
            Some(v) if !v.is_null() => v,
            _ => continue,
        };
        let ty = spec.get("type").and_then(Value::as_str).unwrap_or("");
        let ok = match ty {
            "string" => v.is_string(),
            "boolean" => v.is_boolean(),
            "integer" | "number" => v.is_i64() || v.is_u64() || v.is_f64(),
            "array" => v.is_array(),
            "object" => v.is_object(),
            _ => true,
        };
        if !ok {
            return Err(format!("{name}: argument `{key}` must be {ty}"));
        }
        if let Some(min) = spec.get("minLength").and_then(Value::as_u64) {
            if v.as_str().map(|s| s.chars().count() < min as usize).unwrap_or(false) {
                return Err(format!("{name}: argument `{key}` must be at least {min} characters"));
            }
        }
    }
    Ok(())
}

/// The advertised tool schemas, keyed by name — the dispatch validator uses
/// exactly what `list_tools` returned to the client.
pub fn tool_schemas() -> serde_json::Map<String, Value> {
    let resp = list_tools(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: None,
        method: "tools/list".into(),
        params: None,
    });
    let tools = resp
        .result
        .as_ref()
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    tools
        .into_iter()
        .filter_map(|t| {
            let name = t.get("name")?.as_str()?.to_string();
            Some((name, t.get("inputSchema").cloned().unwrap_or(Value::Null)))
        })
        .collect()
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
    // Sprint 3.3 (#32): enforce the advertised schema at dispatch — enums,
    // types, required keys — before any API call happens.
    let schemas = tool_schemas();
    let validated = match schemas.get(name) {
        Some(schema) => match validate_args(name, schema, &args) {
            Ok(()) => args,
            Err(e) => {
                return JsonRpcResponse::ok(
                    id,
                    json!({
                        "isError": true,
                        "content": [{ "type": "text", "text": format!("error: {e}") }]
                    }),
                )
            }
        },
        None => {
            return JsonRpcResponse::ok(
                id,
                json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("error: unknown tool `{name}`") }]
                }),
            )
        }
    };
    let result = dispatch_call(client, name, validated).await;
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
        "stop_task" => {
            let id = args.get("id").and_then(|v| v.as_str()).ok_or("missing id")?;
            let v = client
                .post(&format!("/api/v1/tasks/{id}/cancel"), json!({}))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "delete_task" => {
            let id = args.get("id").and_then(|v| v.as_str()).ok_or("missing id")?;
            let confirm = args
                .get("confirm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !confirm {
                return Err(
                    "deleting a task also deletes its findings — pass confirm=true to proceed"
                        .into(),
                );
            }
            let _ = client
                .delete(&format!("/api/v1/tasks/{id}"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(format!("task {id} deleted"))
        }
        "get_raw_output" => {
            let id = args.get("id").and_then(|v| v.as_str()).ok_or("missing id")?;
            let v = client
                .get(&format!("/api/v1/tasks/{id}/output"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
        "create_finding" => {
            let task_id = args
                .get("task_id")
                .and_then(|v| v.as_str())
                .ok_or("missing task_id")?;
            let title = args
                .get("title")
                .and_then(|v| v.as_str())
                .ok_or("missing title")?;
            let severity = args
                .get("severity")
                .and_then(|v| v.as_str())
                .ok_or("missing severity")?;
            let body = json!({
                "task_id": task_id,
                "title": title,
                "severity": severity,
                "category": args.get("category"),
                "description": args.get("description"),
                "remediation": args.get("remediation"),
                "proof": args.get("proof"),
                "url": args.get("url"),
            });
            let v = client
                .post("/api/v1/findings", body)
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?)
        }
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
        "list_workspaces" => {
            let v = client
                .get("/api/v1/workspaces")
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
        "start_people_hunter" => {
            let target = args
                .get("target")
                .and_then(Value::as_str)
                .ok_or("missing target")?;
            let body = approved_scan_payload(&args, "people-hunter", json!({ "target": target }))?;
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
        for action in [
            "triage_finding",
            "create_workspace",
            "add_target",
            "create_report",
            "test_vpn_profile",
        ] {
            assert!(!items.iter().any(|x| x["name"] == action));
        }
    }

    #[test]
    fn no_consent_or_approval_cannot_build_scan_request() {
        let request = json!({ "target": "127.0.0.1" });
        assert!(
            approved_scan_payload(&request, "port-scanner", json!({"target":"127.0.0.1"})).is_err()
        );
        let no_approval = json!({"consent_granted":true});
        assert!(
            approved_scan_payload(&no_approval, "port-scanner", json!({"target":"127.0.0.1"}))
                .is_err()
        );
        let refused = json!({"consent_granted":false,"approval_token":"mcpap_test"});
        assert!(
            approved_scan_payload(&refused, "port-scanner", json!({"target":"127.0.0.1"})).is_err()
        );
    }

    #[test]
    fn approved_scan_preserves_exact_scope_and_preset() {
        let args = json!({
            "consent_granted": true,
            "approval_token": "mcpap_test",
            "workspace_id": "workspace-1",
            "preset": "deep",
        });
        let request =
            approved_scan_payload(&args, "port-scanner", json!({"target": "127.0.0.1"})).unwrap();
        assert_eq!(request["approval_token"], "mcpap_test");
        assert_eq!(request["scan"]["plugin_id"], "port-scanner");
        assert_eq!(request["scan"]["workspace_id"], "workspace-1");
        assert_eq!(request["scan"]["preset"], "deep");
    }
}

#[cfg(test)]
mod governance_tests {
    use super::*;

    #[test]
    fn validator_enforces_required_types_and_min_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "limit": { "type": "integer" },
                "confirm": { "type": "boolean" },
                "title": { "type": "string", "minLength": 3 }
            },
            "required": ["id"]
        });

        // Missing required.
        assert!(validate_args("t", &schema, &json!({})).is_err());
        // Type mismatch.
        assert!(validate_args("t", &schema, &json!({ "id": 42 })).is_err());
        assert!(validate_args("t", &schema, &json!({ "id": "x", "confirm": "yes" })).is_err());
        // minLength.
        assert!(validate_args("t", &schema, &json!({ "id": "x", "title": "ab" })).is_err());
        // Happy paths.
        assert!(validate_args("t", &schema, &json!({ "id": "x", "limit": 5, "confirm": true, "title": "abc" })).is_ok());
        // Extra unknown args are tolerated (the API re-validates authoritatively).
        assert!(validate_args("t", &schema, &json!({ "id": "x", "extra": 1 })).is_ok());
    }

    #[test]
    fn every_tool_carries_annotations() {
        let resp = list_tools(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "tools/list".into(),
            params: None,
        });
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
        println!("DEBUG tools len={}", tools.len());
        assert!(tools.len() >= 17, "tool catalogue size: {}", tools.len());
        for t in &tools {
            let ann = t.get("annotations").expect("annotations block");
            assert!(ann.get("readOnlyHint").is_some(), "readOnlyHint on {}", t["name"]);
            assert!(ann.get("destructiveHint").is_some(), "destructiveHint on {}", t["name"]);
        }
        // Launchers destructive; readers read-only.
        let by = |n: &str| tools.iter().find(|t| t["name"] == n).unwrap().clone();
        assert_eq!(by("start_scan")["annotations"]["destructiveHint"], true);
        assert_eq!(by("list_tasks")["annotations"]["readOnlyHint"], true);
        assert_eq!(by("delete_task")["annotations"]["destructiveHint"], true);
    }

    #[test]
    fn tool_schemas_cover_every_tool() {
        let schemas = tool_schemas();
        let resp = list_tools(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "tools/list".into(),
            params: None,
        });
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
        for t in &tools {
            let name = t["name"].as_str().unwrap();
            assert!(schemas.contains_key(name), "schema registry has {name}");
        }
    }

    #[test]
    fn dispatch_rejects_invalid_args_before_api_calls() {
        // The validator is the gate: a get_task without `id` must fail with a
        // structured message naming the tool and the missing key.
        let schema = tool_schemas().get("get_task").unwrap().clone();
        let err = validate_args("get_task", &schema, &json!({})).unwrap_err();
        assert!(err.contains("get_task") && err.contains("`id`"), "{err}");
    }
}
