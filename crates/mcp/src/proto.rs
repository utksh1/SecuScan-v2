//! JSON-RPC 2.0 protocol types + MCP-specific handlers (initialize, prompts).

use crate::client::SecuScanClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    pub fn error(id: Option<Value>, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".into(), id, result: None,
            error: Some(JsonRpcError { code: code.into(), message: message.into(), data: None }),
        }
    }
}

pub mod ErrorCodes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

pub fn handle_initialize(req: JsonRpcRequest) -> JsonRpcResponse {
    let result = json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": { "listChanged": false },
            "resources": { "listChanged": false, "subscribe": false },
            "prompts": { "listChanged": false }
        },
        "serverInfo": {
            "name": "secuscan-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        }
    });
    JsonRpcResponse::ok(req.id, result)
}

pub fn list_resources(req: JsonRpcRequest) -> JsonRpcResponse {
    let resources = json!({
        "resources": [
            { "uri": "secuscan://plugins", "name": "Plugin catalogue", "description": "All available scanners" },
            { "uri": "secuscan://tasks", "name": "Recent tasks", "description": "Most recent scan tasks" },
            { "uri": "secuscan://findings", "name": "Recent findings", "description": "Most recent findings across all scans" },
            { "uri": "secuscan://workspaces", "name": "Workspaces", "description": "All workspaces" },
            { "uri": "secuscan://attack-surface", "name": "Attack Surface", "description": "Aggregated asset inventory" },
        ]
    });
    JsonRpcResponse::ok(req.id, resources)
}

pub async fn read_resource(client: &SecuScanClient, req: JsonRpcRequest) -> JsonRpcResponse {
    let uri = match req.params.as_ref().and_then(|p| p.get("uri")).and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => return JsonRpcResponse::error(req.id, ErrorCodes::INVALID_PARAMS, "missing `uri`"),
    };
    let body = match client.get_resource(&uri).await {
        Ok(b) => b,
        Err(e) => return JsonRpcResponse::error(req.id, ErrorCodes::INTERNAL_ERROR, &e.to_string()),
    };
    JsonRpcResponse::ok(req.id, json!({
        "contents": [{ "uri": uri, "mimeType": "application/json", "text": body }]
    }))
}

pub fn list_prompts(req: JsonRpcRequest) -> JsonRpcResponse {
    let prompts = json!({
        "prompts": [
            { "name": "pentest", "description": "Comprehensive pentest against a target",
              "arguments": [{ "name": "target", "required": true, "description": "IP/hostname/URL" }] },
            { "name": "subdomains", "description": "Find all subdomains for a domain",
              "arguments": [{ "name": "domain", "required": true }] },
            { "name": "summary", "description": "Executive summary of latest scans in a workspace",
              "arguments": [{ "name": "workspace_id", "required": false }] },
            { "name": "vibeseccoding", "description": "Scan-then-remediate plan for a finding",
              "arguments": [{ "name": "finding_id", "required": true }] },
        ]
    });
    JsonRpcResponse::ok(req.id, prompts)
}

pub fn get_prompt(req: JsonRpcRequest) -> JsonRpcResponse {
    let params = match req.params { Some(p) => p, None => return JsonRpcResponse::error(req.id, ErrorCodes::INVALID_PARAMS, "missing params") };
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let (description, messages) = match name {
        "pentest" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("TARGET");
            (
                format!("Run a comprehensive pentest against {target}"),
                vec![json!({
                    "role": "user",
                    "content": { "type": "text", "text": format!(
                        "Please provide a comprehensive pentesting report for {target}, using the tools at your disposal. Run subdomain enumeration, port scanning, web scanning, and TLS checks. Aggregate findings by severity and propose remediation."
                    ) }
                })]
            )
        }
        "subdomains" => {
            let domain = args.get("domain").and_then(|v| v.as_str()).unwrap_or("DOMAIN");
            (
                format!("Find all subdomains for {domain}"),
                vec![json!({
                    "role": "user",
                    "content": { "type": "text", "text": format!(
                        "Please find all the subdomains that you can for {domain}, using the tools at your disposal. Combine passive sources (subfinder) with active brute-force (subdomain-finder)."
                    ) }
                })]
            )
        }
        "summary" => {
            let ws = args.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("");
            (
                "Executive summary of latest scans".into(),
                vec![json!({
                    "role": "user",
                    "content": { "type": "text", "text": format!(
                        "Please create an executive summary for the latest scans in the workspace {ws}, using the tools at your disposal. Highlight critical and high findings and the affected assets."
                    ) }
                })]
            )
        }
        "vibeseccoding" => {
            let fid = args.get("finding_id").and_then(|v| v.as_str()).unwrap_or("");
            (
                "Scan-then-remediate plan".into(),
                vec![json!({
                    "role": "user",
                    "content": { "type": "text", "text": format!(
                        "Finding {fid} needs remediation. Read the finding, look up the affected code/config, propose a concrete patch, and verify by re-scanning."
                    ) }
                })]
            )
        }
        _ => return JsonRpcResponse::error(req.id, ErrorCodes::INVALID_PARAMS, &format!("unknown prompt: {name}")),
    };
    JsonRpcResponse::ok(req.id, json!({
        "description": description,
        "messages": messages
    }))
}
