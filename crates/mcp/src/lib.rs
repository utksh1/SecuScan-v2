//! SecuScan MCP server — Model Context Protocol over stdio.
//!
//! Implements JSON-RPC 2.0 with the MCP method surface so AI agents
//! (Claude Desktop, Cursor, Continue, …) can drive SecuScan scans.
//!
//! Tools exposed (see `tools.rs` for the full list with schemas):
//!   * list_plugins          — show the plugin catalogue
//!   * start_scan            — submit a scan and wait for completion
//!   * list_tasks            — recent tasks with status + finding counts
//!   * get_task              — task detail incl. output
//!   * list_findings         — findings with filters
//!   * get_finding           — single finding detail
//!   * triage_finding        — set analyst_status (confirmed/false_positive/…)
//!   * list_workspaces       — workspaces the user can see
//!   * create_workspace      — new workspace
//!   * list_targets          — targets in a workspace
//!   * add_target            — register a target
//!   * list_robots           — show available Pentest Robots
//!   * run_robot             — execute a robot
//!   * get_robot_run         — robot run status
//!   * list_attack_surface   — assets in the Attack Surface inventory
//!   * create_report         — generate a report (md/json/csv/html/sarif)
//!   * list_reports          — recent reports
//!
//! Resources exposed (read-only URIs):
//!   * secuscan://plugins/{id}
//!   * secuscan://tasks/{id}
//!   * secuscan://findings/{id}
//!   * secuscan://workspaces/{id}
//!
//! Built-in prompts:
//!   * pentest       — full pentest against a target
//!   * subdomains    — find all subdomains for a domain
//!   * summary       — exec summary of the latest scans in a workspace
//!   * vibeseccoding — scan + remediate plan for a finding
//!
//! Auth: the MCP server connects to SecuScan's REST API with an API key
//! passed via `SECUSCAN_API_KEY` (or `--api-key`). The key is sent as
//! `Authorization: Bearer <key>` on every request.

pub mod client;
mod proto;
mod tools;
pub use client::SecuScanClient;

use crate::proto::{JsonRpcRequest, JsonRpcResponse};
use anyhow::Result;
use std::io::{self, BufRead, Write};

#[derive(clap::Parser, Debug)]
#[command(name = "secuscan-mcp", version, about = "SecuScan v2 MCP server")]
pub struct Cli {
    /// Base URL of the SecuScan API (e.g. http://127.0.0.1:8080).
    #[arg(
        long,
        env = "SECUSCAN_API_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub api_url: String,

    /// API key for authentication (preferred for production).
    #[arg(long, env = "SECUSCAN_API_KEY")]
    pub api_key: Option<String>,

    /// Email for token-based auth (alternative to --api-key).
    #[arg(long, env = "SECUSCAN_API_EMAIL")]
    pub email: Option<String>,

    /// Password for token-based auth.
    #[arg(long, env = "SECUSCAN_API_PASSWORD")]
    pub password: Option<String>,

    /// Run as HTTP server on the given bind addr (e.g. 127.0.0.1:9100) instead of stdio.
    #[arg(long, env = "SECUSCAN_MCP_HTTP")]
    pub http: Option<String>,
}

pub async fn run_stdio(client: SecuScanClient) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse::error(
                    None,
                    proto::error_codes::PARSE_ERROR,
                    &format!("parse error: {e}"),
                );
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
                continue;
            }
        };
        let resp = dispatch(&client, req).await;
        writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
        stdout.flush()?;
    }
    Ok(())
}

async fn dispatch(client: &SecuScanClient, req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone();
    match req.method.as_str() {
        "initialize" => proto::handle_initialize(req),
        "initialized" => JsonRpcResponse::ok(id, serde_json::Value::Null),
        "tools/list" => tools::list_tools(req),
        "tools/call" => tools::call_tool(client, req).await,
        "resources/list" => proto::list_resources(req),
        "resources/read" => proto::read_resource(client, req).await,
        "prompts/list" => proto::list_prompts(req),
        "prompts/get" => proto::get_prompt(req),
        _ => JsonRpcResponse::error(
            id,
            proto::error_codes::METHOD_NOT_FOUND,
            &format!("unknown method: {}", req.method),
        ),
    }
}

pub async fn run_http(client: SecuScanClient, bind: String) -> Result<()> {
    use axum::{routing::post, Json as AxumJson, Router};
    use std::sync::Arc;

    let client = Arc::new(client);
    let client1 = client.clone();
    let client2 = client.clone();
    let app = Router::new()
        .route(
            "/",
            post(move |AxumJson(req): AxumJson<JsonRpcRequest>| {
                let client = client1.clone();
                async move {
                    let resp = dispatch(&client, req).await;
                    AxumJson(resp)
                }
            }),
        )
        .route(
            "/mcp",
            post(move |AxumJson(req): AxumJson<JsonRpcRequest>| {
                let client = client2.clone();
                async move {
                    let resp = dispatch(&client, req).await;
                    AxumJson(resp)
                }
            }),
        );
    if !(bind.starts_with("127.") || bind.starts_with("localhost") || bind.starts_with("[::1]")) {
        tracing::warn!(
            "MCP HTTP has no auth — binding {bind} exposes start_scan/run_sniper to the network. Prefer 127.0.0.1"
        );
    }
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("MCP HTTP server listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
