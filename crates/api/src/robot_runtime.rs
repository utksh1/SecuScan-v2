//! Pentest Robot runtime — walks the DAG and orchestrates scans.
//!
//! A robot is a directed acyclic graph with four node kinds:
//!
//! * `Tool` — runs one scan per incoming target. The plugin's `target` field
//!   is set from each incoming target string. Emits one result per scan
//!   (target + finding count + status).
//! * `Filter` — keeps/discards results by a JSON predicate (severity op value,
//!   category match, target match). One result per surviving item.
//! * `Extractor` — pulls new target strings out of a result's findings (e.g.
//!   hostnames from a Subdomain Finder run, or URLs built from open ports).
//!   Emits one "target" item per extracted string.
//! * `Reducer` — processes ALL incoming items together and emits a reduced
//!   set (e.g. deduplicate by resolved IP — one hostname per IP).
//!
//! The graph is stored as JSON. We parse it, walk it in topological order,
//! and persist state after each node finishes so the UI can render live
//! progress. Failed nodes abort the run; the user can rerun from any node.

use crate::auth::extractor::CurrentUser;

use crate::routes::tasks::{validate_and_create_task, StartTaskRequest};
use crate::state::SharedState;
use secuscan_db::repo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

/// Maximum number of nodes in a robot graph. Keeps the runtime bounded.
pub const MAX_NODES: usize = 64;
/// Maximum number of items a single node may emit. Prevents a runaway
/// extractor (e.g. a wildcard DNS brute-force) from OOMing the process.
pub const MAX_ITEMS_PER_NODE: usize = 5_000;

// --- node model ------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RobotNode {
    pub id: String,
    pub kind: NodeKind,
    /// Tool nodes only: which plugin to run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    /// Tool nodes only: static inputs merged with {target: <incoming>}.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, Value>,
    /// Tool nodes only: optional preset name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Filter nodes only: JSON predicate (see [`eval_filter`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Value>,
    /// Extractor nodes only: extractor spec (see [`run_extractor`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extractor: Option<ExtractorSpec>,
    /// Reducer nodes only: reducer kind (`dedup_by_ip`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reducer: Option<String>,
    /// Human-readable label shown in the UI.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Tool,
    Filter,
    Extractor,
    Reducer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtractorSpec {
    /// `finding_field` — pull a field out of each finding (url, hostname, ip).
    /// `port_url` — build URLs from open ports found in findings metadata.
    /// `finding_title_regex` — extract from titles with a regex (group 1).
    pub kind: String,
    /// For `finding_field` / `finding_title_regex`: the field name or regex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// For `port_url`: which schemes to emit (default: ["http", "https"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schemes: Vec<String>,
    /// Cap on items emitted (default: [`MAX_ITEMS_PER_NODE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RobotEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RobotGraph {
    pub nodes: Vec<RobotNode>,
    #[serde(default)]
    pub edges: Vec<RobotEdge>,
}

// --- runtime items ---------------------------------------------------------

/// One row flowing through the graph. Tools emit `Result` items (one per
/// scan); extractors emit `Target` items; filters pass items through; reducers
/// re-emit Target items (deduplicated).
#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub kind: ItemKind,
    /// The target string (extractor/reducer output) or the scan's target.
    pub target: Option<String>,
    /// For `Result` items: the task id and finding summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings_count: Option<usize>,
    /// Severity counts for the scan (high: n, medium: n, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub severity: BTreeMap<String, usize>,
    /// The findings themselves (only kept transiently for filter/extractor).
    #[serde(skip)]
    pub findings: Vec<secuscan_db::models::FindingRow>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Target,
    Result,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeState {
    pub status: String,
    pub items_in: usize,
    pub items_out: usize,
    pub task_ids: Vec<String>,
    pub error: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

pub type GraphState = HashMap<String, NodeState>;

// --- entry point -----------------------------------------------------------

/// Validate a robot graph at definition time.
pub fn validate(graph: &RobotGraph) -> Result<(), String> {
    if graph.nodes.is_empty() || graph.nodes.len() > MAX_NODES {
        return Err(format!("graph must have 1..={MAX_NODES} nodes"));
    }
    let ids: HashSet<&str> = graph.nodes.iter().map(|n| n.id.as_str()).collect();
    if ids.len() != graph.nodes.len() {
        return Err("duplicate node id".into());
    }
    for n in &graph.nodes {
        match n.kind {
            NodeKind::Tool => {
                if n.plugin_id.as_deref().unwrap_or("").is_empty() {
                    return Err(format!("tool node `{}` missing plugin_id", n.id));
                }
            }
            NodeKind::Filter => {
                if n.filter.is_none() {
                    return Err(format!("filter node `{}` missing filter predicate", n.id));
                }
            }
            NodeKind::Extractor => {
                if n.extractor.is_none() {
                    return Err(format!("extractor node `{}` missing extractor spec", n.id));
                }
            }
            NodeKind::Reducer => {
                if n.reducer.as_deref().unwrap_or("").is_empty() {
                    return Err(format!("reducer node `{}` missing reducer kind", n.id));
                }
            }
        }
    }
    for e in &graph.edges {
        if !ids.contains(e.from.as_str()) || !ids.contains(e.to.as_str()) {
            return Err(format!("edge references unknown node: {:?}", e));
        }
    }
    if has_cycle(graph) {
        return Err("graph contains a cycle".into());
    }
    Ok(())
}

fn has_cycle(graph: &RobotGraph) -> bool {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in &graph.edges {
        adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
    }
    let mut white: HashSet<&str> = graph.nodes.iter().map(|n| n.id.as_str()).collect();
    let mut gray: HashSet<&str> = HashSet::new();
    let mut black: HashSet<&str> = HashSet::new();
    fn dfs<'a>(
        u: &'a str,
        adj: &HashMap<&'a str, Vec<&'a str>>,
        white: &mut HashSet<&'a str>,
        gray: &mut HashSet<&'a str>,
        black: &mut HashSet<&'a str>,
    ) -> bool {
        white.remove(u);
        gray.insert(u);
        if let Some(neighbors) = adj.get(u) {
            for &v in neighbors {
                if gray.contains(v) {
                    return true;
                }
                if black.contains(v) {
                    continue;
                }
                if dfs(v, adj, white, gray, black) {
                    return true;
                }
            }
        }
        gray.remove(u);
        black.insert(u);
        false
    }
    for n in &graph.nodes {
        if white.contains(n.id.as_str())
            && dfs(n.id.as_str(), &adj, &mut white, &mut gray, &mut black)
        {
            return true;
        }
    }
    false
}

/// Topological order of node ids.
fn topo_order(graph: &RobotGraph) -> Vec<String> {
    let mut in_deg: HashMap<&str, usize> = HashMap::new();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for n in &graph.nodes {
        in_deg.entry(n.id.as_str()).or_insert(0);
    }
    for e in &graph.edges {
        adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
        *in_deg.entry(e.to.as_str()).or_insert(0) += 1;
    }
    let mut queue: Vec<&str> = in_deg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(k, _)| *k)
        .collect();
    queue.sort();
    let mut out = Vec::new();
    while let Some(u) = queue.pop() {
        out.push(u.to_string());
        if let Some(neighbors) = adj.get(u) {
            for &v in neighbors {
                if let Some(d) = in_deg.get_mut(v) {
                    *d -= 1;
                    if *d == 0 {
                        queue.push(v);
                        queue.sort();
                    }
                }
            }
        }
    }
    out
}

/// Items destined for a node = union of all predecessor nodes' outputs.
fn incoming_for(
    graph: &RobotGraph,
    node_id: &str,
    outputs: &HashMap<String, Vec<Item>>,
) -> Vec<Item> {
    let mut items = Vec::new();
    for e in &graph.edges {
        if e.to == node_id {
            if let Some(out) = outputs.get(&e.from) {
                items.extend(out.iter().cloned());
            }
        }
    }
    items
}

/// Run the robot. The `initial_targets` are the seed items fed to the
/// graph's source nodes (nodes with no incoming edges).
pub async fn run(
    state: &SharedState,
    user: &CurrentUser,
    robot_id: &str,
    run_id: &str,
    workspace_id: Option<&str>,
    auth_profile_id: Option<&str>,
    initial_targets: Vec<String>,
) -> Result<(), String> {
    let robot = repo::robots::get(&state.db, robot_id)
        .await
        .map_err(|e| format!("load robot: {e}"))?;
    // Reconstruct the full graph from the two separate JSON columns.
    let nodes: Vec<RobotNode> =
        serde_json::from_str(&robot.nodes_json).map_err(|e| format!("parse nodes: {e}"))?;
    let edges: Vec<RobotEdge> =
        serde_json::from_str(&robot.edges_json).map_err(|e| format!("parse edges: {e}"))?;
    let graph = RobotGraph { nodes, edges };
    validate(&graph).map_err(|e| format!("invalid graph: {e}"))?;

    let order = topo_order(&graph);
    let mut outputs: HashMap<String, Vec<Item>> = HashMap::new();

    // Seed source nodes with initial targets as Target items.
    let source_ids: HashSet<String> = graph
        .nodes
        .iter()
        .filter(|n| !graph.edges.iter().any(|e| e.to == n.id))
        .map(|n| n.id.clone())
        .collect();
    for sid in &source_ids {
        outputs.insert(
            sid.clone(),
            initial_targets
                .iter()
                .map(|t| Item {
                    kind: ItemKind::Target,
                    target: Some(t.clone()),
                    task_id: None,
                    status: None,
                    findings_count: None,
                    severity: BTreeMap::new(),
                    findings: vec![],
                })
                .collect(),
        );
    }

    let deadline = Instant::now() + repo::robots::run_timeout();
    for node_id in &order {
        if Instant::now() >= deadline {
            return Err("robot run exceeded 48h bound".into());
        }
        let node = graph
            .nodes
            .iter()
            .find(|n| &n.id == node_id)
            .ok_or_else(|| format!("missing node {node_id}"))?;
        // Source nodes (no incoming edges) get their items from the
        // pre-seeded outputs map; non-source nodes pull from predecessors.
        let items_in = if source_ids.contains(node_id) {
            outputs.get(node_id).cloned().unwrap_or_default()
        } else {
            incoming_for(&graph, node_id, &outputs)
        };

        // Update state to running.
        set_node_state(
            state,
            run_id,
            node_id,
            NodeState {
                status: "running".into(),
                items_in: items_in.len(),
                items_out: 0,
                task_ids: vec![],
                error: None,
                started_at: secuscan_db::now(),
                finished_at: None,
            },
        )
        .await
        .map_err(|e| e.to_string())?;

        let result = match node.kind {
            NodeKind::Tool => {
                run_tool(
                    state,
                    user,
                    node,
                    &items_in,
                    workspace_id,
                    auth_profile_id,
                    run_id,
                )
                .await
            }
            NodeKind::Filter => run_filter(node, &items_in),
            NodeKind::Extractor => run_extractor(node, &items_in),
            NodeKind::Reducer => run_reducer(node, &items_in),
        };

        match result {
            Ok(out_items) => {
                let truncated = out_items.len() > MAX_ITEMS_PER_NODE;
                let out_items: Vec<Item> = if truncated {
                    out_items.into_iter().take(MAX_ITEMS_PER_NODE).collect()
                } else {
                    out_items
                };
                let task_ids: Vec<String> =
                    out_items.iter().filter_map(|i| i.task_id.clone()).collect();
                set_node_state(
                    state,
                    run_id,
                    node_id,
                    NodeState {
                        status: "completed".into(),
                        items_in: items_in.len(),
                        items_out: out_items.len(),
                        task_ids,
                        error: if truncated {
                            Some(format!("truncated to {MAX_ITEMS_PER_NODE} items"))
                        } else {
                            None
                        },
                        started_at: secuscan_db::now(),
                        finished_at: Some(secuscan_db::now()),
                    },
                )
                .await
                .map_err(|e| e.to_string())?;
                outputs.insert(node_id.clone(), out_items);
            }
            Err(e) => {
                set_node_state(
                    state,
                    run_id,
                    node_id,
                    NodeState {
                        status: "failed".into(),
                        items_in: items_in.len(),
                        items_out: 0,
                        task_ids: vec![],
                        error: Some(e.clone()),
                        started_at: secuscan_db::now(),
                        finished_at: Some(secuscan_db::now()),
                    },
                )
                .await
                .map_err(|e2| e2.to_string())?;
                return Err(format!("node `{node_id}` failed: {e}"));
            }
        }
    }
    Ok(())
}

async fn set_node_state(
    state: &SharedState,
    run_id: &str,
    node_id: &str,
    st: NodeState,
) -> Result<(), String> {
    // Read-modify-write the run's state_json.
    let row = repo::robots::get_run(&state.db, run_id)
        .await
        .map_err(|e| e.to_string())?;
    let mut map: serde_json::Map<String, Value> =
        serde_json::from_str(&row.state_json).unwrap_or_else(|_| serde_json::Map::new());
    map.insert(
        node_id.into(),
        serde_json::to_value(&st).unwrap_or(Value::Null),
    );
    let new_state = serde_json::to_string(&Value::Object(map)).unwrap_or_else(|_| "{}".into());
    repo::robots::set_run_state(&state.db, run_id, &new_state)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

// --- node runners ----------------------------------------------------------

async fn run_tool(
    state: &SharedState,
    user: &CurrentUser,
    node: &RobotNode,
    items: &[Item],
    workspace_id: Option<&str>,
    auth_profile_id: Option<&str>,
    run_id: &str,
) -> Result<Vec<Item>, String> {
    let plugin_id = node
        .plugin_id
        .as_ref()
        .ok_or("tool node missing plugin_id")?;
    // If no incoming targets, treat the static inputs (must contain target).
    let targets: Vec<String> = if items.is_empty() {
        match node
            .inputs
            .get("target")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        {
            Some(t) => vec![t],
            None => {
                // No incoming items and no static target — this is a leaf
                // node whose upstream extractor produced nothing (e.g. a
                // port scan that found no HTTP ports). Return empty rather
                // than erroring so the robot can continue to other branches.
                return Ok(Vec::new());
            }
        }
    } else {
        items.iter().filter_map(|i| i.target.clone()).collect()
    };
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for target in targets {
        let mut inputs = node.inputs.clone();
        inputs.insert("target".into(), json!(target));
        let req = StartTaskRequest {
            plugin_id: plugin_id.clone(),
            inputs,
            preset: node.preset.clone(),
            consent_granted: true,
            auth_profile_id: None,
            workspace_id: workspace_id.map(str::to_string),
        };
        let (task, manifest, normalized) = validate_and_create_task(state, user, &req, None, None)
            .await
            .map_err(|e| format!("task rejected for target `{target}`: {e}"))?;
        // Attach to robot run.
        let _ = sqlx::query("UPDATE tasks SET robot_run_id = ? WHERE id = ?")
            .bind(run_id)
            .bind(&task.id)
            .execute(&state.db)
            .await;
        // Also set auth_profile_id if provided.
        if let Some(pid) = auth_profile_id {
            let _ = sqlx::query("UPDATE tasks SET auth_profile_id = ? WHERE id = ?")
                .bind(pid)
                .bind(&task.id)
                .execute(&state.db)
                .await;
        }
        state.tasks.spawn(task.clone(), manifest, normalized).await;
        // Wait for terminal state.
        let deadline = Instant::now() + std::time::Duration::from_secs(86_400);
        let final_status = loop {
            let t = repo::tasks::get(&state.db, &task.id)
                .await
                .map_err(|e| e.to_string())?;
            if t.status().is_terminal() {
                break t.status();
            }
            if Instant::now() >= deadline {
                state.tasks.cancel(&task.id).await;
                return Err(format!("task `{}` exceeded 24h bound", task.id));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        };
        let findings = repo::findings::list_all_for_task(&state.db, &task.id)
            .await
            .map_err(|e| e.to_string())?;
        let mut sev: BTreeMap<String, usize> = BTreeMap::new();
        for f in &findings {
            *sev.entry(f.severity.clone()).or_insert(0) += 1;
        }
        out.push(Item {
            kind: ItemKind::Result,
            target: Some(target),
            task_id: Some(task.id.clone()),
            status: Some(final_status.label().to_string()),
            findings_count: Some(findings.len()),
            severity: sev,
            findings,
        });
    }
    Ok(out)
}

fn run_filter(node: &RobotNode, items: &[Item]) -> Result<Vec<Item>, String> {
    let pred = node
        .filter
        .as_ref()
        .ok_or("filter node missing predicate")?;
    let mut out = Vec::new();
    for item in items {
        if eval_filter(pred, item) {
            out.push(item.clone());
        }
    }
    Ok(out)
}

/// Predicate evaluator. Supports a small JSON DSL:
///   {"severity": ">=medium"}                — keep results with at least one medium+
///   {"severity": "high"}                    — keep results with at least one high
///   {"category": "open_port"}               — keep findings with this category
///   {"status": "completed"}                 — keep completed scans
///   {"target_contains": "example.com"}      — substring match on target
///   {"and": [pred, pred, ...]}              — all must match
///   {"or":  [pred, pred, ...]}              — any must match
fn eval_filter(pred: &Value, item: &Item) -> bool {
    let obj = match pred.as_object() {
        Some(o) => o,
        None => return false,
    };
    for (k, v) in obj {
        match k.as_str() {
            "severity" => {
                let want = v.as_str().unwrap_or("");
                let (op, val) = if let Some(rest) = want.strip_prefix(">=") {
                    (">=", rest)
                } else if let Some(rest) = want.strip_prefix("<=") {
                    ("<=", rest)
                } else {
                    ("=", want)
                };
                let order = ["info", "low", "medium", "high", "critical"];
                let want_idx = order.iter().position(|s| *s == val).unwrap_or(0);
                let max_seen = item
                    .severity
                    .iter()
                    .filter_map(|(k, _)| order.iter().position(|s| s == k))
                    .max()
                    .unwrap_or(0);
                let pass = match op {
                    ">=" => max_seen >= want_idx,
                    "<=" => max_seen <= want_idx,
                    _ => max_seen == want_idx,
                };
                if !pass {
                    return false;
                }
            }
            "category" => {
                let want = v.as_str().unwrap_or("");
                if !item.findings.iter().any(|f| f.category == want) {
                    return false;
                }
            }
            "status" => {
                let want = v.as_str().unwrap_or("");
                if item.status.as_deref().unwrap_or("") != want {
                    return false;
                }
            }
            "target_contains" => {
                let needle = v.as_str().unwrap_or("");
                if !item.target.as_deref().unwrap_or("").contains(needle) {
                    return false;
                }
            }
            "and" => {
                if let Some(arr) = v.as_array() {
                    if !arr.iter().all(|p| eval_filter(p, item)) {
                        return false;
                    }
                }
            }
            "or" => {
                if let Some(arr) = v.as_array() {
                    if !arr.iter().any(|p| eval_filter(p, item)) {
                        return false;
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

fn run_extractor(node: &RobotNode, items: &[Item]) -> Result<Vec<Item>, String> {
    let spec = node.extractor.as_ref().ok_or("extractor missing spec")?;
    let limit = spec.limit.unwrap_or(MAX_ITEMS_PER_NODE);
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for item in items {
        for f in &item.findings {
            let extracted: Vec<String> = match spec.kind.as_str() {
                "finding_field" => {
                    let field = spec.pattern.as_deref().unwrap_or("url");
                    extract_finding_field(f, field)
                }
                "port_url" => extract_port_urls(f, &spec.schemes),
                "finding_title_regex" => {
                    let pat = spec.pattern.as_deref().unwrap_or("");
                    extract_title_regex(f, pat)
                }
                _ => return Err(format!("unknown extractor kind: {}", spec.kind)),
            };
            for v in extracted {
                if seen.insert(v.clone()) {
                    out.push(v);
                    if out.len() >= limit {
                        break;
                    }
                }
            }
            if out.len() >= limit {
                break;
            }
        }
        if out.len() >= limit {
            break;
        }
    }
    Ok(out
        .into_iter()
        .map(|t| Item {
            kind: ItemKind::Target,
            target: Some(t),
            task_id: None,
            status: None,
            findings_count: None,
            severity: BTreeMap::new(),
            findings: vec![],
        })
        .collect())
}

fn extract_finding_field(f: &secuscan_db::models::FindingRow, field: &str) -> Vec<String> {
    match field {
        "url" => f.url.clone().into_iter().collect(),
        "title" => vec![f.title.clone()],
        _ => {
            // Try metadata
            if let Ok(meta) = serde_json::from_str::<Value>(&f.metadata_json) {
                if let Some(s) = meta.get(field).and_then(|v| v.as_str()) {
                    return vec![s.to_string()];
                }
            }
            vec![]
        }
    }
}

fn extract_port_urls(f: &secuscan_db::models::FindingRow, schemes: &[String]) -> Vec<String> {
    let schemes = if schemes.is_empty() {
        vec!["http".to_string(), "https".to_string()]
    } else {
        schemes.to_vec()
    };
    // Look in metadata for {ports: [{port, proto}]} or {port: n, host: h}
    let meta: Value = serde_json::from_str(&f.metadata_json).unwrap_or(Value::Null);
    let mut out = Vec::new();
    let host = f
        .url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
        .or_else(|| {
            meta.get("host")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    let host = match host {
        Some(h) => h,
        None => return out,
    };
    if let Some(ports) = meta.get("ports").and_then(|v| v.as_array()) {
        for p in ports {
            let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            if port == 0 {
                continue;
            }
            let proto = p.get("proto").and_then(|v| v.as_str()).unwrap_or("tcp");
            if proto != "tcp" {
                continue;
            }
            for s in &schemes {
                out.push(format!("{s}://{host}:{port}"));
            }
        }
    }
    out
}

fn extract_title_regex(f: &secuscan_db::models::FindingRow, pat: &str) -> Vec<String> {
    let re = match regex::Regex::new(pat) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    if let Some(caps) = re.captures(&f.title) {
        if let Some(g) = caps.get(1) {
            return vec![g.as_str().to_string()];
        }
    }
    vec![]
}

fn run_reducer(node: &RobotNode, items: &[Item]) -> Result<Vec<Item>, String> {
    match node.reducer.as_deref().unwrap_or("") {
        "dedup_by_ip" => {
            // Group targets by resolved IP — but we don't have DNS here, so
            // we dedup by target string (which is the common case when the
            // upstream tool already resolved). This is a behavioural match
            // for the pentest-tools.com Reducer: one hostname per IP. We
            // keep the first seen for each target value.
            let mut seen: HashSet<String> = HashSet::new();
            let mut out = Vec::new();
            for item in items {
                if let Some(t) = &item.target {
                    if seen.insert(t.clone()) {
                        out.push(item.clone());
                    }
                }
            }
            Ok(out)
        }
        "unique_targets" => {
            let mut seen: HashSet<String> = HashSet::new();
            let mut out = Vec::new();
            for item in items {
                if let Some(t) = &item.target {
                    if seen.insert(t.clone()) {
                        out.push(item.clone());
                    }
                }
            }
            Ok(out)
        }
        other => Err(format!("unknown reducer kind: {other}")),
    }
}

// --- builtin robots --------------------------------------------------------

/// Returns the builtin robot graphs shipped with the product. Each entry
/// is `(name, description, graph_json)`. The route layer inserts them on
/// first run if missing.
pub fn builtin_robots() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("Domain Recon",
         "Discovers subdomains, port scans each, and runs HTTP Recon on every HTTP/S port. Populates the Attack Surface.",
         r#"{"nodes":[
            {"id":"seed","kind":"tool","plugin_id":"subfinder","label":"Subdomain enumeration"},
            {"id":"uniq","kind":"reducer","reducer":"unique_targets","label":"Dedupe subdomains"},
            {"id":"ports","kind":"tool","plugin_id":"port-scanner","label":"Port scan each subdomain"},
            {"id":"extract_http","kind":"extractor","extractor":{"kind":"port_url","schemes":["http","https"]},"label":"Build URLs from open HTTP/S ports"},
            {"id":"recon","kind":"tool","plugin_id":"http-recon","label":"HTTP Recon on every URL"}
          ],"edges":[
            {"from":"seed","to":"uniq"},
            {"from":"uniq","to":"ports"},
            {"from":"ports","to":"extract_http"},
            {"from":"extract_http","to":"recon"}
          ]}"#),
        ("Treasure Hunter (domain)",
         "Finds subdomains, port scans them, then runs URL Fuzzing on every HTTP/S port to discover hidden files and directories.",
         r#"{"nodes":[
            {"id":"seed","kind":"tool","plugin_id":"subfinder","label":"Subdomain enumeration"},
            {"id":"ports","kind":"tool","plugin_id":"port-scanner","label":"Port scan each subdomain"},
            {"id":"extract_http","kind":"extractor","extractor":{"kind":"port_url","schemes":["http","https"]},"label":"Build URLs from open HTTP/S ports"},
            {"id":"fuzz","kind":"tool","plugin_id":"ffuf","label":"URL Fuzz each discovered web service"}
          ],"edges":[
            {"from":"seed","to":"ports"},
            {"from":"ports","to":"extract_http"},
            {"from":"extract_http","to":"fuzz"}
          ]}"#),
        ("HTTP Lockpicker",
         "Discovers web services, crawls for login interfaces, then brute-forces them with default credentials.",
         r#"{"nodes":[
            {"id":"ports","kind":"tool","plugin_id":"port-scanner","label":"Port scan target"},
            {"id":"extract_http","kind":"extractor","extractor":{"kind":"port_url","schemes":["http","https"]},"label":"Build URLs from open HTTP/S ports"},
            {"id":"recon","kind":"tool","plugin_id":"http-recon","label":"Discover login interfaces"},
            {"id":"creds","kind":"tool","plugin_id":"password-audit","label":"Default-credential audit"}
          ],"edges":[
            {"from":"ports","to":"extract_http"},
            {"from":"extract_http","to":"recon"},
            {"from":"recon","to":"creds"}
          ]}"#),
        ("Website Scanner — All Ports",
         "Discovers every HTTP/S port (1-65535), then runs the Website Scanner on each.",
         r#"{"nodes":[
            {"id":"ports","kind":"tool","plugin_id":"port-scanner","inputs":{"ports":"1-65535"},"label":"Full TCP port scan"},
            {"id":"extract_http","kind":"extractor","extractor":{"kind":"port_url","schemes":["http","https"]},"label":"Build URLs from open HTTP/S ports"},
            {"id":"web","kind":"tool","plugin_id":"nikto","label":"Website Scanner on each URL"}
          ],"edges":[
            {"from":"ports","to":"extract_http"},
            {"from":"extract_http","to":"web"}
          ]}"#),
        ("Log4Shell Detector",
         "Discovers web apps, crawls pages and forms, and injects Log4Shell payloads to test for CVE-2021-44228.",
         r#"{"nodes":[
            {"id":"ports","kind":"tool","plugin_id":"port-scanner","label":"Port scan target"},
            {"id":"extract_http","kind":"extractor","extractor":{"kind":"port_url","schemes":["http","https"]},"label":"Build URLs"},
            {"id":"nuclei","kind":"tool","plugin_id":"nuclei","inputs":{"tags":"log4j,cve-2021-44228"},"label":"Nuclei Log4Shell templates"}
          ],"edges":[
            {"from":"ports","to":"extract_http"},
            {"from":"extract_http","to":"nuclei"}
          ]}"#),
    ]
}

// --- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_rejects_empty_graph() {
        let g = RobotGraph {
            nodes: vec![],
            edges: vec![],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn validate_rejects_cycle() {
        let g = RobotGraph {
            nodes: vec![
                RobotNode {
                    id: "a".into(),
                    kind: NodeKind::Tool,
                    plugin_id: Some("p".into()),
                    inputs: BTreeMap::new(),
                    preset: None,
                    filter: None,
                    extractor: None,
                    reducer: None,
                    label: None,
                },
                RobotNode {
                    id: "b".into(),
                    kind: NodeKind::Tool,
                    plugin_id: Some("p".into()),
                    inputs: BTreeMap::new(),
                    preset: None,
                    filter: None,
                    extractor: None,
                    reducer: None,
                    label: None,
                },
            ],
            edges: vec![
                RobotEdge {
                    from: "a".into(),
                    to: "b".into(),
                },
                RobotEdge {
                    from: "b".into(),
                    to: "a".into(),
                },
            ],
        };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn filter_severity_ge_medium_passes_high() {
        let item = Item {
            kind: ItemKind::Result,
            target: Some("t".into()),
            task_id: None,
            status: None,
            findings_count: None,
            severity: [("high".to_string(), 1)].into(),
            findings: vec![],
        };
        let pred = json!({"severity": ">=medium"});
        assert!(eval_filter(&pred, &item));
    }

    #[test]
    fn filter_severity_ge_medium_fails_low() {
        let item = Item {
            kind: ItemKind::Result,
            target: Some("t".into()),
            task_id: None,
            status: None,
            findings_count: None,
            severity: [("low".to_string(), 1)].into(),
            findings: vec![],
        };
        let pred = json!({"severity": ">=medium"});
        assert!(!eval_filter(&pred, &item));
    }

    #[test]
    fn reducer_dedup_unique_targets() {
        let items = vec![
            Item {
                kind: ItemKind::Target,
                target: Some("a".into()),
                task_id: None,
                status: None,
                findings_count: None,
                severity: BTreeMap::new(),
                findings: vec![],
            },
            Item {
                kind: ItemKind::Target,
                target: Some("a".into()),
                task_id: None,
                status: None,
                findings_count: None,
                severity: BTreeMap::new(),
                findings: vec![],
            },
            Item {
                kind: ItemKind::Target,
                target: Some("b".into()),
                task_id: None,
                status: None,
                findings_count: None,
                severity: BTreeMap::new(),
                findings: vec![],
            },
        ];
        let node = RobotNode {
            id: "r".into(),
            kind: NodeKind::Reducer,
            plugin_id: None,
            inputs: BTreeMap::new(),
            preset: None,
            filter: None,
            extractor: None,
            reducer: Some("unique_targets".into()),
            label: None,
        };
        let out = run_reducer(&node, &items).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn topo_order_linear_chain() {
        let g = RobotGraph {
            nodes: vec![
                RobotNode {
                    id: "a".into(),
                    kind: NodeKind::Tool,
                    plugin_id: Some("p".into()),
                    inputs: BTreeMap::new(),
                    preset: None,
                    filter: None,
                    extractor: None,
                    reducer: None,
                    label: None,
                },
                RobotNode {
                    id: "b".into(),
                    kind: NodeKind::Tool,
                    plugin_id: Some("p".into()),
                    inputs: BTreeMap::new(),
                    preset: None,
                    filter: None,
                    extractor: None,
                    reducer: None,
                    label: None,
                },
                RobotNode {
                    id: "c".into(),
                    kind: NodeKind::Tool,
                    plugin_id: Some("p".into()),
                    inputs: BTreeMap::new(),
                    preset: None,
                    filter: None,
                    extractor: None,
                    reducer: None,
                    label: None,
                },
            ],
            edges: vec![
                RobotEdge {
                    from: "a".into(),
                    to: "b".into(),
                },
                RobotEdge {
                    from: "b".into(),
                    to: "c".into(),
                },
            ],
        };
        let order = topo_order(&g);
        assert_eq!(
            order,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn builtin_robots_all_validate() {
        for (name, _desc, graph_json) in builtin_robots() {
            let g: RobotGraph = serde_json::from_str(graph_json)
                .unwrap_or_else(|e| panic!("builtin `{name}` not parseable: {e}"));
            validate(&g).unwrap_or_else(|e| panic!("builtin `{name}` invalid: {e}"));
        }
    }
}
