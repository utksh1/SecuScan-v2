//! SecuScan v2 CLI.
//!
//! Subcommands:
//! - `scan`    — run a plugin locally (no server needed): normalized input
//!   validation, safe argv execution, findings printed as a table plus an
//!   optional Markdown report.
//! - `plugins` — list / validate plugin manifests.
//! - `serve`   — start the API server (delegates to the api crate).
//! - `export-openapi` — print the OpenAPI 3.1 spec served by
//!   `GET /api/v1/openapi.json` to stdout (SDK generation pipelines;
//!   pipe into a file or an OpenAPI generator).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use secuscan_core::manifest::EngineSpec;
use secuscan_core::models::Finding;
use secuscan_core::validate::normalize_inputs;
use secuscan_core::PluginRegistry;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "secuscan",
    version,
    about = "SecuScan v2 — authorized security scanning workspace",
    long_about = "SecuScan v2 — an open-source, local-first security scanning workspace.\nUse only against systems you own or are explicitly authorized to assess."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a plugin locally and print findings.
    Scan {
        /// Plugin id (see `secuscan plugins list`).
        #[arg(long)]
        plugin: String,
        /// Input as `key=value` (repeatable), e.g. --input target=127.0.0.1
        #[arg(long = "input", value_name = "KEY=VALUE")]
        inputs: Vec<String>,
        /// Named preset from the plugin manifest.
        #[arg(long)]
        preset: Option<String>,
        /// Write a Markdown report to this path.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Confirm you are authorized to scan the target.
        #[arg(long)]
        consent: bool,
        /// Plugins directory (default: ./plugins).
        #[arg(long, default_value = "./plugins")]
        plugins_dir: PathBuf,
    },
    /// Plugin manifest utilities.
    Plugins {
        #[command(subcommand)]
        command: PluginsCommands,
    },
    /// Start the API server.
    Serve,
    /// Run against a remote SecuScan server (CI mode)
    Remote {
        /// Base URL, e.g. https://secuscan.example.com
        #[arg(long)]
        server_url: String,
        /// API key (X-API-Key) — prefer passing via SECUSCAN_API_KEY env
        #[arg(long)]
        api_key: Option<String>,
        /// Plugin id to run
        #[arg(long)]
        plugin: String,
        /// key=value inputs (repeatable)
        #[arg(long = "input")]
        inputs: Vec<String>,
        /// Fail (exit 2) if a finding at/above this severity is reported
        #[arg(long)]
        fail: Option<String>,
        /// Emit machine-readable JSON instead of prose
        #[arg(long)]
        json: bool,
        /// Seconds to wait for completion (default 600)
        #[arg(long, default_value_t = 600)]
        timeout_seconds: u64,
    },
    /// Print the OpenAPI 3.1 spec (same artifact as GET /api/v1/openapi.json).
    ExportOpenapi {
        /// Write to this file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// The OpenAPI spec committed at `docs/openapi.json` — the same bytes the
/// server embeds, so CLI export and HTTP endpoint can never drift.
const OPENAPI_SPEC_JSON: &str = include_str!("../../../docs/openapi.json");

#[derive(Subcommand)]
enum PluginsCommands {
    /// List installed plugin manifests.
    List {
        #[arg(long, default_value = "./plugins")]
        plugins_dir: PathBuf,
    },
    /// Validate one manifest file or a whole directory.
    Validate { path: PathBuf },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secuscan=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let exit = match cli.command {
        Commands::Scan {
            plugin,
            inputs,
            preset,
            output,
            consent,
            plugins_dir,
        } => run_scan(plugin, inputs, preset, output, consent, plugins_dir),
        Commands::Remote {
            server_url,
            api_key,
            plugin,
            inputs,
            fail,
            json,
            timeout_seconds,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            let code = rt.block_on(run_remote(
                server_url,
                api_key,
                plugin,
                inputs,
                fail.as_deref(),
                json,
                timeout_seconds,
            ));
            // The severity gate (and launch/poll failures) must fail CI.
            // `exit` never returns — the `!` coerces to the match's type.
            std::process::exit(code)
        }
        Commands::Plugins { command } => match command {
            PluginsCommands::List { plugins_dir } => {
                list_plugins(&plugins_dir);
                Ok(())
            }
            PluginsCommands::Validate { path } => validate_manifests(&path),
        },
        Commands::Serve => serve(),
        Commands::ExportOpenapi { output } => export_openapi(output),
    };
    exit
}

fn export_openapi(output: Option<PathBuf>) -> Result<()> {
    // Validate that the embedded artifact is well-formed JSON before emitting.
    let spec: serde_json::Value = serde_json::from_str(OPENAPI_SPEC_JSON)
        .context("embedded docs/openapi.json is not valid JSON")?;
    let pretty = serde_json::to_string_pretty(&spec).context("cannot serialize spec")?;
    match output {
        Some(path) => {
            std::fs::write(&path, pretty + "\n")
                .with_context(|| format!("cannot write {}", path.display()))?;
            eprintln!("OpenAPI spec written to {}", path.display());
        }
        None => println!("{pretty}"),
    }
    Ok(())
}

fn parse_inputs(pairs: &[String]) -> Result<BTreeMap<String, serde_json::Value>> {
    let mut map = BTreeMap::new();
    for pair in pairs {
        let (k, v) = pair
            .split_once('=')
            .with_context(|| format!("--input must be KEY=VALUE, got `{pair}`"))?;
        // Accept booleans and integers natively, everything else as string.
        let value = if v == "true" || v == "false" {
            serde_json::json!(v == "true")
        } else if let Ok(i) = v.parse::<i64>() {
            serde_json::json!(i)
        } else {
            serde_json::json!(v)
        };
        map.insert(k.to_string(), value);
    }
    Ok(map)
}

fn run_scan(
    plugin_id: String,
    raw_inputs: Vec<String>,
    preset: Option<String>,
    output: Option<PathBuf>,
    consent: bool,
    plugins_dir: PathBuf,
) -> Result<()> {
    let registry = PluginRegistry::load_dir(&plugins_dir);
    for issue in registry.issues() {
        eprintln!("! plugin issue [{}]: {}", issue.file, issue.error);
    }
    let manifest = registry
        .get(&plugin_id)
        .with_context(|| {
            format!(
                "plugin `{plugin_id}` not found in {}",
                plugins_dir.display()
            )
        })?
        .clone();

    if !manifest.available {
        anyhow::bail!(
            "plugin `{}` is unavailable; missing binaries: {}",
            plugin_id,
            manifest.missing_binaries.join(", ")
        );
    }
    if manifest.safety.requires_consent && !consent {
        anyhow::bail!(
            "plugin `{}` requires consent: re-run with --consent after confirming you are \
             authorized to scan the target\n  {}",
            plugin_id,
            manifest
                .safety
                .consent_message
                .as_deref()
                .unwrap_or("Only scan systems you own or are explicitly permitted to assess.")
        );
    }

    let mut inputs = parse_inputs(&raw_inputs)?;
    if let Some(preset_name) = &preset {
        let preset_values = manifest
            .presets
            .get(preset_name)
            .with_context(|| format!("unknown preset `{preset_name}`"))?;
        for (k, v) in preset_values {
            inputs.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    let inputs = normalize_inputs(&manifest, &inputs)
        .map_err(|e| anyhow::anyhow!("input validation failed: {e}"))?;

    // Target policy (plugin-level).
    let target = inputs
        .get("target")
        .or_else(|| inputs.get("url"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let verdict = secuscan_core::policy::evaluate_target(
        target.as_deref(),
        &manifest.safety.allowed_targets,
        &secuscan_core::policy::NetworkPolicy::default(),
    );
    if let secuscan_core::policy::TargetVerdict::Denied { reason, .. } = verdict {
        anyhow::bail!("target rejected: {reason}");
    }

    println!(
        "▶ running `{}` ({} v{}) against `{}`",
        manifest.plugin.name,
        manifest.plugin.id,
        manifest.plugin.version,
        target.as_deref().unwrap_or("—")
    );

    let plugin_name = manifest.plugin.name.clone();
    let started = std::time::Instant::now();
    let rt = tokio::runtime::Runtime::new()?;
    let outcome = rt.block_on(async {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<secuscan_exec::EventEnvelope>(1024);
        let sink = secuscan_exec::EventSink::new(uuid_v4(), tx.clone());
        let printer = tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                if let secuscan_exec::TaskEvent::LogLine { line, .. } = env.event {
                    println!("  | {line}");
                }
            }
        });
        let cancel = tokio_util::sync::CancellationToken::new();
        // CLI runs locally without the API's auth-profile store: always
        // unauthenticated (Max-Parity Sprint 1.1), and without the API's
        // OOB receiver context: blind-callback tooling stays disabled
        // (Max-Parity Sprint 1.2).
        let result =
            secuscan_exec::execute_task(&manifest, &inputs, &sink, cancel, None, None, None).await;
        // Drop the sender BEFORE awaiting the reader, otherwise the printer
        // waits forever for the channel to close (classic deadlock).
        drop(sink);
        drop(tx);
        let _ = printer.await;
        result
    });

    println!("\n──────────────────────────────────────────────");
    println!(
        "status: {:?}  ·  findings: {}  ·  {:.1?}",
        outcome.status,
        outcome.findings.len(),
        started.elapsed()
    );
    if let Some(err) = &outcome.error {
        println!("error:  {err}");
    }
    print_findings(&outcome.findings);

    if let Some(path) = output {
        let md = markdown_report(&plugin_name, &outcome.findings);
        std::fs::write(&path, md).with_context(|| format!("writing {}", path.display()))?;
        println!("\nreport written to {}", path.display());
    }
    if outcome.status == secuscan_core::models::TaskStatus::Failed {
        std::process::exit(2);
    }
    Ok(())
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("\nno findings.");
        return;
    }
    println!("\n{:<9} {:<60} CATEGORY", "SEVERITY", "TITLE");
    println!("{}", "-".repeat(100));
    for f in findings {
        println!(
            "{:<9} {:<60} {}",
            f.severity,
            truncate(&f.title, 60),
            f.category
        );
    }
    println!("\n(details in the generated report or via `secuscan-server`)");
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max - 1).collect();
        format!("{t}…")
    }
}

fn markdown_report(plugin_name: &str, findings: &[Finding]) -> String {
    let mut md = format!(
        "# SecuScan CLI Report — {plugin_name}\n\n## Findings ({})\n\n",
        findings.len()
    );
    md.push_str("| Severity | Title | Category | Kind |\n|---|---|---|---|\n");
    for f in findings {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            f.severity,
            f.title.replace('|', "\\|"),
            f.category.replace('|', "\\|"),
            f.kind
        ));
    }
    md.push_str("\n## Details\n\n");
    for (i, f) in findings.iter().enumerate() {
        md.push_str(&format!("### {}. [{}] {}\n\n", i + 1, f.severity, f.title));
        if !f.description.is_empty() {
            md.push_str(&format!("{}\n\n", f.description));
        }
        if !f.proof.is_empty() {
            md.push_str(&format!(
                "**Evidence:** `{}`\n\n",
                f.proof.replace('\n', " ")
            ));
        }
        if !f.remediation.is_empty() {
            md.push_str(&format!("**Remediation:** {}\n\n", f.remediation));
        }
    }
    md.push_str(
        "\n> Generated by SecuScan v2 CLI. Automated findings require manual validation.\n",
    );
    md
}

fn uuid_v4() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

fn list_plugins(plugins_dir: &std::path::Path) {
    let registry = PluginRegistry::load_dir(plugins_dir);
    for issue in registry.issues() {
        eprintln!("! plugin issue [{}]: {}", issue.file, issue.error);
    }
    println!(
        "{:<24} {:<28} {:<10} {:<9} SAFETY",
        "ID", "NAME", "CATEGORY", "AVAILABLE"
    );
    println!("{}", "-".repeat(100));
    for p in registry.all() {
        println!(
            "{:<24} {:<28} {:<10} {:<9} {}",
            p.plugin.id,
            truncate(&p.plugin.name, 28),
            p.plugin.category,
            if p.available { "yes" } else { "no" },
            p.safety.level.label(),
        );
    }
    println!(
        "\n{} plugin(s), {} available",
        registry.len(),
        registry.all().iter().filter(|p| p.available).count()
    );
}

fn validate_manifests(path: &std::path::Path) -> Result<()> {
    let files: Vec<PathBuf> = if path.is_dir() {
        let mut v: Vec<PathBuf> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .collect();
        v.sort();
        v
    } else {
        vec![path.to_path_buf()]
    };
    if files.is_empty() {
        anyhow::bail!("no .toml manifests found at {}", path.display());
    }
    let mut failures = 0;
    for file in files {
        let raw = std::fs::read_to_string(&file)?;
        match toml::from_str::<secuscan_core::manifest::PluginManifest>(&raw) {
            Ok(m) => {
                let errs = secuscan_core::validate::validate_manifest(&m);
                if errs.is_empty() {
                    let mut m = m;
                    let missing = {
                        let mut names = m.dependencies.binaries.clone();
                        if let EngineSpec::Cli { binary, .. } = &m.engine {
                            names.push(binary.clone());
                        }
                        names.retain(|b| !b.is_empty());
                        names.sort();
                        names.dedup();
                        names
                            .into_iter()
                            .filter(|b| !secuscan_core::loader::binary_available(b))
                            .collect::<Vec<_>>()
                    };
                    m.available = missing.is_empty();
                    m.missing_binaries = missing;
                    println!(
                        "✓ {}  ({}, {} field(s))",
                        file.display(),
                        m.plugin.id,
                        m.fields.len()
                    );
                } else {
                    failures += 1;
                    println!("✗ {}", file.display());
                    for e in errs {
                        println!("    - {e}");
                    }
                }
            }
            Err(e) => {
                failures += 1;
                println!("✗ {}  (TOML/structure error)\n    - {e}", file.display());
            }
        }
    }
    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn serve() -> Result<()> {
    // Delegate to the api server binary.
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("no parent dir")?;
    let server = dir.join("secuscan-server");
    if server.exists() {
        let err = std::process::Command::new(&server)
            .status()
            .context("failed to run secuscan-server")?;
        std::process::exit(err.code().unwrap_or(1));
    }
    anyhow::bail!(
        "secuscan-server binary not found next to `{}`.\nBuild it with: cargo build --workspace",
        exe.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_parsing() {
        let m = parse_inputs(&[
            "target=127.0.0.1".to_string(),
            "verbose=true".to_string(),
            "count=5".to_string(),
            "note=hello world".to_string(),
        ])
        .unwrap();
        assert_eq!(m.get("target").unwrap(), &serde_json::json!("127.0.0.1"));
        assert_eq!(m.get("verbose").unwrap(), &serde_json::json!(true));
        assert_eq!(m.get("count").unwrap(), &serde_json::json!(5));
        assert_eq!(m.get("note").unwrap(), &serde_json::json!("hello world"));
    }

    #[test]
    fn bad_input_rejected() {
        assert!(parse_inputs(&["nokeyvalue".to_string()]).is_err());
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate("short", 10), "short");
        let long = "x".repeat(50);
        let t = truncate(&long, 20);
        assert_eq!(t.chars().count(), 20);
    }
}


/// Remote scan mode (Sprint 4, issue #34): drives a SecuScan server's REST
/// API from CI — launch, poll to completion, apply a severity gate.
async fn run_remote(
    server_url: String,
    api_key: Option<String>,
    plugin: String,
    inputs: Vec<String>,
    fail_sev: Option<&str>,
    json: bool,
    timeout_seconds: u64,
) -> i32 {
    let key = api_key
        .or_else(|| std::env::var("SECUSCAN_API_KEY").ok())
        .unwrap_or_default();
    let base = server_url.trim_end_matches('/');
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("client build failed: {e}");
            return 2;
        }
    };
    let mut kv = std::collections::BTreeMap::new();
    for i in &inputs {
        if let Some((k, v)) = i.split_once('=') {
            kv.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    let body = serde_json::json!({
        "plugin_id": plugin,
        "inputs": kv,
        "consent_granted": true,
    });

    let mut req = client
        .post(format!("{base}/api/v1/tasks"))
        .header("content-type", "application/json")
        .json(&body);
    if !key.is_empty() {
        req = req.header("x-api-key", &key);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("launch failed: {e}");
            return 2;
        }
    };
    if resp.status() != 201 {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eprintln!("launch rejected ({status}): {body}");
        return 2;
    }
    let task: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let task_id = task["id"].as_str().unwrap_or("").to_string();
    if json {
        println!(r#"{{ "task_id": "{}" }}"#, task_id);
    } else {
        println!("launched task {task_id}");
    }

    // Poll to terminal state.
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_seconds);
    let mut status = String::new();
    loop {
        if std::time::Instant::now() >= deadline {
            eprintln!("timeout waiting for task {task_id}");
            return 2;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut req = client.get(format!("{base}/api/v1/tasks/{task_id}"));
        if !key.is_empty() {
            req = req.header("x-api-key", &key);
        }
        let t = match req.send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let v: serde_json::Value = match t.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        status = v["status"].as_str().unwrap_or("").to_string();
        if ["completed", "failed", "cancelled"].contains(&status.as_str()) {
            break;
        }
    }

    // Fetch findings (final gate input).
    let mut req = client.get(format!("{base}/api/v1/findings?task_id={task_id}&limit=1000"));
    if !key.is_empty() {
        req = req.header("x-api-key", &key);
    }
    let findings: serde_json::Value = match req.send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };
    let items = findings["items"].as_array().cloned().unwrap_or_default();

    let rank = |s: &str| match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "task_id": task_id,
                "status": status,
                "findings": items,
            }))
            .unwrap_or_default()
        );
    } else {
        for f in &items {
            println!(
                "[{}] {} ({})",
                f["severity"].as_str().unwrap_or("?"),
                f["title"].as_str().unwrap_or("?"),
                f["plugin_id"].as_str().unwrap_or("?")
            );
        }
        println!("task {task_id}: {status}, {} finding(s)", items.len());
    }

    // Severity gate: exit 2 when a finding at/above the threshold exists.
    if let Some(threshold) = fail_sev {
        let want = rank(threshold);
        let hit = items
            .iter()
            .any(|f| rank(f["severity"].as_str().unwrap_or("info")) >= want && want > 0);
        if hit {
            eprintln!("CI gate: findings at or above `{threshold}` present");
            return 2;
        }
    }
    if status != "completed" {
        return 2;
    }
    0
}
