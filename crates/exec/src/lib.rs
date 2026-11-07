//! SecuScan v2 — task executor.
//!
//! Runs plugin tasks:
//! - `cli` plugins through [`runner`] (tokio subprocess, no shell, timeout,
//!   cancellation, output caps, per-task temp working dir, scrubbed env),
//! - `native` plugins through in-process Rust scanners ([`native`]),
//!
//! Live [`events`] are streamed to the API layer, and per-plugin
//! concurrency/hourly limits are enforced by [`limiter`].

pub mod events;
pub mod limiter;
pub mod native;
pub mod runner;

pub use events::{EventEnvelope, EventSink, StreamKind, TaskEvent};
pub use limiter::{LimitVerdict, PluginLimiter};
pub use native::AuthMaterial;
pub use native::{NativeCtx, NativeScanner, OobCtx};
pub use runner::{run_cli, CliOutcome};

use secuscan_core::manifest::PluginManifest;
use secuscan_core::models::{now_iso, Finding, TaskStatus};
use std::collections::BTreeMap;

/// Install the process-wide rustls crypto provider (ring). Must be called
/// once before any TLS client is built; safe to call repeatedly.
pub fn init_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Result of executing one task.
#[derive(Debug)]
pub struct TaskOutcome {
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    /// Raw captured output (stdout + stderr interleaved), capped.
    pub output: String,
    pub output_truncated: bool,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    pub duration_ms: u128,
    /// Tool exited non-zero (surfaced as a warning, not a failure).
    pub tool_exit_nonzero: bool,
}

/// Execute a plugin task end-to-end (engine dispatch + parsing).
/// Inputs must already be normalized via [`secuscan_core::validate::normalize_inputs`].
/// `auth` carries resolved auth-profile material for native HTTP scanners
/// (None = unauthenticated).
pub async fn execute_task(
    manifest: &PluginManifest,
    inputs: &BTreeMap<String, serde_json::Value>,
    sink: &EventSink,
    cancel: tokio_util::sync::CancellationToken,
    auth: Option<AuthMaterial>,
    oob: Option<native::OobCtx>,
) -> TaskOutcome {
    let started = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(match &manifest.engine {
        secuscan_core::manifest::EngineSpec::Cli {
            timeout_seconds, ..
        } => *timeout_seconds,
        secuscan_core::manifest::EngineSpec::Native {
            timeout_seconds, ..
        } => *timeout_seconds,
    });

    sink.emit(TaskEvent::Phase(secuscan_core::models::Phase::Running))
        .await;

    let outcome = match &manifest.engine {
        secuscan_core::manifest::EngineSpec::Cli {
            ok_exit_codes, ..
        } => {
            let argv = match secuscan_core::template::build_argv(&manifest.engine, inputs) {
                Ok(a) => a,
                Err(e) => {
                    return failure(sink, format!("failed to render command: {e}"), started).await;
                }
            };
            let cli = run_cli(
                &argv,
                runner::RunOpts {
                    timeout,
                    cancel: cancel.clone(),
                    // Issue #11 — the plugin contract documents which
                    // non-zero codes mean "not an error" (e.g. testssl.sh
                    // exits 1/2 when vulnerabilities are found). Everything
                    // else is a tool failure and must not report Completed.
                    ok_exit_codes: ok_exit_codes.clone(),
                    ..Default::default()
                },
                sink,
            )
            .await;
            sink.emit(TaskEvent::Phase(secuscan_core::models::Phase::Parsing))
                .await;
            let findings = match secuscan_core::parser_engine::parse_output(
                &manifest.parser,
                &manifest.static_rules,
                &cli.output,
            ) {
                Ok(f) => f,
                Err(e) => {
                    return failure(sink, format!("parser error: {e}"), started).await;
                }
            };
            complete(cli, findings, manifest, sink).await
        }
        secuscan_core::manifest::EngineSpec::Native { native, .. } => {
            let scanner = match native::registry().lookup(native) {
                Some(s) => s,
                None => {
                    return failure(sink, format!("unknown native scanner `{native}`"), started)
                        .await;
                }
            };
            let ctx = NativeCtx {
                sink: sink.clone(),
                cancel: cancel.clone(),
                timeout,
                auth,
                oob,
            };
            match tokio::time::timeout(timeout, scanner.run(inputs, &ctx)).await {
                Err(_) => {
                    failure(
                        sink,
                        format!("timed out after {}s", timeout.as_secs()),
                        started,
                    )
                    .await
                }
                Ok(Err(e)) => failure(sink, e, started).await,
                Ok(Ok(findings)) => {
                    sink.emit(TaskEvent::Info(format!(
                        "native scanner `{native}` produced {} finding(s)",
                        findings.len()
                    )))
                    .await;
                    TaskOutcome {
                        status: TaskStatus::Completed,
                        exit_code: Some(0),
                        output: String::new(),
                        output_truncated: false,
                        findings,
                        error: None,
                        duration_ms: started.elapsed().as_millis(),
                        tool_exit_nonzero: false,
                    }
                }
            }
        }
    };

    sink.emit(TaskEvent::Phase(secuscan_core::models::Phase::Reporting))
        .await;
    let status = outcome.status;
    let exit_code = outcome.exit_code;
    sink.emit(TaskEvent::Finished { status, exit_code }).await;
    outcome
}

async fn complete(
    cli: runner::CliOutcome,
    findings: Vec<Finding>,
    manifest: &PluginManifest,
    sink: &EventSink,
) -> TaskOutcome {
    let tool_exit_nonzero = cli.exit_code.map(|c| c != 0).unwrap_or(false);
    if tool_exit_nonzero {
        sink.emit(TaskEvent::Warn(format!(
            "tool exited with code {} — output was still parsed for findings",
            cli.exit_code.unwrap_or(-1)
        )))
        .await;
    }
    let _ = manifest;
    TaskOutcome {
        status: cli.status,
        exit_code: cli.exit_code,
        findings,
        error: cli.error,
        output: cli.output,
        output_truncated: cli.truncated,
        duration_ms: 0, // replaced by caller
        tool_exit_nonzero,
    }
}

async fn failure(sink: &EventSink, message: String, started: std::time::Instant) -> TaskOutcome {
    sink.emit(TaskEvent::Error(message.clone())).await;
    TaskOutcome {
        status: TaskStatus::Failed,
        exit_code: None,
        output: String::new(),
        output_truncated: false,
        findings: Vec::new(),
        error: Some(message),
        duration_ms: started.elapsed().as_millis(),
        tool_exit_nonzero: false,
    }
}

/// Ensure the outcome carries the real elapsed duration.
pub fn with_duration(mut o: TaskOutcome, started: std::time::Instant) -> TaskOutcome {
    o.duration_ms = started.elapsed().as_millis();
    o
}

/// Helper for API/CLI layers: spawn a task recorder that persists events and
/// fans them out to a broadcast channel.
pub fn now() -> String {
    now_iso()
}
