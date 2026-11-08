//! Hardened subprocess runner.
//!
//! Guarantees per execution:
//! - **no shell** — argv vector only;
//! - **scrubbed environment** — only `PATH`, `HOME`, `LANG`, `TMPDIR` are
//!   passed through, so platform secrets never leak into tools;
//! - **per-task temp working directory** — created and removed by the runner;
//! - **wall-clock timeout** — child killed on expiry;
//! - **cancellation** — child killed when the token fires;
//! - **output caps** — buffering stops at `max_output_bytes` while the pipe
//!   keeps draining (a tool spamming stdout cannot exhaust memory).

use crate::events::{EventSink, StreamKind, TaskEvent};
use secuscan_core::models::TaskStatus;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

/// Default output capture cap (8 MiB, parity with the v1 sandbox).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RunOpts {
    pub timeout: Duration,
    pub cancel: CancellationToken,
    pub max_output_bytes: usize,
    /// Extra env vars to inject (used by tests; kept minimal by design).
    pub env: Vec<(String, String)>,
    /// Non-zero exit codes the tool's contract documents as non-error
    /// (issue #11). Empty by default: any non-zero exit is a failure.
    pub ok_exit_codes: Vec<i32>,
    /// Reporting-friendly soft cap (issue #25): when `soft_timeout` fires
    /// before `timeout`, the run ends **Completed** with partial output
    /// (parsed for findings) and `CliOutcome::timeout_fired` set — the
    /// user-set `max_scan_time` semantics. None = no soft cap.
    pub soft_timeout: Option<Duration>,
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts {
            timeout: Duration::from_secs(300),
            cancel: CancellationToken::new(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            env: Vec::new(),
            ok_exit_codes: Vec::new(),
            soft_timeout: None,
        }
    }
}

#[derive(Debug)]
pub struct CliOutcome {
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub output: String,
    pub truncated: bool,
    pub error: Option<String>,
    /// Set when the soft timeout (`max_scan_time`) terminated the run —
    /// the caller maps it to a reporting-friendly Completed-with-partials.
    pub timeout_fired: bool,
}

/// Run a command and stream its output as events.
pub async fn run_cli(argv: &[String], opts: RunOpts, sink: &EventSink) -> CliOutcome {
    if argv.is_empty() {
        return CliOutcome {
            status: TaskStatus::Failed,
            exit_code: None,
            output: String::new(),
            truncated: false,
            error: Some("empty argv".into()),
            timeout_fired: false,
        };
    }

    let workdir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return CliOutcome {
                status: TaskStatus::Failed,
                exit_code: None,
                output: String::new(),
                truncated: false,
                error: Some(format!("cannot create task working dir: {e}")),
                timeout_fired: false,
            }
        }
    };

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&workdir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env(
            "LANG",
            std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".into()),
        )
        .env(
            "TMPDIR",
            std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()),
        )
        .env("SECUSCAN_TASK", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Issue #9 (Max-Parity) — put the child in its own process group so
    // cancellation/timeout can terminate the whole tree (tools like nmap
    // and sqlmap spawn children of their own) instead of orphaning it.
    #[cfg(unix)]
    cmd.as_std_mut().process_group(0);
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }

    sink.emit(TaskEvent::Info(format!("$ {}", argv.join(" "))))
        .await;

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return CliOutcome {
                status: TaskStatus::Failed,
                exit_code: None,
                output: String::new(),
                truncated: false,
                error: Some(format!(
                    "failed to spawn `{}`: {e} (is the tool installed and on PATH?)",
                    argv[0]
                )),
                timeout_fired: false,
            }
        }
    };

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    // Reader tasks: forward lines as events, accumulate into capped buffers.
    // They run as spawned tasks so the wait/timeout/cancel loop below is
    // never blocked by an unfinished process.
    let buf_out = SharedBuffer::new(opts.max_output_bytes);
    let buf_err = SharedBuffer::new(opts.max_output_bytes);
    let pump_out = tokio::spawn(pump(
        stdout,
        StreamKind::Stdout,
        sink.clone(),
        buf_out.clone(),
    ));
    let pump_err = tokio::spawn(pump(
        stderr,
        StreamKind::Stderr,
        sink.clone(),
        buf_err.clone(),
    ));

    // Wait for exit, timeout, or cancellation. Both interrupt paths
    // terminate the whole process group (issue #9), not just the direct
    // child — grandchildren must not survive the scan.
    let wait_result = tokio::select! {
        _ = opts.cancel.cancelled() => {
            terminate_tree(&mut child).await;
            WaitResult::Cancelled
        }
        _ = async {
            match opts.soft_timeout {
                Some(soft) => tokio::time::sleep(soft).await,
                None => std::future::pending().await,
            }
        } => {
            terminate_tree(&mut child).await;
            WaitResult::SoftTimeout
        }
        _ = tokio::time::sleep(opts.timeout) => {
            terminate_tree(&mut child).await;
            WaitResult::Timeout
        }
        status = child.wait() => {
            match status {
                // Preserve None for signal deaths (issue #11): the old
                // `or_else(|| Some(-1))` mapping meant the signal-detection
                // arm below could never fire and signal-killed tools were
                // reported as Completed with exit code -1.
                Ok(s) => WaitResult::Exited(s.code()),
                Err(e) => WaitResult::SpawnErr(e),
            }
        }
    };

    // Pipes are closed now; drain any remaining buffered lines (bounded so a
    // pathological pump can never hang the runner).
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = pump_out.await;
        let _ = pump_err.await;
    })
    .await;

    // The pumps finished with the process; collect captured output.
    let mut output = buf_out.take();
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(&buf_err.take());
    let truncated = buf_out.was_truncated() || buf_err.was_truncated();

    match wait_result {
        WaitResult::Exited(code) => {
            // A child killed by a signal (code None, not success) crashed.
            if code.is_none() {
                return CliOutcome {
                    status: TaskStatus::Failed,
                    exit_code: Some(-1),
                    output,
                    truncated,
                    error: Some("process terminated by a signal (crash or OOM kill)".into()),
                    timeout_fired: false,
                };
            }
            let code = code.expect("checked above");
            // Issue #11 — honesty about tool failures: a non-zero exit is a
            // failure unless the plugin contract documents that specific
            // code as non-error (e.g. testssl.sh exits 1/2 when it finds
            // vulnerabilities). Output and partial findings are preserved
            // either way; only the classification changes.
            if code != 0 && !opts.ok_exit_codes.contains(&code) {
                return CliOutcome {
                    status: TaskStatus::Failed,
                    exit_code: Some(code),
                    output,
                    truncated,
                    error: Some(format!(
                        "scanner exited non-zero ({code}) — tool failure; captured findings may be partial"
                    )),
                    timeout_fired: false,
                };
            }
            CliOutcome {
                status: TaskStatus::Completed,
                exit_code: Some(code),
                output,
                truncated,
                error: None,
                timeout_fired: false,
            }
        }
        WaitResult::Timeout => CliOutcome {
            status: TaskStatus::Failed,
            exit_code: None,
            output,
            truncated,
            error: Some(format!(
                "timed out after {}s and the process was killed",
                opts.timeout.as_secs().max(1)
            )),
            timeout_fired: false,
        },
        WaitResult::SoftTimeout => CliOutcome {
            status: TaskStatus::Completed,
            exit_code: Some(0),
            output,
            truncated,
            error: None,
            timeout_fired: true,
        },
        WaitResult::Cancelled => CliOutcome {
            status: TaskStatus::Cancelled,
            exit_code: None,
            output,
            truncated,
            error: None,
            timeout_fired: false,
        },
        WaitResult::SpawnErr(e) => CliOutcome {
            status: TaskStatus::Failed,
            exit_code: None,
            output,
            truncated,
            error: Some(format!("wait failed: {e}")),
            timeout_fired: false,
        },
    }
}

enum WaitResult {
    Exited(Option<i32>),
    Timeout,
    SoftTimeout,
    Cancelled,
    SpawnErr(std::io::Error),
}

/// Grace window a group gets to exit on SIGTERM before SIGKILL. Short enough
/// to keep cancel/timeout latency bounded, long enough for tools to flush
/// their output buffers.
const TERM_GRACE: Duration = Duration::from_millis(2_000);

/// Terminate the child **and its whole process group** (issue #9).
///
/// The child is spawned in its own group (`process_group(0)` on unix), so
/// tools that spawn their own children (nmap scripts, sqlmap, hydra workers)
/// are all covered. Sequence: SIGTERM to the group → grace window → SIGKILL
/// to the group → reap the direct child. Every step is best-effort; the
/// final `wait()` is what prevents zombies.
///
/// Platforms: full group semantics on unix. On Windows there is no portable
/// process-group kill from Rust std; the direct child is killed (`kill_on_drop`
/// also stays armed) — document this in DEPLOYMENT.md.
async fn terminate_tree(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    {
        // tokio's Child::id() returns None once the child has exited; the
        // group id equals the child's pid by construction (process_group(0)).
        if let Some(pid) = child.id() {
            let negpid = -(pid as i32);
            // Graceful: let the group flush output and shut down.
            let _ = unsafe { libc::kill(negpid, libc::SIGTERM) };
            let deadline = tokio::time::Instant::now() + TERM_GRACE;
            while tokio::time::Instant::now() < deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return; // exited during grace window; already reaped
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            // Hard kill the group, then the child itself (belt & braces if
            // it somehow escaped the group).
            let _ = unsafe { libc::kill(negpid, libc::SIGKILL) };
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await; // reap — no zombies
}

/// Fixed-size read chunk for output pumps (issue #10): never allocate more
/// than this per read, regardless of what the tool emits.
const READ_CHUNK: usize = 8 * 1024;
/// Per-record cap: a single line longer than this is truncated at the head
/// and its remainder is skipped instead of accumulating.
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Per-stream event quota: beyond this many LogLine events the pump keeps
/// draining and buffering (up to the buffer cap) but stops emitting events,
/// so a chatty tool cannot flood the SSE bus / DB event log.
const MAX_LOG_EVENTS: usize = 20_000;

/// Drain one output stream with **bounded allocation** (issue #10).
///
/// The previous implementation used `BufReader::lines()` whose internal
/// buffer grows unboundedly for a line without newlines — a pathological
/// tool emitting one giant line could exhaust server memory before any cap
/// applied (and invalid UTF-8 aborted the pump entirely). This reader:
///   * reads fixed chunks and splits lines itself,
///   * truncates single lines at `MAX_LINE_BYTES` (head kept, remainder
///     skipped, marker appended),
///   * lossy-decodes so binary output cannot kill the pump,
///   * caps emitted events while still buffering (bounded) for parsers.
async fn pump<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    stream: StreamKind,
    sink: EventSink,
    buf: SharedBuffer,
) {
    use tokio::io::AsyncReadExt;
    let mut reader = reader;
    let mut pending: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let mut skipping_oversize = false;
    let mut events_emitted = 0usize;
    let mut chunk = vec![0u8; READ_CHUNK];

    'read: loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
        // Split out every complete line currently buffered.
        loop {
            match pending.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    let line: Vec<u8> = pending.drain(..=pos).collect();
                    if skipping_oversize {
                        // Tail of an already-reported oversize line.
                        skipping_oversize = false;
                        continue;
                    }
                    emit_line(&sink, &buf, stream, &mut events_emitted, &line[..pos], false)
                        .await;
                }
                None => {
                    if pending.len() > MAX_LINE_BYTES {
                        if !skipping_oversize {
                            skipping_oversize = true;
                            emit_line(
                                &sink,
                                &buf,
                                stream,
                                &mut events_emitted,
                                &pending[..MAX_LINE_BYTES],
                                true,
                            )
                            .await;
                        }
                        pending.clear();
                    }
                    continue 'read;
                }
            }
        }
    }

    // EOF with a final unterminated line (common: tools that omit the last
    // newline). Emit it unless it is the remainder of an oversize line.
    if !pending.is_empty() && !skipping_oversize {
        emit_line(&sink, &buf, stream, &mut events_emitted, &pending, false).await;
    }
}

/// Bounded single-line handler: lossy UTF-8 (binary cannot kill the pump),
/// truncation metadata, event quota, capped buffering.
async fn emit_line(
    sink: &EventSink,
    buf: &SharedBuffer,
    stream: StreamKind,
    events_emitted: &mut usize,
    line: &[u8],
    oversize_head: bool,
) {
    let mut text = String::from_utf8_lossy(line).into_owned();
    if oversize_head {
        text.push_str("…[secuscan: line truncated]");
    }
    let keep = !buf.was_truncated();
    if keep {
        buf.push_line(&text);
    }
    if *events_emitted < MAX_LOG_EVENTS {
        *events_emitted += 1;
        sink.emit(TaskEvent::LogLine {
            stream,
            line: text.chars().take(2000).collect(),
        })
        .await;
    }
}

/// Append-only capped output buffer shared with the reader task.
#[derive(Clone)]
struct SharedBuffer {
    inner: std::sync::Arc<std::sync::Mutex<BufferState>>,
}

struct BufferState {
    data: String,
    cap: usize,
    truncated: bool,
}

impl SharedBuffer {
    fn new(cap: usize) -> Self {
        SharedBuffer {
            inner: std::sync::Arc::new(std::sync::Mutex::new(BufferState {
                data: String::new(),
                cap,
                truncated: false,
            })),
        }
    }

    fn push_line(&self, line: &str) {
        let mut st = self.inner.lock().expect("buffer lock");
        if st.truncated {
            return;
        }
        let add = line.len() + 1;
        if st.data.len() + add > st.cap {
            st.truncated = true;
            // Leave a visible marker in the retained output so downstream
            // consumers (reports, parsers' users) see the cut honestly.
            // Deliberately not finding-shaped: no parser matches it.
            let marker = "\n[secuscan: output truncated]";
            if st.data.len() + marker.len() <= st.cap + marker.len() {
                st.data.push_str(marker);
            }
            return;
        }
        st.data.push_str(line);
        st.data.push('\n');
    }

    fn take(&self) -> String {
        let mut st = self.inner.lock().expect("buffer lock");
        std::mem::take(&mut st.data)
    }

    fn was_truncated(&self) -> bool {
        self.inner.lock().expect("buffer lock").truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventEnvelope;
    use tokio::sync::mpsc;

    fn sink() -> (EventSink, mpsc::Receiver<EventEnvelope>) {
        let (tx, rx) = mpsc::channel(1024);
        (EventSink::new(uuid::Uuid::new_v4(), tx), rx)
    }

    fn argv(program: &str, args: &[&str]) -> Vec<String> {
        std::iter::once(program.to_string())
            .chain(args.iter().map(|s| s.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn captures_output_and_exit_code() {
        let (s, mut rx) = sink();
        let out = run_cli(
            &argv("sh", &["-c", "echo out-line; echo err-line 1>&2; exit 0"]),
            RunOpts::default(),
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Completed);
        assert_eq!(out.exit_code, Some(0));
        assert!(out.output.contains("out-line"));
        assert!(out.output.contains("err-line"));
        let mut saw_stdout = false;
        let mut saw_stderr = false;
        while let Ok(env) = rx.try_recv() {
            if let TaskEvent::LogLine { stream, .. } = env.event {
                match stream {
                    StreamKind::Stdout => saw_stdout = true,
                    StreamKind::Stderr => saw_stderr = true,
                }
            }
        }
        assert!(saw_stdout && saw_stderr);
    }

    // Issue #11: a non-zero exit is a tool failure — Completed would hide
    // it — while output (and any partial findings) is still preserved.
    #[tokio::test]
    async fn nonzero_exit_fails_honestly_with_output_preserved() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv("sh", &["-c", "echo partial-evidence; exit 3"]),
            RunOpts::default(),
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Failed);
        assert_eq!(out.exit_code, Some(3));
        assert!(
            out.error
                .unwrap()
                .contains("scanner exited non-zero (3)"),
            "error names the code"
        );
        assert!(
            out.output.contains("partial-evidence"),
            "captured output preserved for parsers"
        );
    }

    // Issue #11: the plugin contract can document a non-zero code as
    // non-error (grep-convention tools) — that code still completes.
    #[tokio::test]
    async fn contract_ok_exit_codes_still_complete() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv("sh", &["-c", "echo vuln-found; exit 1"]),
            RunOpts {
                ok_exit_codes: vec![1],
                ..RunOpts::default()
            },
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Completed);
        assert_eq!(out.exit_code, Some(1));
        assert_eq!(out.error, None);
        // A code outside the contract list still fails.
        let out = run_cli(
            &argv("sh", &["-c", "exit 2"]),
            RunOpts {
                ok_exit_codes: vec![1],
                ..RunOpts::default()
            },
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Failed);
    }

    // Issue #11: every terminal category is distinguishable.
    #[tokio::test]
    async fn terminal_states_are_distinguishable() {
        let (s, _rx) = sink();
        // Success: zero exit, no findings needed.
        let out = run_cli(&argv("sh", &["-c", "exit 0"]), RunOpts::default(), &s).await;
        assert_eq!(out.status, TaskStatus::Completed);
        // Non-zero exit: failed, code surfaced.
        let out = run_cli(&argv("sh", &["-c", "exit 7"]), RunOpts::default(), &s).await;
        assert_eq!(out.status, TaskStatus::Failed);
        assert_eq!(out.exit_code, Some(7));
        // Signal death: failed, distinct message.
        let out = run_cli(&argv("sh", &["-c", "kill -9 $$"]), RunOpts::default(), &s).await;
        assert_eq!(out.status, TaskStatus::Failed);
        let err = out.error.clone().unwrap_or_default();
        assert!(err.contains("signal"), "signal exit error: {err:?}");
        // Timeout: failed, distinct message.
        let out = run_cli(
            &argv("sh", &["-c", "sleep 30"]),
            RunOpts {
                timeout: Duration::from_millis(300),
                ..RunOpts::default()
            },
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Failed);
        assert!(out.error.unwrap().contains("timed out"));
        assert_eq!(out.exit_code, None);
        // Cancel: its own status, no exit code.
        let cancel = CancellationToken::new();
        let canceller = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                cancel.cancel();
            })
        };
        let out = run_cli(
            &argv("sh", &["-c", "sleep 30"]),
            RunOpts {
                cancel,
                ..RunOpts::default()
            },
            &s,
        )
        .await;
        canceller.await.unwrap();
        assert_eq!(out.status, TaskStatus::Cancelled);
        assert_eq!(out.exit_code, None);
    }

    #[tokio::test]
    async fn timeout_kills_process() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv("sh", &["-c", "sleep 30; echo never"]),
            RunOpts {
                timeout: Duration::from_millis(300),
                ..Default::default()
            },
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Failed);
        assert!(out.error.as_deref().unwrap_or("").contains("timed out"));
    }

    #[tokio::test]
    async fn cancellation_kills_process() {
        let (s, _rx) = sink();
        let cancel = CancellationToken::new();
        let opts = RunOpts {
            timeout: Duration::from_secs(30),
            cancel: cancel.clone(),
            ..Default::default()
        };
        let (s2, _) = (s.clone(), ());
        let handle = tokio::spawn(async move {
            run_cli(&argv("sh", &["-c", "sleep 30; echo never"]), opts, &s2).await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
        let out = handle.await.unwrap();
        assert_eq!(out.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn output_cap_truncates() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv("sh", &["-c", "yes 0123456789 | head -n 10000"]),
            RunOpts {
                max_output_bytes: 1024,
                timeout: Duration::from_secs(10),
                ..Default::default()
            },
            &s,
        )
        .await;
        assert!(out.truncated, "expected truncation flag");
        assert!(out.output.len() <= 1100, "output len {}", out.output.len());
    }

    #[tokio::test]
    async fn spawn_failure_is_clean() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv("definitely-not-a-real-binary-xyz", &[]),
            RunOpts::default(),
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Failed);
        assert!(out.error.unwrap().contains("failed to spawn"));
    }

    #[tokio::test]
    async fn env_is_scrubbed() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv(
                "sh",
                &[
                    "-c",
                    "echo \"SECRET=$SECRET\"; echo \"PATH_SET=${PATH:+yes}\"",
                ],
            ),
            RunOpts::default(),
            &s,
        )
        .await;
        assert!(
            out.output.contains("SECRET="),
            "secret must not leak: {}",
            out.output
        );
        assert!(out.output.contains("PATH_SET=yes"));
    }

    #[tokio::test]
    async fn missing_binary_message_mentions_path() {
        let (s, _rx) = sink();
        let out = run_cli(&argv("no-such-tool-abc", &["x"]), RunOpts::default(), &s).await;
        assert!(out.error.unwrap().contains("PATH"));
    }

    // Issue #9: a child that spawns its own children must not leak them
    // after cancellation. The grandchild is a subshell that would write a
    // survivor marker ~4 s after launch; with proper group termination it is
    // killed alongside the parent and the marker never appears.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancel_terminates_grandchildren() {
        use tokio_util::sync::CancellationToken;

        let (s, _rx) = sink();
        let dir = tempfile::tempdir().unwrap();
        let survivor = dir.path().join("survived");
        let script = format!(
            "( sleep 4 && echo survived > {} ) & exec sleep 30",
            survivor.display()
        );

        let cancel = CancellationToken::new();
        let opts = RunOpts {
            timeout: Duration::from_secs(60),
            cancel: cancel.clone(),
            ..RunOpts::default()
        };
        // Fire cancellation from a side task so run_cli can borrow the sink.
        let canceller = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(800)).await;
                cancel.cancel();
            }
        });
        let args = argv("sh", &["-c", &script]);
        let outcome = run_cli(&args, opts, &s).await;
        canceller.await.unwrap();
        assert_eq!(outcome.status, TaskStatus::Cancelled);

        // The grandchild would write the marker at ~4 s. Wait past that and
        // prove it never happened.
        tokio::time::sleep(Duration::from_millis(4_500)).await;
        assert!(
            !survivor.exists(),
            "grandchild survived cancellation — process tree was not terminated"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_terminates_grandchildren() {
        let (s, _rx) = sink();
        let dir = tempfile::tempdir().unwrap();
        let survivor = dir.path().join("survived");
        let script = format!(
            "( sleep 4 && echo survived > {} ) & exec sleep 30",
            survivor.display()
        );

        let opts = RunOpts {
            timeout: Duration::from_millis(800),
            ..RunOpts::default()
        };
        let out = run_cli(&argv("sh", &["-c", &script]), opts, &s).await;
        assert_eq!(out.status, TaskStatus::Failed);
        assert!(out.error.unwrap_or_default().contains("timed out"));

        tokio::time::sleep(Duration::from_millis(4_500)).await;
        assert!(
            !survivor.exists(),
            "grandchild survived timeout — process tree was not terminated"
        );
    }

    // --- Issue #10: bounded output reads ------------------------------------------------

    #[tokio::test]
    async fn giant_single_line_is_truncated_not_accumulated() {
        let (s, mut rx) = sink();
        // 50 MB with no newline at all. The old `BufReader::lines()` pump
        // would allocate the whole thing before any cap applied.
        let out = run_cli(
            &argv("sh", &["-c", "head -c 50000000 /dev/zero | tr '\\0' a; echo"]),
            RunOpts {
                max_output_bytes: 64 * 1024,
                ..RunOpts::default()
            },
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Completed);
        assert!(out.truncated, "giant line must be flagged truncated");
        assert!(
            out.output.len() < 200 * 1024,
            "retained output must be bounded, got {} bytes",
            out.output.len()
        );
        assert!(
            out.output.contains("[secuscan: line truncated]")
                || out.output.contains("[secuscan: output truncated]"),
            "truncation marker present"
        );
        // LogLine events must also be bounded (event quota + 2KB slice).
        let mut log_bytes = 0usize;
        while let Ok(env) = rx.try_recv() {
            if let TaskEvent::LogLine { line, .. } = env.event {
                log_bytes += line.len();
            }
        }
        assert!(log_bytes < 200 * 1024, "events bounded, got {log_bytes}");
    }

    #[tokio::test]
    async fn endless_output_stays_bounded_and_times_out() {
        let (s, rx) = sink();
        // Drain events like the real recorder does, otherwise channel
        // backpressure (not the buffer cap) becomes the limiter.
        let drainer = tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        let out = run_cli(
            &argv("sh", &["-c", "while true; do echo spam-line; done"]),
            RunOpts {
                timeout: Duration::from_millis(1_500),
                max_output_bytes: 64 * 1024,
                ..RunOpts::default()
            },
            &s,
        )
        .await;
        drainer.abort();
        assert_eq!(out.status, TaskStatus::Failed);
        assert!(out.error.unwrap_or_default().contains("timed out"));
        assert!(out.truncated, "endless output flagged truncated");
        assert!(
            out.output.len() < 128 * 1024,
            "retained output bounded, got {} bytes",
            out.output.len()
        );
    }

    #[tokio::test]
    async fn binary_output_does_not_kill_the_pump() {
        let (s, mut rx) = sink();
        // Invalid UTF-8 (0xff) and NUL bytes on stdout; a clean line after.
        // The old `next_line()` pump aborted on the invalid UTF-8 and the
        // rest of the stream was lost.
        let out = run_cli(
            &argv("sh", &["-c", "printf 'pre\\xff\\x00line\\nclean-after-binary\\n'"]),
            RunOpts::default(),
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Completed);
        assert!(
            out.output.contains("clean-after-binary"),
            "lines after binary bytes must survive: {:?}",
            out.output
        );
        let mut saw_clean = false;
        while let Ok(env) = rx.try_recv() {
            if let TaskEvent::LogLine { line, .. } = env.event {
                if line.contains("clean-after-binary") {
                    saw_clean = true;
                }
            }
        }
        assert!(saw_clean, "clean line emitted as an event");
    }

    #[tokio::test]
    async fn dual_stream_chatter_stays_bounded_and_ordered() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv(
                "sh",
                &[
                    "-c",
                    "for i in 1 2 3; do echo \"o$i\"; echo \"e$i\" 1>&2; done",
                ],
            ),
            RunOpts::default(),
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Completed);
        // Stdout then stderr concatenation preserves per-stream order.
        for i in 1..=3 {
            assert!(out.output.contains(&format!("o{i}")));
            assert!(out.output.contains(&format!("e{i}")));
        }
        let pos_o1 = out.output.find("o1").unwrap();
        let pos_o3 = out.output.find("o3").unwrap();
        assert!(pos_o1 < pos_o3, "stdout order preserved");
    }
}
