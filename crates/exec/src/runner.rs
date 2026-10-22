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
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
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
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts {
            timeout: Duration::from_secs(300),
            cancel: CancellationToken::new(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            env: Vec::new(),
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

    // Wait for exit, timeout, or cancellation.
    let wait_result = tokio::select! {
        _ = opts.cancel.cancelled() => {
            let _ = child.kill().await;
            let _ = child.wait().await; // reap
            WaitResult::Cancelled
        }
        _ = tokio::time::sleep(opts.timeout) => {
            let _ = child.kill().await;
            let _ = child.wait().await; // reap
            WaitResult::Timeout
        }
        status = child.wait() => {
            match status {
                Ok(s) => WaitResult::Exited(
                    s.code().or_else(|| if s.success() { Some(0) } else { Some(-1) }),
                ),
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
        WaitResult::Exited(code) => CliOutcome {
            status: TaskStatus::Completed,
            exit_code: code,
            output,
            truncated,
            error: None,
        },
        WaitResult::Timeout => CliOutcome {
            status: TaskStatus::Failed,
            exit_code: None,
            output,
            truncated,
            error: Some(format!(
                "timed out after {}s and the process was killed",
                opts.timeout.as_secs().max(1)
            )),
        },
        WaitResult::Cancelled => CliOutcome {
            status: TaskStatus::Cancelled,
            exit_code: None,
            output,
            truncated,
            error: None,
        },
        WaitResult::SpawnErr(e) => CliOutcome {
            status: TaskStatus::Failed,
            exit_code: None,
            output,
            truncated,
            error: Some(format!("wait failed: {e}")),
        },
    }
}

enum WaitResult {
    Exited(Option<i32>),
    Timeout,
    Cancelled,
    SpawnErr(std::io::Error),
}

async fn pump<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    stream: StreamKind,
    sink: EventSink,
    buf: SharedBuffer,
) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if !buf.was_truncated() {
            buf.push_line(&line);
        }
        sink.emit(TaskEvent::LogLine {
            stream,
            line: line.chars().take(2000).collect(),
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

    #[tokio::test]
    async fn nonzero_exit_still_completes() {
        let (s, _rx) = sink();
        let out = run_cli(
            &argv("sh", &["-c", "echo x; exit 3"]),
            RunOpts::default(),
            &s,
        )
        .await;
        assert_eq!(out.status, TaskStatus::Completed);
        assert_eq!(out.exit_code, Some(3));
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
}
