//! Live task events streamed from executors to the API layer (and from
//! there to SSE subscribers and the `task_events` table).

use secuscan_core::models::{now_iso, Phase};
use serde::Serialize;
use tokio::sync::mpsc;
use uuid::Uuid;

/// One live event during task execution.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskEvent {
    Phase(Phase),
    LogLine {
        stream: StreamKind,
        line: String,
    },
    Info(String),
    Warn(String),
    Error(String),
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    /// Terminal event; the SSE stream closes after it.
    Finished {
        status: secuscan_core::models::TaskStatus,
        exit_code: Option<i32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    Stdout,
    Stderr,
}

/// An event plus routing metadata, sent through the recorder channel.
#[derive(Debug, Clone)]
pub struct EventEnvelope {
    pub task_id: Uuid,
    pub event: TaskEvent,
    pub ts: String,
}

/// Cloneable handle used by executors to emit events without awaiting
/// forever on a stalled consumer: sends are bounded to 2 seconds and are
/// dropped past that (the task itself must never block on logging).
#[derive(Clone)]
pub struct EventSink {
    task_id: Uuid,
    tx: mpsc::Sender<EventEnvelope>,
}

impl EventSink {
    pub fn new(task_id: Uuid, tx: mpsc::Sender<EventEnvelope>) -> Self {
        EventSink { task_id, tx }
    }

    pub async fn emit(&self, event: TaskEvent) {
        let env = EventEnvelope {
            task_id: self.task_id,
            event,
            ts: now_iso(),
        };
        // Never let a stalled recorder block or kill the scan.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.tx.send(env),
        )
        .await;
    }
}

impl std::fmt::Debug for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSink").field("task_id", &self.task_id).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn events_flow_through_channel() {
        let (tx, mut rx) = mpsc::channel(16);
        let sink = EventSink::new(Uuid::new_v4(), tx);
        sink.emit(TaskEvent::Info("hello".into())).await;
        let env = rx.recv().await.unwrap();
        assert!(matches!(env.event, TaskEvent::Info(ref m) if m == "hello"));
        assert!(!env.ts.is_empty());
    }

    #[tokio::test]
    async fn stalled_consumer_does_not_block_longer_than_timeout() {
        let (tx, _rx) = mpsc::channel(1); // tiny buffer, no reader
        let sink = EventSink::new(Uuid::new_v4(), tx);
        // fill the buffer
        for _ in 0..2 {
            let start = std::time::Instant::now();
            sink.emit(TaskEvent::Info("x".into())).await;
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
        }
    }
}
