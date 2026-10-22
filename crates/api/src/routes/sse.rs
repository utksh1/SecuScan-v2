//! Server-Sent Events: live task console.
//!
//! Protocol: replay persisted events from the `task_events` table (bounded to
//! the most recent 2000), then switch to the live broadcast. Live frames
//! carry their DB row id; frames with `id <= replay_cursor` are skipped, so
//! no event is ever duplicated or lost across the replay/live transition.
//! When the task is already terminal, the stream closes after a short grace
//! period (the recorder may still be flushing the final `finished` event).

use crate::auth::extractor::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use secuscan_db::models::TaskEventRow;
use secuscan_db::repo;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::time::Duration;

pub fn router() -> axum::Router<SharedState> {
    axum::Router::new().route("/tasks/:id/stream", axum::routing::get(stream))
}

#[derive(serde::Deserialize, Default)]
struct StreamQuery {
    /// Replay only events with DB id strictly greater than this cursor.
    after: Option<i64>,
}

async fn stream(
    State(state): State<SharedState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Query(q): Query<StreamQuery>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let task = repo::tasks::get(&state.db, &id).await?;
    if !user.is_admin() && task.user_id != user.0.id {
        return Err(ApiError::NotFound(format!("task {id}")));
    }

    // Subscribe BEFORE reading the DB so nothing is missed in between.
    let live = state.tasks.subscribe();
    let replay = repo::misc::list_events(&state.db, &id, q.after.unwrap_or(0), 2000).await?;
    let cursor = replay.last().map(|e| e.id).unwrap_or(q.after.unwrap_or(0));
    let terminal = task.status().is_terminal() && !state.tasks.is_running(&id).await;

    #[derive(Debug)]
    struct St {
        replay: VecDeque<TaskEventRow>,
        live: tokio::sync::broadcast::Receiver<crate::manager::SseFrame>,
        cursor: i64,
        task_id: String,
        terminal: bool,
        done: bool,
    }

    let st = St {
        replay: replay.into(),
        live,
        cursor,
        task_id: id,
        terminal,
        done: false,
    };

    let stream = futures::stream::unfold(st, |mut st| async move {
        if st.done {
            return None;
        }
        // 1) drain persisted replay first
        if let Some(ev) = st.replay.pop_front() {
            let is_finished = ev.level == "finished";
            st.cursor = st.cursor.max(ev.id);
            if is_finished {
                st.done = true;
            }
            return Some((Ok(frame_event(&ev.ts, ev.id, &ev.payload_json)), st));
        }
        // 2) task already terminal → grace window for the final flush, then close
        if st.terminal {
            let grace = tokio::time::sleep(Duration::from_secs(3));
            tokio::select! {
                frame = st.live.recv() => {
                    match frame {
                        Ok(f) if f.task_id == st.task_id && f.id > st.cursor => {
                            let is_finished = f.payload_json.contains("\"finished\"");
                            st.cursor = f.id;
                            if is_finished { st.done = true; }
                            return Some((Ok(frame_event(&f.ts, f.id, &f.payload_json)), st));
                        }
                        Ok(_) => return Some((Ok(Event::default().comment("skip")), st)),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            return Some((Ok(Event::default().comment("lagged")), st));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }
                _ = grace => return None,
            }
        }
        // 3) live events
        match st.live.recv().await {
            Ok(f) => {
                if f.task_id != st.task_id || f.id <= st.cursor {
                    return Some((Ok(Event::default().comment("skip")), st));
                }
                let is_finished = f.payload_json.contains("\"finished\"");
                st.cursor = f.id;
                if is_finished {
                    st.done = true;
                }
                Some((Ok(frame_event(&f.ts, f.id, &f.payload_json)), st))
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                Some((Ok(Event::default().comment("lagged")), st))
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
        }
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    ))
}

fn frame_event(ts: &str, id: i64, payload_json: &str) -> Event {
    Event::default()
        .id(id.to_string())
        .event("task")
        .data(format!(r#"{{"ts":"{ts}","event":{payload_json}}}"#))
}
