// Fetch-based SSE reader for live task events.
//
// EventSource cannot send an Authorization header, so we stream
// `text/event-stream` manually via fetch + ReadableStream.

import { getAccessToken, tryRefresh } from './client'

export interface TaskStreamEvent {
  id: number
  ts: string
  event:
    | { type: 'phase'; phase: string }
    | { type: 'log_line'; stream: 'stdout' | 'stderr'; line: string }
    | { type: 'info'; message: string } & Record<string, unknown>
    | { type: 'warn'; message: string } & Record<string, unknown>
    | { type: 'error'; message: string } & Record<string, unknown>
    | { type: 'progress'; done: number; total: number; message: string }
    | { type: 'finished'; status: string; exit_code: number | null }
    | (Record<string, unknown> & { type: string })
}

interface StreamHandle {
  abort: () => void
  done: Promise<void>
}

/**
 * Stream task events with automatic reconnection: on transport errors or
 * server closes while the task is (presumably) still live, reconnects with
 * `?after=<lastId>` so no event is replayed twice. Surfaces the error via
 * `onError` only after retries are exhausted or a finished frame arrives.
 */
export function streamTaskEvents(
  taskId: string,
  onEvent: (evt: TaskStreamEvent) => void,
  onDone?: () => void,
  isTerminal?: () => boolean,
): StreamHandle {
  const controller = new AbortController()

  const done = (async () => {
    let lastId = 0
    let backoff = 500
    let refreshed401 = false

    while (!controller.signal.aborted) {
      let res: Response
      try {
        res = await fetch(`/api/v1/tasks/${taskId}/stream?after=${lastId}`, {
          headers: {
            accept: 'text/event-stream',
            ...(getAccessToken() ? { authorization: `Bearer ${getAccessToken()}` } : {}),
          },
          credentials: 'include',
          signal: controller.signal,
        })
      } catch {
        if (controller.signal.aborted) return
        // Transport error — retry with backoff unless the task is terminal.
        if (isTerminal?.()) {
          onDone?.()
          return
        }
        if (backoff > 15_000) {
          onDone?.()
          return
        }
        await sleep(backoff)
        backoff = Math.min(backoff * 2, 15_000)
        continue
      }

      if (res.status === 401 && !refreshed401) {
        refreshed401 = true
        const { ok } = await tryRefresh()
        if (ok) continue
      }
      if (!res.ok || !res.body) {
        if (isTerminal?.()) {
          onDone?.()
          return
        }
        await sleep(backoff)
        backoff = Math.min(backoff * 2, 15_000)
        continue
      }

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      try {
        for (;;) {
          const { done: chunkDone, value } = await reader.read()
          if (chunkDone) break
          buffer += decoder.decode(value, { stream: true })
          let sep: number
          while ((sep = buffer.indexOf('\n\n')) !== -1) {
            const frame = buffer.slice(0, sep)
            buffer = buffer.slice(sep + 2)
            const parsed = parseFrame(frame)
            if (parsed) {
              lastId = Math.max(lastId, parsed.id)
              backoff = 500 // reset on progress
              onEvent(parsed)
              if (parsed.event?.type === 'finished') {
                controller.abort()
                onDone?.()
                return
              }
            }
          }
        }
        // Server closed the stream. If the task is terminal we are done;
        // otherwise reconnect from the cursor.
        if (isTerminal?.()) {
          onDone?.()
          return
        }
        await sleep(300)
        continue
      } finally {
        reader.cancel().catch(() => undefined)
      }
    }
  })()

  return { abort: () => controller.abort(), done }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

/** @internal test-only export */
export const __test_parseFrame = parseFrame

function parseFrame(frame: string): TaskStreamEvent | null {
  let id = 0
  let ts = ''
  let data = ''
  for (const line of frame.split('\n')) {
    if (line.startsWith('id:')) {
      id = Number.parseInt(line.slice(3).trim(), 10) || 0
    } else if (line.startsWith('data:')) {
      data += line.slice(5).trim()
    } else if (line.startsWith(':')) {
      // comment / keepalive — ts arrives as a comment line from our server? no:
      continue
    }
  }
  // Our server sends: data: {"ts":"...","event":{...}}
  if (!data) return null
  try {
    const parsed = JSON.parse(data) as { ts?: string; event?: Record<string, unknown> }
    ts = parsed.ts ?? ''
    if (parsed.event == null) return null
    return { id, ts, event: parsed.event as TaskStreamEvent['event'] }
  } catch {
    return null
  }
}
