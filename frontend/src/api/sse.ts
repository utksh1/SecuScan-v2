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

export function streamTaskEvents(
  taskId: string,
  onEvent: (evt: TaskStreamEvent) => void,
  onDone?: () => void,
): StreamHandle {
  const controller = new AbortController()

  const done = (async () => {
    let retried = false
    while (!controller.signal.aborted) {
      let res: Response
      try {
        res = await fetch(`/api/v1/tasks/${taskId}/stream`, {
          headers: {
            accept: 'text/event-stream',
            ...(getAccessToken() ? { authorization: `Bearer ${getAccessToken()}` } : {}),
          },
          credentials: 'include',
          signal: controller.signal,
        })
      } catch (err) {
        if (controller.signal.aborted) return
        throw err
      }

      if (res.status === 401 && !retried) {
        retried = true
        const ok = await tryRefresh()
        if (ok) continue
      }
      if (!res.ok || !res.body) {
        throw new Error(`task stream failed (${res.status})`)
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
              onEvent(parsed)
              if (parsed.event?.type === 'finished') {
                controller.abort()
                onDone?.()
                return
              }
            }
          }
        }
        // Server closed the stream (terminal task replayed, keepalive timeout…)
        onDone?.()
        return
      } finally {
        reader.cancel().catch(() => undefined)
      }
    }
  })()

  return { abort: () => controller.abort(), done }
}

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
