import { describe, expect, it } from 'vitest'

// parseFrame is module-private; we test it through a re-export shim.
// (Kept private to avoid widening the public API for tests.)
import { __test_parseFrame as parseFrame } from '@/api/sse'

describe('SSE frame parsing', () => {
  it('parses id + data payload with ts and event', () => {
    const frame = 'id: 42\ndata: {"ts":"2026-01-01T10:00:00.000Z","event":{"type":"info","message":"hi"}}'
    const parsed = parseFrame(frame)
    expect(parsed).not.toBeNull()
    expect(parsed!.id).toBe(42)
    expect(parsed!.ts).toBe('2026-01-01T10:00:00.000Z')
    expect(parsed!.event).toEqual({ type: 'info', message: 'hi' })
  })

  it('detects finished events', () => {
    const frame = 'id: 7\ndata: {"ts":"2026-01-01T10:00:01.000Z","event":{"type":"finished","status":"completed","exit_code":0}}'
    const parsed = parseFrame(frame)
    expect((parsed!.event as Record<string, unknown>).type).toBe('finished')
  })

  it('returns null for comment-only frames (keepalives)', () => {
    expect(parseFrame(': ping')).toBeNull()
    expect(parseFrame('')).toBeNull()
  })

  it('returns null for non-JSON data', () => {
    expect(parseFrame('data: not-json')).toBeNull()
  })

  it('returns null when the event key is missing', () => {
    expect(parseFrame('data: {"ts":"2026-01-01T00:00:00Z"}')).toBeNull()
  })

  it('concatenates multi-line data fields', () => {
    const frame = 'id: 1\ndata: {"ts":"t","event":\ndata: {"type":"phase","phase":"running"}}'
    const parsed = parseFrame(frame)
    expect(parsed!.event).toEqual({ type: 'phase', phase: 'running' })
  })
})
