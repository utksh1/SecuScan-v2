import { describe, expect, it } from 'vitest'
import {
  cn,
  formatDate,
  formatDuration,
  relativeTime,
  SEVERITY_CLASSES,
  SEVERITY_ORDER,
} from '@/utils/format'

describe('cn', () => {
  it('merges class names', () => {
    expect(cn('px-2', 'py-1')).toBe('px-2 py-1')
  })
  it('later classes win conflicts', () => {
    expect(cn('text-sm', 'text-lg')).toBe('text-lg')
  })
})

describe('formatDate', () => {
  it('formats valid ISO dates', () => {
    expect(formatDate('2026-01-15T10:30:00Z')).toMatch(/2026/)
  })
  it('handles missing values', () => {
    expect(formatDate(null)).toBe('—')
    expect(formatDate(undefined)).toBe('—')
  })
  it('passes through unparseable strings', () => {
    expect(formatDate('not-a-date')).toBe('not-a-date')
  })
})

describe('formatDuration', () => {
  it('renders milliseconds', () => {
    expect(formatDuration(42)).toBe('42ms')
  })
  it('renders seconds', () => {
    expect(formatDuration(1500)).toBe('1.5s')
  })
  it('renders minutes', () => {
    expect(formatDuration(125_000)).toBe('2m 5s')
  })
  it('handles missing', () => {
    expect(formatDuration(null)).toBe('—')
  })
})

describe('relativeTime', () => {
  it('renders just now for fresh timestamps', () => {
    expect(relativeTime(new Date().toISOString())).toBe('just now')
  })
  it('renders minutes ago', () => {
    const d = new Date(Date.now() - 5 * 60_000).toISOString()
    expect(relativeTime(d)).toBe('5m ago')
  })
})

describe('severity model', () => {
  it('is ordered critical → info', () => {
    expect(SEVERITY_ORDER[0]).toBe('critical')
    expect(SEVERITY_ORDER[SEVERITY_ORDER.length - 1]).toBe('info')
  })
  it('has a style class for every severity', () => {
    for (const s of SEVERITY_ORDER) {
      expect(SEVERITY_CLASSES[s]).toBeTruthy()
    }
  })
})
