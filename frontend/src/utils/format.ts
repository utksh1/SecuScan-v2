import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatDuration(ms?: number | null): string {
  if (ms == null) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const m = Math.floor(ms / 60_000)
  const s = Math.round((ms % 60_000) / 1000)
  return `${m}m ${s}s`
}

export function relativeTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const diff = Date.now() - d.getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

export const SEVERITY_CLASSES: Record<string, string> = {
  critical: 'bg-rose-100 text-rose-800 ring-1 ring-rose-200',
  high: 'bg-orange-100 text-orange-800 ring-1 ring-orange-200',
  medium: 'bg-amber-100 text-amber-800 ring-1 ring-amber-200',
  low: 'bg-sky-100 text-sky-800 ring-1 ring-sky-200',
  info: 'bg-slate-100 text-slate-600 ring-1 ring-slate-200',
}

export const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-rose-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-500',
  low: 'bg-sky-500',
  info: 'bg-slate-400',
}

export const STATUS_CLASSES: Record<string, string> = {
  queued: 'bg-slate-100 text-slate-700 ring-1 ring-slate-200',
  running: 'bg-blue-100 text-blue-700 ring-1 ring-blue-200',
  completed: 'bg-emerald-100 text-emerald-700 ring-1 ring-emerald-200',
  failed: 'bg-rose-100 text-rose-700 ring-1 ring-rose-200',
  cancelled: 'bg-slate-100 text-slate-500 ring-1 ring-slate-200',
}

export const SAFETY_CLASSES: Record<string, string> = {
  safe: 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200',
  intrusive: 'bg-amber-50 text-amber-700 ring-1 ring-amber-200',
  exploit: 'bg-rose-50 text-rose-700 ring-1 ring-rose-200',
}

export const ANALYST_STATUS_LABEL: Record<string, string> = {
  new: 'New',
  confirmed: 'Confirmed',
  needs_review: 'Needs review',
  false_positive: 'False positive',
  accepted_risk: 'Accepted risk',
  fixed: 'Fixed',
}

export const KIND_LABEL: Record<string, string> = {
  observation: 'Observation',
  suspected_issue: 'Suspected',
  validated_issue: 'Validated',
}

export function formatBytes(n?: number | null): string {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
