import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams, Link, useNavigate } from 'react-router-dom'
import { Search, ChevronRight, Zap, Ban } from 'lucide-react'
import { request, sniperApi } from '@/api/client'
import type { Finding, AnalystStatus } from '@/api/types'
import { SeverityBadge } from '@/components/SeverityBadge'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { cn, SEVERITY_ORDER, ANALYST_STATUS_LABEL, KIND_LABEL } from '@/utils/format'
import { useAuth } from '@/auth/AuthContext'
import { useWorkspace } from '@/auth/WorkspaceContext'

const SEVERITIES = [...SEVERITY_ORDER]
const TRIAGE: AnalystStatus[] = ['new', 'confirmed', 'needs_review', 'false_positive', 'accepted_risk', fixed()]

function fixed(): AnalystStatus {
  return 'fixed'
}

export function FindingsPage() {
  const { scopeParam } = useWorkspace()
  const [params, setParams] = useSearchParams()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const { user } = useAuth()
  // Sprint 2.1: bulk selection + keyset-paginated accumulation.
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [accumulated, setAccumulated] = useState<Finding[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const severity = params.getAll('severity')
  const status = params.get('analyst_status') ?? ''
  const kind = params.get('kind') ?? ''
  const search = params.get('search') ?? ''

  const qs = new URLSearchParams()
  severity.forEach((s) => qs.append('severity', s))
  if (status) qs.set('analyst_status', status)
  if (kind) qs.set('kind', kind)
  if (search) qs.set('search', search)
  qs.set('workspace_id', scopeParam)
  qs.set('limit', '200')

  if (cursor) qs.set('cursor', cursor)

  const { data, isLoading, error } = useQuery({
    queryKey: ['findings', qs.toString()],
    queryFn: () =>
      request<{ items: Finding[]; total: number; next_cursor?: string | null }>(
        `/findings?${qs.toString()}`,
      ),
  })

  // Accumulate pages when loading more; reset when the filter set changes.
  const filterKey = `${severity.join(',')}|${status}|${kind}|${search}|${scopeParam}`
  useEffect(() => {
    setAccumulated([])
    setCursor(null)
    setSelected(new Set())
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey])
  useEffect(() => {
    if (!data) return
    setAccumulated((prev) => {
      const seen = new Set(prev.map((p) => p.id))
      return [...prev, ...data.items.filter((i) => !seen.has(i.id))]
    })
    setCursor(data.next_cursor ?? null)
  }, [data])

  const triageMut = useMutation({
    mutationFn: ({
      id,
      status,
      reason,
      severityOverride,
    }: {
      id: string
      status?: AnalystStatus
      reason?: string
      severityOverride?: string | ''
    }) =>
      request(`/findings/${id}/triage`, {
        method: 'PATCH',
        body: {
          ...(status ? { analyst_status: status } : {}),
          ...(reason ? { reason } : {}),
          ...(severityOverride !== undefined ? { severity_override: severityOverride } : {}),
        },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })

  // v3.1.2 — Launch Sniper against a finding. The Auto-Exploiter picks
  // an exploit chain based on the finding's category and runs it
  // step-by-step as real scan tasks. We navigate to /sniper so the user
  // can watch the chain progress.
  const sniperMut = useMutation({
    mutationFn: ({ findingId, workspaceId }: { findingId: string; workspaceId?: string }) =>
      sniperApi.run(findingId, workspaceId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sniper-runs'] })
      navigate('/sniper')
    },
  })

  const bulkMut = useMutation({
    mutationFn: (payload: { ids: string[]; analyst_status: AnalystStatus; reason?: string }) =>
      request<{ updated: number }>('/findings/bulk', { method: 'PATCH', body: payload }),
    onSuccess: () => {
      setSelected(new Set())
      qc.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  const canTriage = user?.role === 'admin' || user?.role === 'scanner'
  const canSnipe = canTriage // same permission gate as triage

  function toggleSeverity(sev: string) {
    const next = new URLSearchParams(params)
    const current = next.getAll('severity')
    next.delete('severity')
    for (const s of current) {
      if (s !== sev) next.append('severity', s)
    }
    if (!current.includes(sev)) next.append('severity', sev)
    setParams(next, { replace: true })
  }

  if (isLoading) return <Spinner label="Loading findings…" />
  if (error) return <ErrorNote message={error instanceof Error ? error.message : 'Failed to load'} />

  const items = accumulated.length > 0 ? accumulated : (data?.items ?? [])
  const nextCursor = data?.next_cursor ?? null

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-4">
      {selected.size > 0 && (
        <div
          className="flex flex-wrap items-center gap-2 rounded-lg bg-slate-900 px-4 py-2.5 text-sm text-white"
          data-testid="bulk-toolbar"
        >
          <span className="font-medium">{selected.size} selected</span>
          <select
            className="rounded-md bg-slate-800 px-2 py-1 text-xs ring-1 ring-slate-600"
            defaultValue=""
            aria-label="Bulk triage status"
            onChange={(e) => {
              const st = e.target.value as AnalystStatus
              if (!st) return
              bulkMut.mutate({ ids: [...selected], analyst_status: st })
              e.target.value = ''
            }}
          >
            <option value="">Set triage status…</option>
            {TRIAGE.map((t) => (
              <option key={t} value={t}>
                {ANALYST_STATUS_LABEL[t]}
              </option>
            ))}
          </select>
          {bulkMut.error && (
            <span className="text-xs text-rose-300">
              {bulkMut.error instanceof Error ? bulkMut.error.message : 'bulk triage failed'}
            </span>
          )}
          <button
            className="ml-auto rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
            onClick={() => setSelected(new Set())}
          >
            Clear selection
          </button>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="input pl-9"
            placeholder="Search title or description…"
            value={search}
            onChange={(e) => {
              const next = new URLSearchParams(params)
              if (e.target.value) next.set('search', e.target.value)
              else next.delete('search')
              setParams(next, { replace: true })
            }}
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              className={cn(
                'chip capitalize transition-colors',
                severity.includes(s)
                  ? 'bg-slate-800 text-white'
                  : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50',
              )}
            >
              {s}
            </button>
          ))}
        </div>
        <select
          className="input w-auto"
          value={status}
          onChange={(e) => {
            const next = new URLSearchParams(params)
            if (e.target.value) next.set('analyst_status', e.target.value)
            else next.delete('analyst_status')
            setParams(next, { replace: true })
          }}
          aria-label="Triage status"
        >
          <option value="">All triage states</option>
          {TRIAGE.map((t) => (
            <option key={t} value={t}>
              {ANALYST_STATUS_LABEL[t]}
            </option>
          ))}
        </select>
      </div>

      <div className="text-xs text-slate-400">
        {data?.total ?? 0} finding(s){items.length < (data?.total ?? 0) && ` · showing first ${items.length}`}
      </div>

      {items.length === 0 ? (
        <EmptyState
          title="No findings match"
          description="Adjust the filters, or run more scans to collect findings."
        />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[860px]">
            <thead className="border-b border-slate-100 bg-slate-50/60">
              <tr>
                <th className="th w-8">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-slate-300 text-slate-800 focus:ring-slate-500"
                    checked={items.length > 0 && items.every((i) => selected.has(i.id))}
                    onChange={() => {
                      if (items.every((i) => selected.has(i.id))) setSelected(new Set())
                      else setSelected(new Set(items.map((i) => i.id)))
                    }}
                    aria-label="Select all findings on this page"
                  />
                </th>
                <th className="th">Severity</th>
                <th className="th">Finding</th>
                <th className="th">Type</th>
                <th className="th">Scanner</th>
                <th className="th">Triage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((f) => (
                <FindingTableEntry
                  key={f.id}
                  finding={f}
                  canTriage={canTriage}
                  canSnipe={canSnipe}
                  sniperPending={sniperMut.isPending}
                  sniperError={
                    sniperMut.error && sniperMut.variables?.findingId === f.id
                      ? sniperMut.error instanceof Error
                        ? sniperMut.error.message
                        : 'sniper launch failed'
                      : null
                  }
                  onSnipe={() =>
                    sniperMut.mutate({
                      findingId: f.id,
                    })
                  }
                  onTriage={(s, reason) => triageMut.mutate({ id: f.id, status: s, reason })}
                  selected={selected.has(f.id)}
                  onSelect={() => toggleSelect(f.id)}
                  onOverride={(sev) =>
                    triageMut.mutate({
                      id: f.id,
                      status: f.analyst_status,
                      severityOverride: sev,
                    })
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {nextCursor && items.length > 0 && (
        <div className="text-center">
          <button
            className="btn-secondary"
            onClick={() => setCursor(nextCursor)}
            data-testid="load-more"
          >
            Load more ({(data?.total ?? 0) - items.length} remaining)
          </button>
        </div>
      )}
    </div>
  )
}

function FindingTableEntry({
  finding: f,
  canTriage,
  canSnipe,
  sniperPending,
  sniperError,
  onSnipe,
  onTriage,
  selected,
  onSelect,
  onOverride,
}: {
  finding: Finding
  canTriage: boolean
  canSnipe: boolean
  sniperPending: boolean
  sniperError: string | null
  onSnipe: () => void
  onTriage: (status: AnalystStatus, reason?: string) => void
  selected: boolean
  onSelect: () => void
  onOverride: (severity: string | '') => void
}) {
  const [open, setOpen] = useState(false)
  // Max-Parity Sprint 1.1 — false-positive marking collects an optional
  // justification for the FP-memory audit trail, and the expanded row
  // lazy-fetches the single finding to surface that audit trail.
  const [fpPromptOpen, setFpPromptOpen] = useState(false)
  const [fpReason, setFpReason] = useState('')

  const { data: full } = useQuery({
    queryKey: ['finding', f.id],
    queryFn: () => request<Finding>(`/findings/${f.id}`),
    enabled: open && f.analyst_status === 'false_positive',
  })
  const fp = full?.fp_memory

  function handleStatusChange(status: AnalystStatus) {
    if (status === 'false_positive') {
      setFpReason('')
      setFpPromptOpen(true)
      return
    }
    setFpPromptOpen(false)
    onTriage(status)
  }

  return (
    <>
      <tr
        className={cn('cursor-pointer transition-colors hover:bg-slate-50', open && 'bg-slate-50')}
        onClick={() => setOpen((o) => !o)}
      >
        <td className="td" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-slate-300 text-slate-800 focus:ring-slate-500"
            checked={selected}
            onChange={onSelect}
            aria-label={`Select ${f.title}`}
          />
        </td>
        <td className="td">
          <SeverityBadge severity={f.severity_override ?? f.severity} />
          {f.severity_override && (
            <div className="mt-0.5 text-[10px] text-slate-400">scanner: {f.severity}</div>
          )}
        </td>
        <td className="td max-w-[420px]">
          <div className="truncate font-medium text-slate-700">{f.title}</div>
          <div className="truncate text-xs text-slate-400">{f.category}</div>
        </td>
        <td className="td text-xs text-slate-500">{KIND_LABEL[f.kind] ?? f.kind}</td>
        <td className="td">
          <Link
            to={`/tasks/${f.task_id}`}
            className="text-xs text-brand-700 hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {f.plugin_id}
          </Link>
        </td>
        <td className="td" onClick={(e) => e.stopPropagation()}>
          <div className="flex items-center gap-1.5">
            <select
              className={cn(
                'rounded-md border-0 px-2 py-1 text-xs font-medium ring-1 focus:outline-none',
                f.analyst_status === 'new' && 'bg-sky-50 text-sky-700 ring-sky-200',
                f.analyst_status === 'confirmed' && 'bg-rose-50 text-rose-700 ring-rose-200',
                f.analyst_status === 'false_positive' && 'bg-slate-100 text-slate-500 ring-slate-200',
                f.analyst_status === 'accepted_risk' && 'bg-amber-50 text-amber-700 ring-amber-200',
                f.analyst_status === 'fixed' && 'bg-emerald-50 text-emerald-700 ring-emerald-200',
                f.analyst_status === 'needs_review' && 'bg-violet-50 text-violet-700 ring-violet-200',
              )}
              value={f.analyst_status}
              disabled={!canTriage}
              onChange={(e) => handleStatusChange(e.target.value as AnalystStatus)}
              aria-label="Triage"
            >
              {TRIAGE.map((t) => (
                <option key={t} value={t}>
                  {ANALYST_STATUS_LABEL[t]}
                </option>
              ))}
            </select>
            {canTriage && fpPromptOpen && (
              <span
                className="inline-flex items-center gap-1.5"
                role="group"
                aria-label="False-positive reason controls"
              >
                <input
                  className="input w-44 px-2 py-1 text-xs"
                  placeholder="Why is this a false positive?"
                  value={fpReason}
                  autoFocus
                  onChange={(e) => setFpReason(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      setFpPromptOpen(false)
                      onTriage('false_positive', fpReason.trim() || undefined)
                    }
                    if (e.key === 'Escape') setFpPromptOpen(false)
                  }}
                  aria-label="False-positive reason"
                />
                <button
                  type="button"
                  className="inline-flex items-center gap-1 rounded-md bg-slate-800 px-2 py-1 text-xs font-medium text-white hover:bg-slate-700"
                  title="Mark as false positive (recorded in FP memory)"
                  onClick={() => {
                    setFpPromptOpen(false)
                    onTriage('false_positive', fpReason.trim() || undefined)
                  }}
                >
                  <Ban className="h-3.5 w-3.5" />
                  Mark FP
                </button>
              </span>
            )}
            {canSnipe && (
              <button
                type="button"
                className={cn(
                  'inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium ring-1 transition-colors',
                  'bg-violet-50 text-violet-700 ring-violet-200 hover:bg-violet-100',
                  sniperPending && 'cursor-wait opacity-60',
                )}
                disabled={sniperPending}
                onClick={onSnipe}
                title="Launch Sniper Auto-Exploiter against this finding"
              >
                <Zap className="h-3.5 w-3.5" />
                Sniper
              </button>
            )}
          </div>
          {sniperError && (
            <div className="mt-1 text-xs text-rose-600" role="alert">{sniperError}</div>
          )}
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50/70">
          <td colSpan={6} className="px-4 py-4">
            {f.analyst_status === 'false_positive' && fp && (
              <div
                className="mb-3 rounded-md bg-slate-100 px-3 py-2 text-xs text-slate-600 ring-1 ring-slate-200"
                data-testid="fp-audit"
              >
                <span className="font-semibold">False-positive memory:</span>{' '}
                marked by <span className="font-medium">{fp.decided_by_email}</span> on{' '}
                {new Date(fp.decided_at).toLocaleString()}
                {fp.reason ? ` — “${fp.reason}”` : ''}. Re-scans of this target will
                auto-suppress this finding until it is re-triaged.
              </div>
            )}
            {(f.cve || f.cvss_v3 || f.cwe || f.owasp || f.epss_score || f.cisa_kev) && (
              <div className="mb-3 flex flex-wrap gap-1.5 text-xs" data-testid="enrichment-badges">
                {f.cve && (
                  <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-white">
                    {f.cve}
                    {f.cisa_kev && (
                      <span className="ml-1 rounded bg-red-600 px-1">KEV</span>
                    )}
                  </span>
                )}
                {f.cvss_v3 !== null && f.cvss_v3 !== undefined && (
                  <span className="rounded bg-orange-100 px-2 py-0.5 text-orange-800 ring-1 ring-orange-200">
                    CVSS {f.cvss_v3.toFixed(1)}
                    {f.cvss_vector ? ` (${f.cvss_vector})` : ''}
                  </span>
                )}
                {f.cwe && (
                  <span className="rounded bg-slate-100 px-2 py-0.5 text-slate-700 ring-1 ring-slate-200">
                    {f.cwe}
                  </span>
                )}
                {f.owasp && (
                  <span className="rounded bg-violet-100 px-2 py-0.5 text-violet-800 ring-1 ring-violet-200">
                    {f.owasp}
                  </span>
                )}
                {f.epss_score !== null && f.epss_score !== undefined && (
                  <span className="rounded bg-sky-100 px-2 py-0.5 text-sky-800 ring-1 ring-sky-200">
                    EPSS {(f.epss_score * 100).toFixed(1)}%
                    {f.epss_percentile
                      ? ` (p${Math.round(f.epss_percentile * 100)})`
                      : ''}
                  </span>
                )}
              </div>
            )}
            <div className="grid gap-4 md:grid-cols-3">
              <DetailBlock label="Description">{f.description || '—'}</DetailBlock>
              <DetailBlock label="Evidence">
                <pre className="overflow-x-auto rounded bg-slate-900 p-2.5 font-mono text-xs text-slate-200">
                  {f.proof || '—'}
                </pre>
              </DetailBlock>
              <DetailBlock label="Remediation">{f.remediation || '—'}</DetailBlock>
            </div>
            {f.url && (
              <div className="mt-2 text-xs text-slate-500">
                URL: <span className="font-mono">{f.url}</span>
              </div>
            )}
            {canTriage && (
              <div className="mt-3 flex items-center gap-2 text-xs">
                <span className="text-slate-500">Severity override:</span>
                <select
                  className="input w-auto px-2 py-1"
                  value={f.severity_override ?? ''}
                  onChange={(e) => onOverride(e.target.value)}
                  aria-label="Severity override"
                  data-testid="severity-override"
                >
                  <option value="">— scanner value —</option>
                  {SEVERITIES.map((sv) => (
                    <option key={sv} value={sv}>
                      {sv}
                    </option>
                  ))}
                </select>
                {f.severity_original && f.severity_override && (
                  <span className="text-slate-400">
                    scanner reported {f.severity_original}
                  </span>
                )}
                {f.triage_by && f.triage_at && (
                  <span className="text-slate-400">
                    last triage by {f.triage_by} at{' '}
                    {new Date(f.triage_at).toLocaleString()}
                    {f.triage_reason ? ` — “${f.triage_reason}”` : ''}
                  </span>
                )}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

function DetailBlock({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
        <ChevronRight className="h-3 w-3" />
        {label}
      </div>
      <div className="text-sm text-slate-600">{children}</div>
    </div>
  )
}
