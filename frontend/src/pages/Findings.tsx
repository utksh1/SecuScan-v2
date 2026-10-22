import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams, Link } from 'react-router-dom'
import { Search, ChevronRight } from 'lucide-react'
import { request } from '@/api/client'
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
  const { user } = useAuth()
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

  const { data, isLoading, error } = useQuery({
    queryKey: ['findings', qs.toString()],
    queryFn: () => request<{ items: Finding[]; total: number }>(`/findings?${qs.toString()}`),
  })

  const triageMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: AnalystStatus }) =>
      request(`/findings/${id}/triage`, { method: 'PATCH', body: { analyst_status: status } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })

  const canTriage = user?.role === 'admin' || user?.role === 'scanner'

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

  const items = data?.items ?? []

  return (
    <div className="space-y-4">
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
                  onTriage={(s) => triageMut.mutate({ id: f.id, status: s })}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function FindingTableEntry({
  finding: f,
  canTriage,
  onTriage,
}: {
  finding: Finding
  canTriage: boolean
  onTriage: (status: AnalystStatus) => void
}) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <tr
        className={cn('cursor-pointer transition-colors hover:bg-slate-50', open && 'bg-slate-50')}
        onClick={() => setOpen((o) => !o)}
      >
        <td className="td">
          <SeverityBadge severity={f.severity} />
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
            onChange={(e) => onTriage(e.target.value as AnalystStatus)}
            aria-label="Triage"
          >
            {TRIAGE.map((t) => (
              <option key={t} value={t}>
                {ANALYST_STATUS_LABEL[t]}
              </option>
            ))}
          </select>
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50/70">
          <td colSpan={5} className="px-4 py-4">
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
