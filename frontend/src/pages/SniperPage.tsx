// Sniper Auto-Exploiter: finding-driven exploit chains. Runs are launched
// from the Findings page ("Sniper" action); this page tracks every run's
// step-by-step progress and the final proof.

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Zap, ChevronRight, XCircle } from 'lucide-react'
import { sniperApi } from '@/api/client'
import type { SniperRun } from '@/api/types'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { cn, formatDate } from '@/utils/format'

function OutcomeBadge({ outcome }: { outcome?: SniperRun['outcome'] }) {
  if (!outcome) return null
  return (
    <span
      className={cn(
        'chip capitalize',
        outcome === 'proven' && 'bg-rose-50 text-rose-700 ring-1 ring-rose-200',
        outcome === 'not_proven' && 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200',
        outcome === 'inconclusive' && 'bg-amber-50 text-amber-700 ring-1 ring-amber-200',
      )}
    >
      {outcome === 'proven' ? 'exploit proven' : outcome.replace('_', ' ')}
    </span>
  )
}

function RunStatusBadge({ status }: { status: SniperRun['status'] }) {
  return (
    <span
      className={cn(
        'chip capitalize',
        status === 'running' && 'bg-sky-50 text-sky-700 ring-1 ring-sky-200',
        status === 'queued' && 'bg-slate-100 text-slate-500 ring-1 ring-slate-200',
        status === 'completed' && 'bg-violet-50 text-violet-700 ring-1 ring-violet-200',
        status === 'failed' && 'bg-rose-50 text-rose-700 ring-1 ring-rose-200',
        status === 'cancelled' && 'bg-slate-100 text-slate-400 ring-1 ring-slate-200',
      )}
    >
      {status === 'running' && (
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-sky-500" aria-hidden />
      )}
      {status}
    </span>
  )
}

export function SniperPage() {
  const qc = useQueryClient()
  const { user } = useAuth()
  const [openId, setOpenId] = useState<string | null>(null)

  const { data, isLoading, error } = useQuery({
    queryKey: ['sniper-runs'],
    queryFn: () => sniperApi.list(),
    // Live-poll while anything is in flight.
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((r) => r.status === 'running' || r.status === 'queued')
        ? 2_500
        : false,
  })

  const cancelMut = useMutation({
    mutationFn: (id: string) => sniperApi.cancel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sniper-runs'] }),
  })

  if (isLoading) return <Spinner label="Loading sniper runs…" />
  if (error) return <ErrorNote message={error instanceof Error ? error.message : 'Failed to load'} />

  const runs = data?.items ?? []
  const canCancel = user?.role === 'admin' || user?.role === 'scanner'

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <Zap className="mt-1 h-6 w-6 shrink-0 text-brand-600" />
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Sniper Auto-Exploiter</h2>
          <p className="text-sm text-slate-500">
            Turn a finding into a validated exploit: Sniper picks a chain of exploit steps for the
            finding's category (SQL → sqlmap enumeration → hash extraction; XSS → OOB callback;
            …), executes them as real consented tasks, and upgrades the source finding with proof
            when impact is confirmed. Launch runs from the{' '}
            <Link to="/findings" className="text-brand-700 hover:underline">Findings</Link> page.
          </p>
        </div>
      </div>

      {runs.length === 0 ? (
        <EmptyState
          title="No sniper runs yet"
          description="Open a finding and press “Run Sniper” to start an exploit chain against its target."
        />
      ) : (
        <div className="card divide-y divide-slate-100">
          {runs.map((r) => {
            const open = openId === r.id
            return (
              <div key={r.id}>
                <button
                  className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50"
                  onClick={() => setOpenId(open ? null : r.id)}
                  aria-expanded={open}
                >
                  <ChevronRight className={cn('h-4 w-4 shrink-0 text-slate-400 transition-transform', open && 'rotate-90')} />
                  <RunStatusBadge status={r.status} />
                  <OutcomeBadge outcome={r.outcome} />
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-slate-700">
                    {r.category}
                    {r.target ? <span className="ml-2 font-mono text-xs text-slate-400">{r.target}</span> : null}
                  </span>
                  <span className="hidden text-xs text-slate-400 sm:block">
                    {r.steps?.length ?? 0} step(s) · {formatDate(r.created_at)}
                  </span>
                </button>
                {open && (
                  <div className="space-y-3 border-t border-slate-100 bg-slate-50/60 px-4 py-4 pl-10">
                    {r.error && (
                      <div className="rounded bg-rose-50 px-3 py-2 text-xs text-rose-700">{r.error}</div>
                    )}
                    <ol className="space-y-2">
                      {(r.steps ?? []).map((s) => (
                        <li key={s.step} className="flex flex-wrap items-center gap-2 text-sm">
                          <span className="flex h-5 w-5 items-center justify-center rounded-full bg-slate-200 text-[10px] font-semibold text-slate-600">
                            {s.step}
                          </span>
                          <span className="font-medium text-slate-700">{s.label}</span>
                          <span className="font-mono text-xs text-slate-400">{s.plugin_id}</span>
                          <span
                            className={cn(
                              'chip',
                              s.status === 'running' && 'bg-sky-50 text-sky-700',
                              s.status === 'completed' && 'bg-emerald-50 text-emerald-700',
                              s.status === 'failed' && 'bg-rose-50 text-rose-700',
                              (s.status === 'cancelled' || s.status === 'failed') && 'opacity-80',
                            )}
                          >
                            {s.status}
                          </span>
                          {typeof s.findings_count === 'number' && s.findings_count > 0 && (
                            <span className="text-xs text-slate-500">{s.findings_count} finding(s)</span>
                          )}
                          {s.error && <span className="text-xs text-rose-600">{s.error}</span>}
                          {s.task_id && (
                            <Link to={`/tasks/${s.task_id}`} className="text-xs text-brand-700 hover:underline">
                              view task
                            </Link>
                          )}
                        </li>
                      ))}
                    </ol>
                    {r.proof && (
                      <div>
                        <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                          Proof
                        </div>
                        <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded bg-slate-900 p-3 font-mono text-xs text-slate-200">
                          {r.proof}
                        </pre>
                      </div>
                    )}
                    <div className="flex items-center gap-3 text-xs text-slate-400">
                      {r.finished_at && <span>finished {formatDate(r.finished_at)}</span>}
                      {canCancel && (r.status === 'running' || r.status === 'queued') && (
                        <button
                          className="btn-ghost px-2 py-1 text-xs text-rose-600 hover:bg-rose-50"
                          disabled={cancelMut.isPending}
                          onClick={(e) => {
                            e.stopPropagation()
                            cancelMut.mutate(r.id)
                          }}
                        >
                          <XCircle className="h-3.5 w-3.5" /> Cancel run
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
