import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { Search, Trash2, RotateCcw, Ban } from 'lucide-react'
import { request } from '@/api/client'
import type { Task, TaskStatus } from '@/api/types'
import { StatusBadge } from '@/components/StatusBadge'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { formatDate, formatDuration, cn } from '@/utils/format'

const STATUSES: (TaskStatus | 'all')[] = ['all', 'queued', 'running', 'completed', 'failed', 'cancelled']

export function TasksPage() {
  const [params, setParams] = useSearchParams()
  const qc = useQueryClient()
  const status = params.get('status') ?? 'all'
  const search = params.get('search') ?? ''

  const { data, isLoading, error } = useQuery({
    queryKey: ['tasks', status, search],
    queryFn: () =>
      request<{ items: Task[]; total: number }>('/tasks', {
        method: 'GET',
      }).then(async () => {
        // Build query string
        const qs = new URLSearchParams()
        if (status !== 'all') qs.set('status', status)
        if (search) qs.set('search', search)
        qs.set('limit', '100')
        return request<{ items: Task[]; total: number }>(`/tasks?${qs.toString()}`)
      }),
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? []
      const anyActive = items.some((t) => t.status === 'running' || t.status === 'queued')
      return anyActive ? 2000 : 10_000
    },
  })

  const cancelMut = useMutation({
    mutationFn: (id: string) => request(`/tasks/${id}/cancel`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tasks'] }),
  })
  const retryMut = useMutation({
    mutationFn: (id: string) => request(`/tasks/${id}/retry`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tasks'] }),
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => request(`/tasks/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tasks'] }),
  })

  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  if (isLoading) return <Spinner label="Loading tasks…" />
  if (error) return <ErrorNote message={error instanceof Error ? error.message : 'Failed to load'} />

  const items = data?.items ?? []

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="input pl-9"
            placeholder="Search target or scanner…"
            value={search}
            onChange={(e) => {
              const next = new URLSearchParams(params)
              if (e.target.value) next.set('search', e.target.value)
              else next.delete('search')
              setParams(next, { replace: true })
            }}
          />
        </div>
        <div className="flex gap-1.5">
          {STATUSES.map((s) => (
            <button
              key={s}
              onClick={() => {
                const next = new URLSearchParams(params)
                if (s === 'all') next.delete('status')
                else next.set('status', s)
                setParams(next, { replace: true })
              }}
              className={cn(
                'chip capitalize transition-colors',
                status === s
                  ? 'bg-brand-600 text-white'
                  : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50',
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {items.length === 0 ? (
        <EmptyState
          title="No tasks found"
          description="Tasks you start will appear here with live status and findings."
        />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[820px]">
            <thead className="border-b border-slate-100 bg-slate-50/60">
              <tr>
                <th className="th">Scanner</th>
                <th className="th">Target</th>
                <th className="th">Status</th>
                <th className="th">Findings</th>
                <th className="th">Created</th>
                <th className="th">Duration</th>
                <th className="th text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((t) => {
                const active = t.status === 'running' || t.status === 'queued'
                const duration = t.stats?.duration_ms
                return (
                  <tr key={t.id} className="group transition-colors hover:bg-slate-50">
                    <td className="td">
                      <Link
                        to={`/tasks/${t.id}`}
                        className="font-medium text-brand-700 hover:underline"
                      >
                        {t.plugin_name}
                      </Link>
                      {t.workflow_run_id && (
                        <span className="ml-2 chip bg-violet-50 text-violet-600">workflow</span>
                      )}
                    </td>
                    <td className="td max-w-[240px] truncate font-mono text-xs text-slate-500">
                      {t.target ?? '—'}
                    </td>
                    <td className="td">
                      <StatusBadge status={t.status} />
                    </td>
                    <td className="td font-semibold text-slate-700">
                      {t.stats?.findings ?? '—'}
                    </td>
                    <td className="td text-xs text-slate-500">{formatDate(t.created_at)}</td>
                    <td className="td text-xs text-slate-500">
                      {active ? '—' : formatDuration(duration)}
                    </td>
                    <td className="td">
                      <div className="flex items-center justify-end gap-1">
                        {active && (
                          <button
                            className="btn-ghost px-2 py-1 text-xs"
                            title="Cancel"
                            onClick={() => cancelMut.mutate(t.id)}
                          >
                            <Ban className="h-3.5 w-3.5" />
                          </button>
                        )}
                        {!active && (
                          <button
                            className="btn-ghost px-2 py-1 text-xs"
                            title="Retry"
                            onClick={() => retryMut.mutate(t.id)}
                          >
                            <RotateCcw className="h-3.5 w-3.5" />
                          </button>
                        )}
                        {!active &&
                          (confirmDelete === t.id ? (
                            <span className="flex items-center gap-1">
                              <button
                                className="btn-danger px-2 py-1 text-xs"
                                onClick={() => {
                                  deleteMut.mutate(t.id)
                                  setConfirmDelete(null)
                                }}
                              >
                                Confirm
                              </button>
                              <button
                                className="btn-ghost px-2 py-1 text-xs"
                                onClick={() => setConfirmDelete(null)}
                              >
                                No
                              </button>
                            </span>
                          ) : (
                            <button
                              className="btn-ghost px-2 py-1 text-xs text-slate-400 hover:text-rose-600"
                              title="Delete"
                              onClick={() => setConfirmDelete(t.id)}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          ))}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
