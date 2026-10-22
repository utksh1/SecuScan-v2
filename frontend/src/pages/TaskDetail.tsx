import { useEffect, useRef, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Ban,
  RotateCcw,
  Download,
  Terminal,
  ShieldAlert,
  FileText,
  ChevronRight,
} from 'lucide-react'
import { request, downloadFile } from '@/api/client'
import { streamTaskEvents, type TaskStreamEvent } from '@/api/sse'
import type { Task, Finding } from '@/api/types'
import { StatusBadge } from '@/components/StatusBadge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { Spinner, ErrorNote } from '@/components/ui'
import { formatDate, formatDuration, cn } from '@/utils/format'
import { useAuth } from '@/auth/AuthContext'

type Tab = 'console' | 'findings' | 'output'

export function TaskDetailPage() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const { user } = useAuth()
  const [tab, setTab] = useState<Tab>('console')
  const [events, setEvents] = useState<TaskStreamEvent[]>([])
  const [streamError, setStreamError] = useState<string | null>(null)
  const consoleRef = useRef<HTMLDivElement>(null)

  const { data: task, isLoading, error } = useQuery({
    queryKey: ['task', id],
    queryFn: () => request<Task>(`/tasks/${id}`),
    refetchInterval: (query) =>
      query.state.data && (query.state.data.status === 'running' || query.state.data.status === 'queued')
        ? 1500
        : false,
  })

  const { data: findings } = useQuery({
    queryKey: ['task-findings', id],
    queryFn: () => request<{ items: Finding[] }>(`/findings?task_id=${id}&limit=1000`),
  })

  const { data: output } = useQuery({
    queryKey: ['task-output', id],
    queryFn: () => request<{ output: string; truncated: boolean }>(`/tasks/${id}/output`),
    enabled: tab === 'output',
  })

  // Live SSE console.
  useEffect(() => {
    if (!task) return
    if (task.status !== 'running' && task.status !== 'queued') return
    setEvents([])
    const handle = streamTaskEvents(
      id,
      (evt) => setEvents((prev) => [...prev.slice(-2000), evt]),
      () => qc.invalidateQueries({ queryKey: ['task', id] }),
    )
    handle.done.catch((err) => setStreamError(err instanceof Error ? err.message : 'stream error'))
    return () => handle.abort()
  }, [id, task?.status]) // eslint-disable-line react-hooks/exhaustive-deps

  // Autoscroll the console.
  useEffect(() => {
    consoleRef.current?.scrollTo({ top: consoleRef.current.scrollHeight })
  }, [events])

  async function cancel() {
    await request(`/tasks/${id}/cancel`, { method: 'POST' })
    qc.invalidateQueries({ queryKey: ['task', id] })
  }
  async function retry() {
    const t = await request<Task>(`/tasks/${id}/retry`, { method: 'POST' })
    window.location.assign(`/tasks/${t.id}`)
  }
  async function download(format: string) {
    await downloadFile(`/tasks/${id}/report/${format}`, `secuscan-report-${id.slice(0, 8)}.${format}`)
  }

  if (isLoading) return <Spinner label="Loading task…" />
  if (error || !task)
    return <ErrorNote message={error instanceof Error ? error.message : 'Task not found'} />

  const active = task.status === 'running' || task.status === 'queued'
  const canCancel = active && (user?.role === 'admin' || user?.role === 'scanner')

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="text-lg font-semibold text-slate-800">{task.plugin_name}</h2>
              <StatusBadge status={task.status} />
              {task.workflow_run_id && (
                <Link
                  to="/workflows"
                  className="chip bg-violet-50 text-violet-600 hover:bg-violet-100"
                >
                  workflow task
                </Link>
              )}
            </div>
            <div className="mt-1.5 space-x-4 text-sm text-slate-500">
              <span>
                Target: <code className="font-mono text-slate-700">{task.target ?? '—'}</code>
              </span>
              <span>Created {formatDate(task.created_at)}</span>
              {!active && (
                <span>
                  Duration {formatDuration(task.stats?.duration_ms)}
                  {task.exit_code != null && ` · exit ${task.exit_code}`}
                </span>
              )}
            </div>
            {task.error && (
              <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700">
                {task.error}
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {canCancel && (
              <button className="btn-danger" onClick={cancel}>
                <Ban className="h-4 w-4" /> Cancel
              </button>
            )}
            {!active && (user?.role === 'admin' || user?.role === 'scanner') && (
              <button className="btn-secondary" onClick={retry}>
                <RotateCcw className="h-4 w-4" /> Retry
              </button>
            )}
            <div className="group relative">
              <button className="btn-secondary">
                <Download className="h-4 w-4" /> Report
              </button>
              <div className="invisible absolute right-0 z-10 mt-1 w-36 rounded-lg border border-slate-200 bg-white py-1 opacity-0 shadow-lg transition-all group-hover:visible group-hover:opacity-100">
                {['md', 'html', 'csv', 'sarif', 'json'].map((f) => (
                  <button
                    key={f}
                    className="block w-full px-4 py-1.5 text-left text-sm text-slate-600 hover:bg-slate-50"
                    onClick={() => download(f)}
                  >
                    .{f}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Findings" value={task.stats?.findings ?? findings?.items.length ?? 0} />
        <Stat label="Duration" value={formatDuration(task.stats?.duration_ms)} />
        <Stat label="Exit code" value={task.exit_code ?? '—'} />
        <Stat
          label="Tool warnings"
          value={task.stats?.tool_exit_nonzero ? 'non-zero exit' : 'none'}
        />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-slate-200">
        <TabButton active={tab === 'console'} onClick={() => setTab('console')} icon={<Terminal className="h-4 w-4" />}>
          Console {events.length > 0 && <span className="text-xs text-slate-400">({events.length})</span>}
        </TabButton>
        <TabButton
          active={tab === 'findings'}
          onClick={() => setTab('findings')}
          icon={<ShieldAlert className="h-4 w-4" />}
        >
          Findings {findings && <span className="text-xs text-slate-400">({findings.items.length})</span>}
        </TabButton>
        <TabButton active={tab === 'output'} onClick={() => setTab('output')} icon={<FileText className="h-4 w-4" />}>
          Raw output
        </TabButton>
      </div>

      {/* Console */}
      {tab === 'console' && (
        <div className="card overflow-hidden">
          {streamError && (
            <div className="border-b border-slate-800 bg-slate-900 px-4 py-2 font-mono text-xs text-amber-400">
              live stream error: {streamError}
            </div>
          )}
          <div
            ref={consoleRef}
            className="console-scroll h-[480px] overflow-y-auto bg-slate-900 p-4 font-mono text-xs leading-relaxed"
            data-testid="task-console"
          >
            {events.length === 0 && !active && (
              <div className="text-slate-500">
                No live events recorded (task already finished when the page opened).
              </div>
            )}
            {events.map((e, i) => (
              <ConsoleLine key={`${e.id}-${i}`} evt={e} />
            ))}
            {active && (
              <span className="inline-block h-3.5 w-2 animate-pulse bg-brand-400 align-middle" />
            )}
          </div>
        </div>
      )}

      {/* Findings */}
      {tab === 'findings' && (
        <div className="space-y-2">
          {(findings?.items ?? []).length === 0 ? (
            <div className="card p-8 text-center text-sm text-slate-400">
              No findings produced by this task.
            </div>
          ) : (
            (findings?.items ?? []).map((f) => <FindingRow key={f.id} finding={f} />)
          )}
        </div>
      )}

      {/* Raw output */}
      {tab === 'output' && (
        <div className="card overflow-hidden">
          <pre className="console-scroll max-h-[560px] overflow-auto bg-slate-50 p-4 font-mono text-xs leading-relaxed text-slate-700">
            {output?.output || '(no output captured)'}
          </pre>
          {output?.truncated && (
            <div className="border-t border-slate-200 bg-amber-50 px-4 py-2 text-xs text-amber-700">
              Output was truncated at the capture limit.
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="card p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-0.5 text-lg font-semibold text-slate-800">{value}</div>
    </div>
  )
}

function TabButton({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        '-mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors',
        active
          ? 'border-brand-600 text-brand-700'
          : 'border-transparent text-slate-500 hover:text-slate-700',
      )}
    >
      {icon}
      {children}
    </button>
  )
}

function ConsoleLine({ evt }: { evt: TaskStreamEvent }) {
  const e = evt.event as Record<string, string & { phase?: string; line?: string; message?: string }>
  const time = evt.ts ? evt.ts.slice(11, 19) : ''
  let cls = 'text-slate-300'
  let text = ''
  switch (e.type) {
    case 'phase':
      cls = 'text-brand-400 font-semibold'
      text = `— phase: ${e.phase} —`
      break
    case 'log_line':
      cls = e.stream === 'stderr' ? 'text-amber-300/90' : 'text-slate-300'
      text = e.line
      break
    case 'info':
      cls = 'text-slate-400'
      text = `ℹ ${e.message}`
      break
    case 'warn':
      cls = 'text-amber-400'
      text = `⚠ ${e.message}`
      break
    case 'error':
      cls = 'text-rose-400'
      text = `✖ ${e.message}`
      break
    case 'progress':
      cls = 'text-sky-400'
      text = `[${e.done}/${e.total}] ${e.message}`
      break
    case 'finished':
      cls = 'text-emerald-400 font-semibold'
      text = `— finished: ${e.status} —`
      break
    default:
      text = JSON.stringify(e)
  }
  return (
    <div className="flex gap-3">
      <span className="shrink-0 text-slate-600">{time}</span>
      <span className={cn('whitespace-pre-wrap break-all', cls)}>{text}</span>
    </div>
  )
}

export function FindingRow({ finding: f }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="card overflow-hidden">
      <button
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50"
        onClick={() => setOpen((o) => !o)}
      >
        <ChevronRight
          className={cn('h-4 w-4 shrink-0 text-slate-400 transition-transform', open && 'rotate-90')}
        />
        <SeverityBadge severity={f.severity} />
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-slate-700">
          {f.title}
        </span>
        <span className="hidden shrink-0 text-xs text-slate-400 sm:block">{f.category}</span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-slate-100 bg-slate-50/60 px-4 py-4 text-sm">
          {f.description && (
            <div>
              <div className="mb-0.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
                Description
              </div>
              <p className="text-slate-600">{f.description}</p>
            </div>
          )}
          {f.proof && (
            <div>
              <div className="mb-0.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
                Evidence
              </div>
              <pre className="overflow-x-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-200">
                {f.proof}
              </pre>
            </div>
          )}
          {f.url && (
            <div className="text-xs text-slate-500">
              URL: <span className="font-mono">{f.url}</span>
            </div>
          )}
          {f.remediation && (
            <div>
              <div className="mb-0.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
                Remediation
              </div>
              <p className="text-slate-600">{f.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
