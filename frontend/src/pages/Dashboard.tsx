import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  CirclePlus,
  ShieldAlert,
  ListChecks,
  Blocks,
  Activity,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react'
import { request } from '@/api/client'
import type { DashboardSummary } from '@/api/types'
import { StatusBadge } from '@/components/StatusBadge'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { relativeTime, SEVERITY_ORDER, SEVERITY_DOT } from '@/utils/format'
import { useWorkspace } from '@/auth/WorkspaceContext'

export function DashboardPage() {
  const { scopeParam } = useWorkspace()
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', scopeParam],
    queryFn: () =>
      request<DashboardSummary>(`/dashboard/summary?workspace_id=${scopeParam}`),
    refetchInterval: 10_000,
  })

  if (isLoading) return <Spinner label="Loading dashboard…" />
  if (error) return <ErrorNote message={error instanceof Error ? error.message : 'Failed to load'} />
  if (!data) return null

  const sevTotal =
    data.findings.critical +
    data.findings.high +
    data.findings.medium +
    data.findings.low +
    data.findings.info

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={<ListChecks className="h-5 w-5" />}
          label="Total tasks"
          value={data.tasks.total}
          sub={`${data.tasks.running} running · ${data.tasks.queued} queued`}
          to="/tasks"
        />
        <StatCard
          icon={<ShieldAlert className="h-5 w-5" />}
          label="Critical + High"
          value={data.findings.critical + data.findings.high}
          sub={`${data.findings.new} awaiting triage`}
          tone={data.findings.critical + data.findings.high > 0 ? 'danger' : 'ok'}
          to="/findings?severity=critical&severity=high"
        />
        <StatCard
          icon={<Blocks className="h-5 w-5" />}
          label="Scanners available"
          value={`${data.plugins.available}/${data.plugins.total}`}
          sub={`${data.plugins.enabled} enabled`}
          to="/scanners"
        />
        <StatCard
          icon={<Activity className="h-5 w-5" />}
          label="Findings total"
          value={sevTotal}
          sub={`${data.workflows_total} workflow(s) · ${data.users_total} user(s)`}
          to="/findings"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Severity distribution */}
        <div className="card p-5">
          <h2 className="mb-4 text-sm font-semibold text-slate-700">Findings by severity</h2>
          {sevTotal === 0 ? (
            <p className="py-6 text-center text-sm text-slate-400">
              No findings yet — run your first scan.
            </p>
          ) : (
            <div className="space-y-2.5">
              {SEVERITY_ORDER.map((sev) => {
                const value =
                  data.findings[sev as keyof typeof data.findings] as number
                const pct = sevTotal > 0 ? Math.round((value / sevTotal) * 100) : 0
                return (
                  <div key={sev} className="flex items-center gap-3">
                    <span className={`h-2.5 w-2.5 rounded-full ${SEVERITY_DOT[sev]}`} />
                    <span className="w-16 text-xs capitalize text-slate-600">{sev}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
                      <div
                        className={`h-full rounded-full ${SEVERITY_DOT[sev]}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="w-8 text-right text-xs font-semibold text-slate-700">
                      {value}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Recent tasks */}
        <div className="card xl:col-span-2">
          <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
            <h2 className="text-sm font-semibold text-slate-700">Recent tasks</h2>
            <Link to="/tasks" className="btn-ghost text-xs">
              View all <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
          {data.recent_tasks.length === 0 ? (
            <div className="p-5">
              <EmptyState
                icon={<ShieldCheck className="h-8 w-8" />}
                title="No tasks yet"
                description="Start your first scan from the scanner catalog."
                action={
                  <Link to="/tasks/new" className="btn-primary">
                    <CirclePlus className="h-4 w-4" /> New task
                  </Link>
                }
              />
            </div>
          ) : (
            <table className="w-full">
              <thead className="border-b border-slate-100 bg-slate-50/60">
                <tr>
                  <th className="th">Scanner</th>
                  <th className="th">Target</th>
                  <th className="th">Status</th>
                  <th className="th">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.recent_tasks.map((t) => (
                  <tr key={t.id} className="transition-colors hover:bg-slate-50">
                    <td className="td">
                      <Link to={`/tasks/${t.id}`} className="font-medium text-brand-700 hover:underline">
                        {t.plugin_name}
                      </Link>
                    </td>
                    <td className="td max-w-[220px] truncate font-mono text-xs text-slate-500">
                      {t.target ?? '—'}
                    </td>
                    <td className="td">
                      <StatusBadge status={t.status} />
                    </td>
                    <td className="td text-xs text-slate-500">{relativeTime(t.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Severity legend strip for latest findings */}
      {data.findings.new > 0 && (
        <Link
          to="/findings?analyst_status=new"
          className="card flex items-center justify-between border-amber-200 bg-amber-50/70 px-5 py-4 transition-colors hover:bg-amber-50"
        >
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-amber-600" />
            <div>
              <div className="text-sm font-semibold text-amber-900">
                {data.findings.new} finding(s) awaiting triage
              </div>
              <div className="text-xs text-amber-700">
                Review and classify them as confirmed, false positive, or accepted risk.
              </div>
            </div>
          </div>
          <ArrowRight className="h-4 w-4 text-amber-600" />
        </Link>
      )}
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  sub,
  to,
  tone = 'default',
}: {
  icon: React.ReactNode
  label: string
  value: React.ReactNode
  sub?: string
  to?: string
  tone?: 'default' | 'danger' | 'ok'
}) {
  const inner = (
    <div className="card flex items-center gap-4 p-5 transition-shadow hover:shadow-md">
      <span
        className={
          tone === 'danger'
            ? 'flex h-11 w-11 items-center justify-center rounded-lg bg-rose-50 text-rose-600'
            : tone === 'ok'
              ? 'flex h-11 w-11 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600'
              : 'flex h-11 w-11 items-center justify-center rounded-lg bg-brand-50 text-brand-600'
        }
      >
        {icon}
      </span>
      <div className="min-w-0">
        <div className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</div>
        <div className="text-2xl font-semibold tracking-tight text-slate-800">{value}</div>
        {sub && <div className="truncate text-xs text-slate-400">{sub}</div>}
      </div>
    </div>
  )
  return to ? (
    <Link to={to} className="block">
      {inner}
    </Link>
  ) : (
    inner
  )
}
