// Shared table of async report jobs: status, artifact, webhook delivery.
// Used by the global Reports page and the per-task Reports tab.

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, Trash2, Webhook } from 'lucide-react'
import { Link } from 'react-router-dom'
import { reportApi, downloadFile } from '@/api/client'
import type { ReportJob } from '@/api/types'
import { formatBytes, relativeTime } from '@/utils/format'

const STATUS_STYLES: Record<string, string> = {
  waiting: 'bg-slate-100 text-slate-600',
  in_progress: 'bg-blue-50 text-blue-600',
  finished: 'bg-emerald-50 text-emerald-600',
  failed: 'bg-rose-50 text-rose-600',
}

function statusLabel(s: string) {
  return s === 'in_progress' ? 'rendering' : s
}

export function ReportJobStatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${
        STATUS_STYLES[status] ?? 'bg-slate-100 text-slate-600'
      }`}
    >
      {status === 'waiting' || status === 'in_progress' ? (
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" />
      ) : null}
      {statusLabel(status)}
    </span>
  )
}

export function ReportJobsTable({
  jobs,
  showTask = true,
}: {
  jobs: ReportJob[]
  showTask?: boolean
}) {
  const qc = useQueryClient()

  const remove = useMutation({
    mutationFn: (id: string) => reportApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['reports'] })
      qc.invalidateQueries({ queryKey: ['task-reports'] })
    },
  })

  async function download(job: ReportJob) {
    if (!job.download_path) return
    await downloadFile(
      job.download_path,
      `secuscan-report-${job.task_id.slice(0, 8)}.${job.format}`,
    )
  }

  if (jobs.length === 0) {
    return (
      <p className="px-4 py-8 text-center text-sm text-slate-500">
        No report jobs yet.
      </p>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead>
          <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
            {showTask && <th className="px-4 py-2.5 font-medium">Task</th>}
            <th className="px-4 py-2.5 font-medium">Format</th>
            <th className="px-4 py-2.5 font-medium">Status</th>
            <th className="px-4 py-2.5 font-medium">Severity</th>
            <th className="px-4 py-2.5 font-medium">Size</th>
            <th className="px-4 py-2.5 font-medium">Webhook</th>
            <th className="px-4 py-2.5 font-medium">Created</th>
            <th className="px-4 py-2.5 font-medium" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {jobs.map((j) => (
            <tr key={j.id} className="hover:bg-slate-50/60">
              {showTask && (
                <td className="px-4 py-2.5">
                  <Link
                    to={`/tasks/${j.task_id}`}
                    className="font-mono text-xs text-brand-600 hover:underline"
                    title={j.task_id}
                  >
                    {j.task_id.slice(0, 8)}…
                  </Link>
                </td>
              )}
              <td className="px-4 py-2.5">
                <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-600">
                  {j.format}
                </span>
              </td>
              <td className="px-4 py-2.5">
                <div className="flex flex-col gap-0.5">
                  <ReportJobStatusBadge status={j.status} />
                  {j.status === 'failed' && j.error && (
                    <span className="max-w-xs truncate text-xs text-rose-500" title={j.error}>
                      {j.error}
                    </span>
                  )}
                </div>
              </td>
              <td className="px-4 py-2.5 text-slate-500">
                {j.severity_filter ? `${j.severity_filter}+` : 'all'}
              </td>
              <td className="px-4 py-2.5 text-slate-500">
                {j.file_bytes != null ? formatBytes(j.file_bytes) : '—'}
              </td>
              <td className="px-4 py-2.5">
                {j.webhook_url ? (
                  <span
                    className="inline-flex items-center gap-1 text-xs text-slate-500"
                    title={j.webhook_url}
                  >
                    <Webhook className="h-3.5 w-3.5" />
                    {j.webhook_attempts} attempt{j.webhook_attempts === 1 ? '' : 's'}
                  </span>
                ) : (
                  <span className="text-xs text-slate-300">—</span>
                )}
              </td>
              <td className="px-4 py-2.5 text-slate-500">{relativeTime(j.created_at)}</td>
              <td className="px-4 py-2.5 text-right">
                <div className="inline-flex gap-1">
                  {j.status === 'finished' && j.download_path && (
                    <button
                      className="rounded p-1.5 text-slate-400 transition-colors hover:bg-brand-50 hover:text-brand-600"
                      title="Download artifact"
                      onClick={() => void download(j)}
                    >
                      <Download className="h-4 w-4" />
                    </button>
                  )}
                  <button
                    className="rounded p-1.5 text-slate-400 transition-colors hover:bg-rose-50 hover:text-rose-600"
                    title="Delete job and artifact"
                    onClick={() => remove.mutate(j.id)}
                    disabled={remove.isPending && remove.variables === j.id}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
