// Per-task Reports tab: instant downloads, background job generation with
// severity filter + signed webhook callback, and this task's job history.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Zap, Webhook } from 'lucide-react'
import { reportApi, downloadFile } from '@/api/client'
import { ReportJobsTable } from '@/components/ReportJobsTable'
import { cn } from '@/utils/format'

const FORMATS = ['md', 'html', 'csv', 'sarif', 'json', 'pdf', 'docx', 'xlsx'] as const
const SEVERITIES = [
  { value: '', label: 'All findings' },
  { value: 'low', label: 'Low and above' },
  { value: 'medium', label: 'Medium and above' },
  { value: 'high', label: 'High and above' },
  { value: 'critical', label: 'Critical only' },
]

export function TaskReportsPanel({ taskId }: { taskId: string }) {
  const qc = useQueryClient()
  const [format, setFormat] = useState<string>('pdf')
  const [severity, setSeverity] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [webhookSecret, setWebhookSecret] = useState('')
  const [showWebhook, setShowWebhook] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const jobsQuery = useQuery({
    queryKey: ['task-reports', taskId],
    queryFn: () => reportApi.list({ task_id: taskId }),
    refetchInterval: (query) => {
      const active = query.state.data?.items.some(
        (j) => j.status === 'waiting' || j.status === 'in_progress',
      )
      return active ? 2000 : false
    },
  })

  const createJob = useMutation({
    mutationFn: () =>
      reportApi.create(taskId, {
        format,
        severity: severity || undefined,
        webhook_url: webhookUrl.trim() || undefined,
        webhook_secret: webhookSecret || undefined,
      }),
    onSuccess: () => {
      setFormError(null)
      setWebhookSecret('')
      qc.invalidateQueries({ queryKey: ['task-reports', taskId] })
      qc.invalidateQueries({ queryKey: ['reports'] })
    },
    onError: (err) => {
      setFormError(err instanceof Error ? err.message : 'Failed to queue report job')
    },
  })

  async function instantDownload(fmt: string) {
    await downloadFile(
      `/tasks/${taskId}/report/${fmt}${severity ? `?severity=${severity}` : ''}`,
      `secuscan-report-${taskId.slice(0, 8)}.${fmt}`,
    )
  }

  return (
    <div className="space-y-4">
      {/* Instant (synchronous) downloads */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-slate-800">Instant download</h3>
        <p className="mt-0.5 text-xs text-slate-500">
          Rendered on the spot from this task's current findings
          {severity && <> — severity filter <span className="font-medium">{severity}+</span> applied</>}.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {FORMATS.map((f) => (
            <button
              key={f}
              onClick={() => void instantDownload(f)}
              className="btn-secondary !px-3 !py-1.5 font-mono text-xs"
            >
              <Download className="h-3.5 w-3.5" /> .{f}
            </button>
          ))}
        </div>
      </div>

      {/* Background job generation */}
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-slate-800">Generate in background</h3>
        <p className="mt-0.5 text-xs text-slate-500">
          Queues a report job (waiting → rendering → finished) — useful for large
          result sets or when you want a webhook notification on completion.
        </p>
        <form
          className="mt-3 flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            createJob.mutate()
          }}
        >
          <label className="flex flex-col gap-1 text-xs text-slate-500">
            Format
            <select
              className="input !w-32"
              value={format}
              onChange={(e) => setFormat(e.target.value)}
            >
              {FORMATS.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-500">
            Severity filter
            <select
              className="input !w-40"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {SEVERITIES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className={cn('btn-secondary !py-2 text-xs', showWebhook && 'text-brand-600')}
            onClick={() => setShowWebhook((v) => !v)}
          >
            <Webhook className="h-3.5 w-3.5" />
            Webhook {showWebhook ? 'on' : 'off'}
          </button>
          <button
            type="submit"
            className="btn-primary !py-2 text-xs"
            disabled={createJob.isPending}
          >
            <Zap className="h-3.5 w-3.5" />
            {createJob.isPending ? 'Queueing…' : 'Queue report job'}
          </button>
        </form>

        {showWebhook && (
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1 text-xs text-slate-500">
              Callback URL (https://…)
              <input
                className="input"
                type="url"
                placeholder="https://example.com/hooks/secuscan"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-500">
              Signing secret (HMAC-SHA256, sent as X-SecuScan-Signature)
              <input
                className="input"
                type="password"
                placeholder="whsec_…"
                value={webhookSecret}
                onChange={(e) => setWebhookSecret(e.target.value)}
              />
            </label>
          </div>
        )}

        {formError && (
          <p role="alert" className="mt-3 text-xs text-rose-600">
            {formError}
          </p>
        )}
      </div>

      {/* Job history */}
      <div className="card">
        <div className="border-b border-slate-100 px-5 py-3">
          <h3 className="text-sm font-semibold text-slate-800">Report jobs for this task</h3>
        </div>
        {jobsQuery.isLoading ? (
          <p className="px-4 py-8 text-center text-sm text-slate-500">Loading jobs…</p>
        ) : jobsQuery.error ? (
          <p className="px-4 py-8 text-center text-sm text-rose-600">
            {jobsQuery.error instanceof Error ? jobsQuery.error.message : 'Failed to load jobs'}
          </p>
        ) : (
          <ReportJobsTable jobs={jobsQuery.data?.items ?? []} showTask={false} />
        )}
      </div>
    </div>
  )
}
