import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Play, Trash2, Plus, X } from 'lucide-react'
import { request } from '@/api/client'
import type { Workflow, WorkflowRun, WorkflowStep, Plugin } from '@/api/types'
import { StatusBadge } from '@/components/StatusBadge'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { formatDate } from '@/utils/format'
import { useAuth } from '@/auth/AuthContext'

export function WorkflowsPage() {
  const qc = useQueryClient()
  const { user } = useAuth()
  const [creating, setCreating] = useState(false)

  const { data, isLoading, error } = useQuery({
    queryKey: ['workflows'],
    queryFn: () => request<{ items: Workflow[] }>('/workflows'),
  })

  const runMut = useMutation({
    mutationFn: (id: string) => request(`/workflows/${id}/run`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workflows'] }),
  })
  const cancelRunMut = useMutation({
    mutationFn: (runId: string) =>
      request(`/workflows/runs/${runId}/cancel`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workflow-runs'] }),
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => request(`/workflows/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workflows'] }),
  })

  const canEdit = user?.role === 'admin' || user?.role === 'scanner'

  if (isLoading) return <Spinner label="Loading workflows…" />
  if (error) return <ErrorNote message={error instanceof Error ? error.message : 'Failed to load'} />

  const workflows = data?.items ?? []

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500">
          Chains of scanners executed in order — a failed step stops the run.
        </p>
        {canEdit && (
          <button className="btn-primary" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" /> New workflow
          </button>
        )}
      </div>

      {workflows.length === 0 ? (
        <EmptyState
          title="No workflows yet"
          description="Create a workflow to chain scanners, e.g. recon → port scan → headers."
        />
      ) : (
        <div className="space-y-4">
          {workflows.map((w) => (
            <WorkflowCard
              key={w.id}
              workflow={w}
              canRun={canEdit}
              onRun={() => runMut.mutate(w.id)}
              onDelete={() => deleteMut.mutate(w.id)}
              onCancelRun={(runId) => cancelRunMut.mutate(runId)}
              running={runMut.isPending && runMut.variables === w.id}
            />
          ))}
        </div>
      )}

      {creating && <CreateWorkflowModal onClose={() => setCreating(false)} />}
    </div>
  )
}

function WorkflowCard({
  workflow: w,
  canRun,
  onRun,
  onDelete,
  onCancelRun,
  running,
}: {
  workflow: Workflow
  canRun: boolean
  onRun: () => void
  onDelete: () => void
  onCancelRun: (runId: string) => void
  running: boolean
}) {
  const { data: runs } = useQuery({
    queryKey: ['workflow-runs', w.id],
    queryFn: () => request<{ items: WorkflowRun[] }>(`/workflows/${w.id}/runs`),
    refetchInterval: (q) => {
      const items = q.state.data?.items ?? []
      return items.some((r) => r.status === 'running' || r.status === 'queued') ? 2000 : false
    },
  })

  return (
    <div className="card p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-800">{w.name}</h3>
          <p className="text-xs text-slate-400">{w.description || 'no description'}</p>
        </div>
        <div className="flex items-center gap-2">
          {canRun && (
            <button className="btn-primary text-xs" onClick={onRun} disabled={running}>
              <Play className="h-3.5 w-3.5" /> {running ? 'Starting…' : 'Run'}
            </button>
          )}
          <button
            className="btn-ghost px-2 py-1 text-xs text-slate-400 hover:text-rose-600"
            onClick={onDelete}
            title="Delete workflow"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Steps */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        {w.steps.map((s, i) => (
          <span key={i} className="flex items-center gap-2">
            {i > 0 && <span className="text-slate-300">→</span>}
            <span className="chip bg-slate-100 font-mono text-slate-600">
              {s.label || s.plugin_id}
            </span>
          </span>
        ))}
      </div>

      {/* Runs */}
      {(runs?.items ?? []).length > 0 && (
        <div className="mt-4 border-t border-slate-100 pt-3">
          <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Recent runs
          </div>
          <div className="space-y-1.5">
            {(runs?.items ?? []).slice(0, 5).map((r) => {
              const runActive = r.status === 'running' || r.status === 'queued'
              return (
              <div key={r.id} className="flex items-center gap-3 text-xs text-slate-500">
                <StatusBadge status={r.status} />
                <span>{formatDate(r.created_at)}</span>
                <span className="flex items-center gap-1">
                  {r.task_ids.map((tid, i) => (
                    <span key={tid} className="flex items-center gap-1">
                      {i > 0 && <span className="text-slate-300">·</span>}
                      <Link to={`/tasks/${tid}`} className="font-mono text-brand-700 hover:underline">
                        {tid.slice(0, 8)}
                      </Link>
                    </span>
                  ))}
                </span>
                {r.error && <span className="truncate text-rose-500">{r.error}</span>}
                {runActive && canRun && (
                  <button
                    className="btn-ghost ml-auto px-2 py-0.5 text-xs text-slate-500 hover:text-rose-600"
                    title="Cancel this run"
                    onClick={() => onCancelRun(r.id)}
                  >
                    Cancel
                  </button>
                )}
              </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

function CreateWorkflowModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [steps, setSteps] = useState<WorkflowStep[]>([])
  const [error, setError] = useState<string | null>(null)
  const [stepPlugin, setStepPlugin] = useState('')
  const [stepLabel, setStepLabel] = useState('')
  const [stepInputs, setStepInputs] = useState('{}')

  const { data: pluginsData } = useQuery({
    queryKey: ['plugins'],
    queryFn: () => request<{ items: Plugin[] }>('/plugins'),
  })
  const plugins = (pluginsData?.items ?? []).filter((p) => p.available && p.enabled)

  async function save() {
    setError(null)
    if (!name.trim() || steps.length === 0) {
      setError('Name and at least one step are required.')
      return
    }
    try {
      await request('/workflows', {
        method: 'POST',
        body: { name, description, steps },
      })
      qc.invalidateQueries({ queryKey: ['workflows'] })
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create workflow')
    }
  }

  function addStep() {
    if (!stepPlugin) return
    let inputs: Record<string, unknown> = {}
    try {
      inputs = stepInputs.trim() ? JSON.parse(stepInputs) : {}
    } catch {
      setError('Step inputs must be valid JSON, e.g. {"target": "127.0.0.1"}')
      return
    }
    setError(null)
    setSteps((prev) => [
      ...prev,
      { plugin_id: stepPlugin, inputs, label: stepLabel || undefined },
    ])
    setStepPlugin('')
    setStepLabel('')
    setStepInputs('{}')
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4">
      <div className="card max-h-[85vh] w-full max-w-2xl overflow-y-auto p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-slate-800">New workflow</h2>
          <button className="btn-ghost px-2" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label" htmlFor="wf-name">Name</label>
              <input
                id="wf-name"
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="lab-recon"
              />
            </div>
            <div>
              <label className="label" htmlFor="wf-desc">Description</label>
              <input
                id="wf-desc"
                className="input"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Recon then port scan"
              />
            </div>
          </div>

          {/* Step builder */}
          <div className="rounded-lg border border-slate-200 p-4">
            <div className="mb-3 text-sm font-medium text-slate-700">Add step</div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label" htmlFor="step-plugin">Scanner</label>
                <select
                  id="step-plugin"
                  className="input"
                  value={stepPlugin}
                  onChange={(e) => setStepPlugin(e.target.value)}
                >
                  <option value="">Select…</option>
                  {plugins.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label" htmlFor="step-label">Label (optional)</label>
                <input
                  id="step-label"
                  className="input"
                  value={stepLabel}
                  onChange={(e) => setStepLabel(e.target.value)}
                  placeholder="quick scan"
                />
              </div>
            </div>
            <div className="mt-3">
              <label className="label" htmlFor="step-inputs">Inputs (JSON)</label>
              <textarea
                id="step-inputs"
                className="input min-h-[64px] font-mono text-xs"
                value={stepInputs}
                onChange={(e) => setStepInputs(e.target.value)}
                placeholder='{"target": "127.0.0.1"}'
              />
            </div>
            <button className="btn-secondary mt-3 text-xs" onClick={addStep} disabled={!stepPlugin}>
              <Plus className="h-3.5 w-3.5" /> Add step
            </button>
          </div>

          {/* Steps list */}
          {steps.length > 0 && (
            <div className="space-y-1.5">
              {steps.map((s, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-lg bg-slate-50 px-3 py-2 text-sm"
                >
                  <span className="flex items-center gap-2">
                    <span className="chip bg-white font-mono text-slate-600 ring-1 ring-slate-200">
                      {i + 1}
                    </span>
                    <span className="font-medium text-slate-700">{s.label || s.plugin_id}</span>
                    <code className="text-xs text-slate-400">{JSON.stringify(s.inputs)}</code>
                  </span>
                  <button
                    className="text-slate-400 hover:text-rose-600"
                    onClick={() => setSteps((prev) => prev.filter((_, j) => j !== i))}
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {error && <ErrorNote message={error} />}

          <div className="flex justify-end gap-2">
            <button className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button className="btn-primary" onClick={save}>
              Create workflow
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
