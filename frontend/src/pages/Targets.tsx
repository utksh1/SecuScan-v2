// Targets: registered assets of the current workspace (pentest-tools.com
// style asset registry). Registered targets can be quick-launched into a
// scan; per-target scan counts and last-scanned times surface scan health.

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Crosshair, Plus, Trash2, Pencil, Play, Layers } from 'lucide-react'
import { workspaceApi } from '@/api/client'
import type { ScanTarget } from '@/api/types'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { useWorkspace } from '@/auth/WorkspaceContext'
import { formatDate, cn } from '@/utils/format'

const KIND_LABEL: Record<string, string> = {
  hostname: 'Hostname',
  ip_address: 'IP address',
  url: 'URL',
}

function KindBadge({ kind }: { kind: string }) {
  return (
    <span
      className={cn(
        'rounded-full px-2 py-0.5 text-[11px] font-medium',
        kind === 'url' && 'bg-sky-100 text-sky-700',
        kind === 'ip_address' && 'bg-violet-100 text-violet-700',
        kind === 'hostname' && 'bg-emerald-100 text-emerald-700',
      )}
    >
      {KIND_LABEL[kind] ?? kind}
    </span>
  )
}

export function TargetsPage() {
  const { current, workspaces, selected, select } = useWorkspace()
  const { user } = useAuth()
  const qc = useQueryClient()
  const canMutate = user?.role === 'admin' || user?.role === 'scanner'
  const isPersonal = selected === 'personal'

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [editing, setEditing] = useState<ScanTarget | null>(null)
  const [editName, setEditName] = useState('')
  const [editDescription, setEditDescription] = useState('')
  const [actionError, setActionError] = useState<string | null>(null)
  const [newWsName, setNewWsName] = useState('')
  const [wsError, setWsError] = useState<string | null>(null)

  // Targets of the selected workspace (Personal has none by definition).
  const targetsQuery = useQuery({
    queryKey: ['targets', selected],
    queryFn: () => workspaceApi.targets(current!.id),
    enabled: !isPersonal && !!current,
  })

  const onError = (err: Error) => setActionError(err.message)

  const addTarget = useMutation({
    mutationFn: () => workspaceApi.createTarget(current!.id, name.trim(), description.trim()),
    onSuccess: () => {
      setName('')
      setDescription('')
      setFormError(null)
      qc.invalidateQueries({ queryKey: ['targets'] })
      qc.invalidateQueries({ queryKey: ['workspaces'] })
    },
    onError: (err: Error) => setFormError(err.message),
  })

  const updateTarget = useMutation({
    mutationFn: (t: ScanTarget) =>
      workspaceApi.updateTarget(t.id, {
        name: editName.trim(),
        description: editDescription.trim(),
      }),
    onSuccess: () => {
      setEditing(null)
      qc.invalidateQueries({ queryKey: ['targets'] })
    },
    onError,
  })

  const deleteTarget = useMutation({
    mutationFn: (id: string) => workspaceApi.removeTarget(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      qc.invalidateQueries({ queryKey: ['workspaces'] })
    },
    onError,
  })

  const createWorkspace = useMutation({
    mutationFn: () => workspaceApi.create(newWsName.trim(), ''),
    onSuccess: () => {
      setNewWsName('')
      setWsError(null)
      qc.invalidateQueries({ queryKey: ['workspaces'] })
    },
    onError: (err: Error) => setWsError(err.message),
  })

  const deleteWorkspace = useMutation({
    mutationFn: (id: string) => workspaceApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workspaces'] }),
    onError,
  })

  if (isPersonal) {
    return (
      <div className="mx-auto max-w-3xl space-y-6">
        <div className="card p-6">
          <h2 className="flex items-center gap-2 text-base font-semibold text-slate-800">
            <Layers className="h-4 w-4 text-brand-600" />
            Personal scope
          </h2>
          <p className="mt-2 text-sm text-slate-500">
            Ad-hoc scans without a workspace live in your Personal scope. Targets are a
            workspace concept — switch to a workspace (or create one below) to register
            assets and track their scan history.
          </p>
          <div className="mt-4 space-y-3">
            <div className="text-xs font-medium uppercase tracking-wide text-slate-400">
              Workspaces ({workspaces.length})
            </div>
            {workspaces.map((w) => (
              <div
                key={w.id}
                className="flex items-center justify-between rounded-lg border border-slate-200 px-4 py-3"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-slate-800">{w.name}</div>
                  <div className="text-xs text-slate-500">
                    {w.targets_total} targets · {w.tasks_total} tasks
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    className="btn-secondary"
                    onClick={() => select(w.id)}
                  >
                    Open
                  </button>
                  {user?.role === 'admin' && (
                    <button
                      className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-red-50 hover:text-red-600"
                      title="Delete workspace"
                      onClick={() => {
                        if (confirm(`Delete workspace "${w.name}"? Its tasks move to the Personal scope; registered targets are removed.`))
                          deleteWorkspace.mutate(w.id)
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
            {canMutate && (
              <form
                className="flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault()
                  if (newWsName.trim()) createWorkspace.mutate()
                }}
              >
                <input
                  className="input"
                  placeholder="New workspace name…"
                  value={newWsName}
                  onChange={(e) => setNewWsName(e.target.value)}
                  maxLength={100}
                />
                <button className="btn-primary shrink-0" type="submit" disabled={!newWsName.trim()}>
                  <Plus className="mr-1 h-4 w-4" /> Create
                </button>
              </form>
            )}
            {wsError && <ErrorNote message={wsError} />}
          </div>
        </div>
      </div>
    )
  }

  if (targetsQuery.isLoading) return <Spinner label="Loading targets…" />
  if (targetsQuery.error)
    return (
      <ErrorNote
        message={targetsQuery.error instanceof Error ? targetsQuery.error.message : 'Failed to load'}
      />
    )

  const targets = targetsQuery.data?.items ?? []

  return (
    <div className="space-y-4">
      {actionError && <ErrorNote message={actionError} />}

      {canMutate && (
        <form
          className="card flex flex-wrap items-start gap-3 p-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (!name.trim()) return setFormError('Target name is required')
            addTarget.mutate()
          }}
        >
          <div className="min-w-[240px] flex-1">
            <label className="mb-1 block text-xs font-medium text-slate-600" htmlFor="target-name">
              Register a target
            </label>
            <input
              id="target-name"
              className="input"
              placeholder="example.com · 192.168.1.10 · https://app.example.com"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={255}
            />
          </div>
          <div className="min-w-[200px] flex-1">
            <label className="mb-1 block text-xs font-medium text-slate-600" htmlFor="target-desc">
              Description <span className="text-slate-400">(optional)</span>
            </label>
            <input
              id="target-desc"
              className="input"
              placeholder="Production web tier…"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={2000}
            />
          </div>
          <button className="btn-primary mt-6 shrink-0" type="submit" disabled={addTarget.isPending}>
            <Plus className="mr-1 h-4 w-4" /> Add target
          </button>
          {formError && <div className="w-full"><ErrorNote message={formError} /></div>}
        </form>
      )}

      {targets.length === 0 ? (
        <EmptyState
          icon={<Crosshair className="h-10 w-10 text-slate-300" />}
          title="No targets registered"
          description="Register assets you scan regularly — hosts, IPs, URLs — to track their scan history in this workspace."
          action={
            canMutate ? (
              <Link className="btn-primary" to="/tasks/new">
                Run an ad-hoc scan instead
              </Link>
            ) : undefined
          }
        />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">Kind</th>
                <th className="px-4 py-3 font-medium">Scans</th>
                <th className="px-4 py-3 font-medium">Last scanned</th>
                <th className="px-4 py-3 font-medium">Added</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/60">
                  <td className="px-4 py-3">
                    {editing?.id === t.id ? (
                      <input
                        className="input"
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        maxLength={255}
                      />
                    ) : (
                      <div>
                        <div className="font-medium text-slate-800">{t.name}</div>
                        {t.description && (
                          <div className="text-xs text-slate-500">{t.description}</div>
                        )}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {editing?.id === t.id ? (
                      <span className="text-xs text-slate-400">re-derived on save</span>
                    ) : (
                      <KindBadge kind={t.kind} />
                    )}
                  </td>
                  <td className="px-4 py-3 text-slate-600">{t.scans_total}</td>
                  <td className="px-4 py-3 text-slate-600">
                    {t.last_scanned_at ? formatDate(t.last_scanned_at) : '—'}
                  </td>
                  <td className="px-4 py-3 text-slate-500">{formatDate(t.created_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <Link
                        to={`/tasks/new?target=${encodeURIComponent(t.name)}`}
                        className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-brand-50 hover:text-brand-600"
                        title="Scan this target"
                      >
                        <Play className="h-4 w-4" />
                      </Link>
                      {canMutate && (
                        <>
                          <button
                            className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700"
                            title="Edit"
                            onClick={() => {
                              setEditing(t)
                              setEditName(t.name)
                              setEditDescription(t.description)
                              setActionError(null)
                            }}
                          >
                            <Pencil className="h-4 w-4" />
                          </button>
                          <button
                            className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-red-50 hover:text-red-600"
                            title="Delete"
                            onClick={() => {
                              if (confirm(`Delete target "${t.name}"?`))
                                deleteTarget.mutate(t.id)
                            }}
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Inline edit row actions rendered as a footer bar when editing */}
      {editing && (
        <div className="card flex flex-wrap items-end gap-3 p-4">
          <div className="min-w-[240px] flex-1">
            <label className="mb-1 block text-xs font-medium text-slate-600">Description</label>
            <input
              className="input"
              value={editDescription}
              onChange={(e) => setEditDescription(e.target.value)}
              maxLength={2000}
            />
          </div>
          <button
            className="btn-primary"
            onClick={() => updateTarget.mutate(editing)}
            disabled={!editName.trim() || updateTarget.isPending}
          >
            Save changes
          </button>
          <button className="btn-secondary" onClick={() => setEditing(null)}>
            Cancel
          </button>
        </div>
      )}
    </div>
  )
}
