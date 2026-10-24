import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Radio, Plus, Trash2, Copy } from 'lucide-react'
import { request } from '@/api/client'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { formatDate } from '@/utils/format'

interface Handler {
  id: string
  name: string
  kind: string
  callback_url: string
  secret?: string
  expires_at: string
  hit_count: number
  last_hit_at?: string
}

interface Hit {
  id: string
  received_at: string
  payload: Record<string, unknown>
}

export function OobHandlersPage() {
  const { user } = useAuth()
  const qc = useQueryClient()
  const canMutate = user?.role === 'admin' || user?.role === 'scanner'
  const [name, setName] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [createdUrl, setCreatedUrl] = useState<string | null>(null)

  const list = useQuery({
    queryKey: ['oob-handlers'],
    queryFn: () => request<{ items: Handler[] }>('/oob-handlers'),
  })
  const hits = useQuery({
    queryKey: ['oob-hits', selected],
    queryFn: () => request<{ items: Hit[] }>(`/oob-handlers/${selected}/hits`),
    enabled: !!selected,
  })
  const create = useMutation({
    mutationFn: () =>
      request<Handler>('/oob-handlers', {
        method: 'POST',
        body: { name: name.trim() || 'handler', kind: 'http_logger' },
      }),
    onSuccess: (h) => {
      setName('')
      setCreatedUrl(h.callback_url)
      qc.invalidateQueries({ queryKey: ['oob-handlers'] })
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => request(`/oob-handlers/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      setSelected(null)
      qc.invalidateQueries({ queryKey: ['oob-handlers'] })
    },
  })

  if (list.isLoading) return <Spinner label="Loading handlers…" />
  if (list.error) return <ErrorNote message={list.error instanceof Error ? list.error.message : 'Failed'} />

  const items = list.data?.items ?? []

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-slate-800">OOB handlers</h2>
        <p className="mt-0.5 text-sm text-slate-500">
          Out-of-band callback URLs for blind SSRF / SQLi / XSS confirmation. Expired
          handlers stop accepting hits.
        </p>
      </div>

      {canMutate && (
        <div className="card flex flex-wrap items-end gap-2 p-4">
          <div className="min-w-[200px] flex-1">
            <label className="label">Name</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="ssrf-lab" />
          </div>
          <button className="btn-primary" onClick={() => create.mutate()}>
            <Plus className="h-4 w-4" /> Create
          </button>
        </div>
      )}
      {createdUrl && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm">
          Callback (copy now — list view hides the secret):{' '}
          <code className="font-mono text-xs">{createdUrl}</code>
          <button
            className="btn-ghost ml-2 p-1"
            onClick={() => navigator.clipboard.writeText(window.location.origin + createdUrl)}
          >
            <Copy className="h-4 w-4" />
          </button>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card overflow-hidden">
          {items.length === 0 ? (
            <EmptyState icon={<Radio className="h-8 w-8 text-slate-400" />} title="No handlers" description="Create one to get a unique /api/v1/oob/:secret URL." />
          ) : (
            <ul className="divide-y divide-slate-100">
              {items.map((h) => (
                <li key={h.id} className="flex items-center justify-between px-4 py-3">
                  <button className="text-left" onClick={() => setSelected(h.id)}>
                    <div className="text-sm font-medium text-slate-800">{h.name}</div>
                    <div className="text-xs text-slate-500">
                      {h.kind} · {h.hit_count} hits · expires {formatDate(h.expires_at)}
                    </div>
                  </button>
                  {canMutate && (
                    <button className="btn-ghost p-1" onClick={() => remove.mutate(h.id)}>
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="card p-4">
          <h3 className="mb-2 text-sm font-semibold text-slate-700">Hits</h3>
          {!selected && <p className="text-sm text-slate-400">Select a handler.</p>}
          {selected && hits.isLoading && <Spinner label="Loading hits…" />}
          {selected && (hits.data?.items ?? []).length === 0 && (
            <p className="text-sm text-slate-400">No hits yet.</p>
          )}
          <ul className="space-y-2">
            {(hits.data?.items ?? []).map((hit) => (
              <li key={hit.id} className="rounded bg-slate-50 p-2 font-mono text-xs text-slate-600">
                <div className="text-slate-400">{formatDate(hit.received_at)}</div>
                <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap">
                  {JSON.stringify(hit.payload, null, 2)}
                </pre>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}
