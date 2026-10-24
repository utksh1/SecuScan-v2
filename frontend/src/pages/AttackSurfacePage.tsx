import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Globe, Trash2 } from 'lucide-react'
import { request } from '@/api/client'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { useWorkspace } from '@/auth/WorkspaceContext'
import { formatDate } from '@/utils/format'

interface Asset {
  id: string
  asset_key: string
  hostname?: string
  ip_address?: string
  url?: string
  first_seen_at?: string
  last_seen_at?: string
  metadata?: Record<string, unknown>
}

export function AttackSurfacePage() {
  const { selected } = useWorkspace()
  const { user } = useAuth()
  const qc = useQueryClient()
  const canMutate = user?.role === 'admin' || user?.role === 'scanner'
  const ws = selected === 'personal' ? undefined : selected

  const list = useQuery({
    queryKey: ['attack-surface', ws],
    queryFn: () =>
      request<{ items: Asset[] }>(
        `/attack-surface${ws ? `?workspace_id=${encodeURIComponent(ws)}` : ''}`,
      ),
  })
  const summary = useQuery({
    queryKey: ['attack-surface-summary', ws],
    queryFn: () =>
      request<{
        assets: number
        technologies?: { name: string; count: number }[]
        services?: { name: string; count: number }[]
      }>(`/attack-surface/summary${ws ? `?workspace_id=${encodeURIComponent(ws)}` : ''}`),
  })
  const del = useMutation({
    mutationFn: (id: string) => request(`/attack-surface/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['attack-surface'] }),
  })

  if (list.isLoading) return <Spinner label="Loading attack surface…" />
  if (list.error) return <ErrorNote message={list.error instanceof Error ? list.error.message : 'Failed'} />

  const items = list.data?.items ?? []

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-slate-800">Attack surface</h2>
        <p className="mt-0.5 text-sm text-slate-500">
          Assets aggregated from completed scans. {summary.data?.assets ?? items.length} recorded.
        </p>
      </div>
      <div className="card overflow-hidden">
        {items.length === 0 ? (
          <EmptyState
            icon={<Globe className="h-8 w-8 text-slate-400" />}
            title="No assets yet"
            description="Run a port scan, website scan, or HTTP recon. Findings with host/IP/URL metadata land here."
          />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="th">Key</th>
                <th className="th">Host / IP</th>
                <th className="th">URL</th>
                <th className="th">Last seen</th>
                {canMutate && <th className="th" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((a) => (
                <tr key={a.id}>
                  <td className="td font-mono text-xs">{a.asset_key}</td>
                  <td className="td text-xs">{a.hostname || a.ip_address || '—'}</td>
                  <td className="td font-mono text-xs text-slate-500">{a.url || '—'}</td>
                  <td className="td text-xs text-slate-500">{a.last_seen_at ? formatDate(a.last_seen_at) : '—'}</td>
                  {canMutate && (
                    <td className="td">
                      <button className="btn-ghost p-1" onClick={() => del.mutate(a.id)} title="Remove">
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
