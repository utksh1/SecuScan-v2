// VPN Profiles: named OpenVPN configs pinned to workspaces. Scans admitted
// in a pinned workspace require the tunnel to be up (auto-connect) —
// see the admission pipeline pre-flight.

import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Network, PlugZap, Plug, Trash2, UploadCloud, ShieldQuestion } from 'lucide-react'
import { vpnApi, workspaceApi } from '@/api/client'
import type { VpnProfile, Workspace } from '@/api/types'
import { Spinner, ErrorNote, EmptyState } from '@/components/ui'
import { useAuth } from '@/auth/AuthContext'
import { useWorkspace } from '@/auth/WorkspaceContext'
import { cn, formatDate } from '@/utils/format'

function VpnStatusBadge({ status }: { status: VpnProfile['status'] }) {
  return (
    <span
      className={cn(
        'chip capitalize',
        status === 'connected' && 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200',
        status === 'connecting' && 'bg-sky-50 text-sky-700 ring-1 ring-sky-200',
        status === 'error' && 'bg-rose-50 text-rose-700 ring-1 ring-rose-200',
        status === 'disconnected' && 'bg-slate-100 text-slate-500 ring-1 ring-slate-200',
      )}
    >
      {status === 'connecting' && (
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-sky-500" aria-hidden />
      )}
      {status}
    </span>
  )
}

export function VpnPage() {
  const qc = useQueryClient()
  const { user } = useAuth()
  const { selected } = useWorkspace()
  const [name, setName] = useState('')
  const [configText, setConfigText] = useState('')
  const [formError, setFormError] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  const canManage = user?.role === 'admin' || user?.role === 'scanner'

  const { data, isLoading, error } = useQuery({
    queryKey: ['vpn-profiles'],
    queryFn: vpnApi.list,
  })
  const { data: wsData } = useQuery({
    queryKey: ['workspaces'],
    queryFn: workspaceApi.list,
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['vpn-profiles'] })
    qc.invalidateQueries({ queryKey: ['workspaces'] })
    qc.invalidateQueries({ queryKey: ['workspace-vpn'] })
  }

  const createMut = useMutation({
    mutationFn: () => vpnApi.create(name.trim(), configText),
    onSuccess: () => {
      setName('')
      setConfigText('')
      setFormError('')
      invalidate()
    },
    onError: (e) => setFormError(e instanceof Error ? e.message : 'create failed'),
  })
  const connectMut = useMutation({ mutationFn: vpnApi.connect, onSuccess: invalidate })
  const disconnectMut = useMutation({ mutationFn: vpnApi.disconnect, onSuccess: invalidate })
  const removeMut = useMutation({ mutationFn: vpnApi.remove, onSuccess: invalidate })
  const attachMut = useMutation({
    mutationFn: ({ wsId, profileId }: { wsId: string; profileId: string | null }) =>
      vpnApi.attachToWorkspace(wsId, profileId),
    onSuccess: invalidate,
  })

  function onFilePicked(f: File | undefined) {
    if (!f) return
    if (configText.trim()) {
      setFormError('Config text already filled — clear it before importing another file.')
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      setConfigText(String(reader.result ?? ''))
      if (!name.trim() && f.name.toLowerCase().endsWith('.ovpn')) {
        setName(f.name.replace(/\.ovpn$/i, ''))
      }
    }
    reader.readAsText(f)
  }

  const profiles = data?.items ?? []
  const openvpnAvailable = profiles.length === 0 || profiles.some((p) => p.openvpn_available)
  const workspaces = (wsData?.items ?? []) as Workspace[]

  if (isLoading) return <Spinner label="Loading VPN profiles…" />
  if (error) return <ErrorNote message={error instanceof Error ? error.message : 'Failed to load'} />

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <Network className="mt-1 h-6 w-6 shrink-0 text-brand-600" />
        <div>
          <h2 className="text-lg font-semibold text-slate-800">VPN Profiles</h2>
          <p className="text-sm text-slate-500">
            Upload OpenVPN (<span className="font-mono">.ovpn</span>) configs and pin one to a
            workspace: scans in that workspace are admitted only while the tunnel is up, and every
            task records which profile guaranteed its route.
          </p>
        </div>
      </div>

      {!openvpnAvailable && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          The <span className="font-mono">openvpn</span> binary is not available on the server.
          Profiles can still be stored and pinned to workspaces, but connecting — and therefore
          scanning through them — will fail until the binary is installed.
        </div>
      )}

      {canManage && (
        <div className="card p-4">
          <h3 className="mb-3 text-sm font-semibold text-slate-700">Add profile</h3>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="label" htmlFor="vpn-name">Profile name</label>
              <input
                id="vpn-name"
                className="input"
                placeholder="corp-internal-tunnel"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={120}
              />
            </div>
            <div>
              <label className="label" htmlFor="vpn-file">Import .ovpn file</label>
              <input
                id="vpn-file"
                ref={fileRef}
                type="file"
                accept=".ovpn,.conf,text/plain"
                className="input file:mr-3 file:rounded file:border-0 file:bg-slate-100 file:px-2 file:py-1 file:text-xs"
                onChange={(e) => onFilePicked(e.target.files?.[0])}
              />
            </div>
          </div>
          <label className="label mt-3" htmlFor="vpn-config">Config text</label>
          <textarea
            id="vpn-config"
            className="input min-h-[140px] font-mono text-xs"
            placeholder={'client\ndev tun\nproto udp\nremote vpn.corp.example 1194\n<ca>…</ca>'}
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
          />
          {formError && (
            <div className="mt-2 text-xs text-rose-600" role="alert">{formError}</div>
          )}
          <div className="mt-3 flex justify-end">
            <button
              className="btn-primary"
              disabled={!name.trim() || !configText.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              <UploadCloud className="h-4 w-4" />
              {createMut.isPending ? 'Saving…' : 'Save profile'}
            </button>
          </div>
        </div>
      )}

      {profiles.length === 0 ? (
        <EmptyState
          title="No VPN profiles yet"
          description="Add an OpenVPN profile above, then pin it to a workspace to enforce tunneled scanning."
        />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <thead className="border-b border-slate-100 bg-slate-50/60">
              <tr>
                <th className="th">Profile</th>
                <th className="th">Status</th>
                <th className="th">Interface</th>
                <th className="th">Connected</th>
                <th className="th">Pinned workspace</th>
                <th className="th text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {profiles.map((p) => {
                const pinned = workspaces.find((w) => w.vpn_profile_id === p.id)
                return (
                  <tr key={p.id} className="align-top">
                    <td className="td">
                      <div className="font-medium text-slate-700">{p.name}</div>
                      <div className="text-xs text-slate-400">{(p.config_size / 1024).toFixed(1)} KB config</div>
                      {(p.last_error || p.error) && (
                        <div className="mt-1 max-w-[320px] rounded bg-rose-50 px-2 py-1 text-xs text-rose-700">
                          {p.error ?? p.last_error}
                        </div>
                      )}
                    </td>
                    <td className="td"><VpnStatusBadge status={p.status} /></td>
                    <td className="td font-mono text-xs">{p.interface ?? '—'}</td>
                    <td className="td text-xs">{p.connected_at ? formatDate(p.connected_at) : '—'}</td>
                    <td className="td text-xs">
                      {pinned ? (
                        <span className="font-medium text-slate-600">{pinned.name}</span>
                      ) : (
                        <span className="text-slate-400">not pinned</span>
                      )}
                      {canManage && (
                        <select
                          className="input mt-1 w-auto py-1 text-xs"
                          value=""
                          aria-label={`Pin ${p.name} to workspace`}
                          onChange={(e) => {
                            const wsId = e.target.value
                            if (!wsId) return
                            attachMut.mutate({ wsId, profileId: p.id })
                          }}
                        >
                          <option value="">Pin to workspace…</option>
                          {workspaces
                            .filter((w) => w.vpn_profile_id !== p.id)
                            .map((w) => (
                              <option key={w.id} value={w.id}>{w.name}</option>
                            ))}
                        </select>
                      )}
                    </td>
                    <td className="td">
                      <div className="flex justify-end gap-1.5">
                        {canManage && p.status !== 'connected' && (
                          <button
                            className="btn-ghost px-2 py-1 text-xs text-emerald-700 hover:bg-emerald-50"
                            disabled={connectMut.isPending}
                            onClick={() => connectMut.mutate(p.id)}
                            title="Connect tunnel"
                          >
                            <PlugZap className="h-3.5 w-3.5" /> Connect
                          </button>
                        )}
                        {canManage && p.status === 'connected' && (
                          <button
                            className="btn-ghost px-2 py-1 text-xs text-sky-700 hover:bg-sky-50"
                            disabled={disconnectMut.isPending}
                            onClick={() => disconnectMut.mutate(p.id)}
                            title="Disconnect tunnel"
                          >
                            <Plug className="h-3.5 w-3.5" /> Disconnect
                          </button>
                        )}
                        {canManage && pinned && (
                          <button
                            className="btn-ghost px-2 py-1 text-xs"
                            disabled={attachMut.isPending}
                            onClick={() => attachMut.mutate({ wsId: pinned.id, profileId: null })}
                            title={`Unpin from ${pinned.name}`}
                          >
                            <ShieldQuestion className="h-3.5 w-3.5" /> Unpin
                          </button>
                        )}
                        {canManage && (
                          <button
                            className="btn-ghost px-2 py-1 text-xs text-rose-600 hover:bg-rose-50"
                            disabled={removeMut.isPending}
                            onClick={() => removeMut.mutate(p.id)}
                            title="Delete profile"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-xs text-slate-400">
        {selected === 'personal'
          ? 'Tip: create a workspace for each internal network and pin its VPN profile there.'
          : 'The selected workspace uses the profile pinned to it above.'}
      </p>
    </div>
  )
}
