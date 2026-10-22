import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Copy, Check, Trash2, Plus, ShieldCheck, RefreshCw } from 'lucide-react'
import { request } from '@/api/client'
import type { ApiKey, User, AuditEntry, Role } from '@/api/types'
import { Spinner, ErrorNote } from '@/components/ui'
import { formatDate, relativeTime } from '@/utils/format'
import { useAuth } from '@/auth/AuthContext'

export function SettingsPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PasswordSection />
      <ApiKeysSection />
      {isAdmin && <AdminUsersSection />}
      {isAdmin && <AdminPolicySection />}
    </div>
  )
}

// ---------------------------------------------------------------------------

function PasswordSection() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setMsg(null)
    setErr(null)
    try {
      await request('/auth/password', {
        method: 'POST',
        body: { current_password: current, new_password: next },
      })
      setMsg('Password updated.')
      setCurrent('')
      setNext('')
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed')
    }
  }

  return (
    <section className="card p-6">
      <h2 className="mb-4 text-sm font-semibold text-slate-700">Account · change password</h2>
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <div className="min-w-[200px] flex-1">
          <label className="label" htmlFor="cur-pass">Current password</label>
          <input
            id="cur-pass"
            type="password"
            className="input"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </div>
        <div className="min-w-[200px] flex-1">
          <label className="label" htmlFor="new-pass">New password (min 8 chars)</label>
          <input
            id="new-pass"
            type="password"
            className="input"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
        </div>
        <button className="btn-primary" disabled={!current || next.length < 8}>
          Update
        </button>
      </form>
      {msg && <p className="mt-2 text-sm text-emerald-600">{msg}</p>}
      {err && <p className="mt-2 text-sm text-rose-600">{err}</p>}
    </section>
  )
}

// ---------------------------------------------------------------------------

function ApiKeysSection() {
  const qc = useQueryClient()
  const [creating, setCreating] = useState('')
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => request<{ items: ApiKey[] }>('/auth/api-keys'),
  })

  const createMut = useMutation({
    mutationFn: (name: string) =>
      request<{ key: string }>('/auth/api-keys', { method: 'POST', body: { name } }),
    onSuccess: (body) => {
      setCreatedKey(body.key)
      setCreating('')
      qc.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })
  const revokeMut = useMutation({
    mutationFn: (id: string) => request(`/auth/api-keys/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  return (
    <section className="card p-6">
      <h2 className="mb-1 text-sm font-semibold text-slate-700">API keys</h2>
      <p className="mb-4 text-xs text-slate-400">
        Use with the <code className="rounded bg-slate-100 px-1 font-mono">X-API-Key</code> header
        for automation (CLI, CI).
      </p>

      <div className="mb-4 flex gap-2">
        <input
          className="input max-w-xs"
          placeholder="key name, e.g. ci-pipeline"
          value={creating}
          onChange={(e) => setCreating(e.target.value)}
        />
        <button
          className="btn-secondary whitespace-nowrap"
          disabled={!creating.trim()}
          onClick={() => createMut.mutate(creating.trim())}
        >
          <Plus className="h-4 w-4" /> Create
        </button>
      </div>

      {createdKey && (
        <div className="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 p-4">
          <div className="mb-1 flex items-center gap-2 text-sm font-medium text-emerald-800">
            <KeyRound className="h-4 w-4" /> Copy this key now — it will not be shown again
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 truncate rounded bg-white px-2 py-1.5 font-mono text-xs text-emerald-900 ring-1 ring-emerald-200">
              {createdKey}
            </code>
            <button
              className="btn-secondary px-2 py-1"
              onClick={async () => {
                await navigator.clipboard.writeText(createdKey)
                setCopied(true)
                setTimeout(() => setCopied(false), 1500)
              }}
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <Spinner />
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-100">
              <th className="th">Name</th>
              <th className="th">Prefix</th>
              <th className="th">Created</th>
              <th className="th">Last used</th>
              <th className="th text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {(data?.items ?? []).map((k) => (
              <tr key={k.id} className={k.revoked_at ? 'opacity-50' : undefined}>
                <td className="td font-medium">{k.name}</td>
                <td className="td font-mono text-xs text-slate-500">{k.prefix}…</td>
                <td className="td text-xs text-slate-500">{formatDate(k.created_at)}</td>
                <td className="td text-xs text-slate-500">
                  {k.revoked_at ? 'revoked' : k.last_used_at ? relativeTime(k.last_used_at) : 'never'}
                </td>
                <td className="td text-right">
                  {!k.revoked_at && (
                    <button
                      className="btn-ghost px-2 py-1 text-xs text-slate-400 hover:text-rose-600"
                      onClick={() => revokeMut.mutate(k.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {(data?.items ?? []).length === 0 && (
              <tr>
                <td className="td text-center text-slate-400" colSpan={5}>
                  No API keys yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------

function AdminUsersSection() {
  const qc = useQueryClient()
  const { user: me } = useAuth()
  const [form, setForm] = useState({ email: '', name: '', password: '', role: 'scanner' as Role })
  const [err, setErr] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => request<{ items: User[] }>('/admin/users'),
  })

  const createMut = useMutation({
    mutationFn: () => request('/admin/users', { method: 'POST', body: form }),
    onSuccess: () => {
      setForm({ email: '', name: '', password: '', role: 'scanner' })
      setErr(null)
      qc.invalidateQueries({ queryKey: ['admin-users'] })
    },
    onError: (e) => setErr(e instanceof Error ? e.message : 'failed'),
  })
  const roleMut = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) =>
      request(`/admin/users/${id}`, { method: 'PATCH', body: { role } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-users'] }),
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => request(`/admin/users/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-users'] }),
  })

  return (
    <section className="card p-6">
      <h2 className="mb-4 text-sm font-semibold text-slate-700">Administration · users</h2>

      <div className="mb-5 flex flex-wrap items-end gap-2">
        <input
          className="input max-w-[220px]"
          placeholder="email"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
        />
        <input
          className="input max-w-[160px]"
          placeholder="name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
        />
        <input
          className="input max-w-[180px]"
          placeholder="password"
          type="password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />
        <select
          className="input w-auto"
          value={form.role}
          onChange={(e) => setForm({ ...form, role: e.target.value as Role })}
        >
          <option value="scanner">scanner</option>
          <option value="viewer">viewer</option>
          <option value="admin">admin</option>
        </select>
        <button
          className="btn-secondary whitespace-nowrap"
          disabled={!form.email || form.password.length < 8 || !form.name}
          onClick={() => createMut.mutate()}
        >
          <Plus className="h-4 w-4" /> Add user
        </button>
      </div>
      {err && <ErrorNote message={err} />}

      {isLoading ? (
        <Spinner />
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-100">
              <th className="th">Email</th>
              <th className="th">Name</th>
              <th className="th">Role</th>
              <th className="th">Created</th>
              <th className="th text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {(data?.items ?? []).map((u) => (
              <tr key={u.id}>
                <td className="td font-medium">{u.email}</td>
                <td className="td">{u.name}</td>
                <td className="td">
                  <select
                    className="rounded-md border-0 bg-slate-50 px-2 py-1 text-xs font-medium ring-1 ring-slate-200 focus:outline-none"
                    value={u.role}
                    onChange={(e) => roleMut.mutate({ id: u.id, role: e.target.value as Role })}
                  >
                    <option value="admin">admin</option>
                    <option value="scanner">scanner</option>
                    <option value="viewer">viewer</option>
                  </select>
                </td>
                <td className="td text-xs text-slate-500">{formatDate(u.created_at)}</td>
                <td className="td text-right">
                  {u.id !== me?.id && (
                    <button
                      className="btn-ghost px-2 py-1 text-xs text-slate-400 hover:text-rose-600"
                      onClick={() => deleteMut.mutate(u.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------

function AdminPolicySection() {
  const qc = useQueryClient()
  const { data: policy, isLoading } = useQuery({
    queryKey: ['network-policy'],
    queryFn: () => request<{ allow: string[]; deny: string[] }>('/admin/network-policy'),
  })
  const { data: audit } = useQuery({
    queryKey: ['audit'],
    queryFn: () => request<{ items: AuditEntry[] }>('/admin/audit?limit=20'),
  })
  const { data: settings } = useQuery({
    queryKey: ['require-consent'],
    queryFn: () => request<{ require_consent?: boolean }>('/admin/settings'),
  })

  const [allow, setAllow] = useState('')
  const [deny, setDeny] = useState('')
  const [saved, setSaved] = useState(false)
  const [loaded, setLoaded] = useState(false)

  if (policy && !loaded) {
    setAllow(policy.allow.join('\n'))
    setDeny(policy.deny.join('\n'))
    setLoaded(true)
  }

  const saveMut = useMutation({
    mutationFn: () =>
      request('/admin/network-policy', {
        method: 'PUT',
        body: {
          allow: allow.split('\n').map((s) => s.trim()).filter(Boolean),
          deny: deny.split('\n').map((s) => s.trim()).filter(Boolean),
        },
      }),
    onSuccess: () => {
      setSaved(true)
      setTimeout(() => setSaved(false), 1500)
      qc.invalidateQueries({ queryKey: ['network-policy'] })
    },
  })

  const refreshMut = useMutation({
    mutationFn: () => request('/admin/plugins/refresh', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['plugins'] }),
  })

  if (isLoading) return <Spinner />

  return (
    <section className="card p-6">
      <h2 className="mb-1 text-sm font-semibold text-slate-700">Administration · security policy</h2>
      <p className="mb-4 text-xs text-slate-400">
        Glob patterns (10.*.*.*) or CIDR (10.0.0.0/8). Deny wins over allow; empty allow = permit
        all except denied. Plugin-level restrictions still apply on top.
      </p>

      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <label className="label" htmlFor="pol-allow">Allow list (one per line)</label>
          <textarea
            id="pol-allow"
            className="input min-h-[100px] font-mono text-xs"
            value={allow}
            onChange={(e) => setAllow(e.target.value)}
            placeholder="127.0.0.1&#10;192.168.*.*"
          />
        </div>
        <div>
          <label className="label" htmlFor="pol-deny">Deny list (one per line)</label>
          <textarea
            id="pol-deny"
            className="input min-h-[100px] font-mono text-xs"
            value={deny}
            onChange={(e) => setDeny(e.target.value)}
            placeholder="169.254.*.*"
          />
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button className="btn-primary" onClick={() => saveMut.mutate()}>
          <ShieldCheck className="h-4 w-4" /> Save policy
        </button>
        {saved && <span className="text-sm text-emerald-600">Saved ✓</span>}
        <button className="btn-secondary" onClick={() => refreshMut.mutate()}>
          <RefreshCw className="h-4 w-4" /> Re-check plugin binaries
        </button>
        <label className="flex items-center gap-2 text-sm text-slate-600">
          <input
            type="checkbox"
            className="h-4 w-4 accent-brand-600"
            checked={settings?.require_consent ?? true}
            onChange={async (e) => {
              await request('/admin/settings', {
                method: 'PUT',
                body: { require_consent: e.target.checked },
              })
              qc.invalidateQueries({ queryKey: ['require-consent'] })
            }}
          />
          Require consent for every plugin
        </label>
      </div>

      {/* Audit log */}
      <div className="mt-6">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
          Blocked target attempts (audit)
        </h3>
        {(audit?.items ?? []).length === 0 ? (
          <p className="text-sm text-slate-400">No blocked attempts recorded.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-100">
            <table className="w-full">
              <thead className="bg-slate-50">
                <tr>
                  <th className="th">Time</th>
                  <th className="th">User</th>
                  <th className="th">Plugin</th>
                  <th className="th">Target</th>
                  <th className="th">Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {(audit?.items ?? []).map((a) => (
                  <tr key={a.id}>
                    <td className="td text-xs text-slate-500">{formatDate(a.ts)}</td>
                    <td className="td text-xs">{a.user_id ?? '—'}</td>
                    <td className="td font-mono text-xs">{a.plugin_id}</td>
                    <td className="td font-mono text-xs text-rose-600">{a.target}</td>
                    <td className="td text-xs text-slate-500">{a.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  )
}
