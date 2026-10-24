import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  KeyRound,
  Copy,
  Check,
  Trash2,
  Plus,
  ShieldCheck,
  RefreshCw,
  Cookie,
  BookOpen,
  Bell,
  Palette,
} from 'lucide-react'
import {
  request,
  authProfileApi,
  wordlistApi,
  notificationApi,
  brandingApi,
} from '@/api/client'
import type {
  ApiKey,
  User,
  AuditEntry,
  Role,
  AuthProfileMethod,
  NotificationRule,
} from '@/api/types'
import { Spinner, ErrorNote } from '@/components/ui'
import { formatDate, relativeTime } from '@/utils/format'
import { useAuth } from '@/auth/AuthContext'
import { useWorkspace } from '@/auth/WorkspaceContext'

export function SettingsPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const canScan = user?.role === 'admin' || user?.role === 'scanner'

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PasswordSection />
      <ApiKeysSection />
      {canScan && <AuthProfilesSection />}
      {canScan && <WordlistsSection />}
      {canScan && <NotificationsSection />}
      <BrandingSection canEdit={isAdmin} />
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

function parsePairs(text: string, sep: string): { name: string; value: string }[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const i = line.indexOf(sep)
      if (i < 0) return { name: line, value: '' }
      return { name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() }
    })
}

function AuthProfilesSection() {
  const qc = useQueryClient()
  const { selected } = useWorkspace()
  const [name, setName] = useState('')
  const [method, setMethod] = useState<AuthProfileMethod>('cookie')
  const [pairs, setPairs] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [notes, setNotes] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['auth-profiles'],
    queryFn: authProfileApi.list,
  })

  function buildConfig(): Record<string, unknown> {
    if (method === 'cookie') return { cookies: parsePairs(pairs, '=') }
    if (method === 'header') return { headers: parsePairs(pairs, ':') }
    if (method === 'form') return { login_url: loginUrl, username, password }
    return {
      steps: pairs
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean)
        .map((url) => ({ url })),
    }
  }

  const createMut = useMutation({
    mutationFn: () =>
      authProfileApi.create({
        name: name.trim(),
        method,
        config: buildConfig(),
        notes,
        workspace_id: selected === 'personal' ? undefined : selected,
      }),
    onSuccess: () => {
      setName('')
      setPairs('')
      setLoginUrl('')
      setUsername('')
      setPassword('')
      setNotes('')
      setErr(null)
      qc.invalidateQueries({ queryKey: ['auth-profiles'] })
    },
    onError: (e) => setErr(e instanceof Error ? e.message : 'failed'),
  })
  const deleteMut = useMutation({
    mutationFn: authProfileApi.remove,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['auth-profiles'] }),
  })

  return (
    <section className="card p-6">
      <h2 className="mb-1 text-sm font-semibold text-slate-700">Auth profiles</h2>
      <p className="mb-4 text-xs text-slate-400">
        Reusable cookies, headers, or form logins for authenticated web/API scans.
      </p>

      <div className="mb-4 grid gap-2 md:grid-cols-2">
        <input
          className="input"
          placeholder="profile name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          className="input"
          value={method}
          onChange={(e) => setMethod(e.target.value as AuthProfileMethod)}
        >
          <option value="cookie">cookie</option>
          <option value="header">header</option>
          <option value="form">form login</option>
          <option value="recorded">recorded steps</option>
        </select>
        {method === 'form' ? (
          <>
            <input
              className="input md:col-span-2"
              placeholder="https://app.example/login"
              value={loginUrl}
              onChange={(e) => setLoginUrl(e.target.value)}
            />
            <input
              className="input"
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              className="input"
              type="password"
              placeholder="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </>
        ) : (
          <textarea
            className="input min-h-[80px] font-mono text-xs md:col-span-2"
            placeholder={
              method === 'cookie'
                ? 'session=abc\ncsrf=def'
                : method === 'header'
                  ? 'Authorization: Bearer …\nX-Api-Key: …'
                  : 'https://app.example/step-1\nhttps://app.example/step-2'
            }
            value={pairs}
            onChange={(e) => setPairs(e.target.value)}
          />
        )}
        <input
          className="input md:col-span-2"
          placeholder="notes (optional)"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </div>
      <button
        className="btn-secondary"
        disabled={!name.trim() || createMut.isPending}
        onClick={() => createMut.mutate()}
      >
        <Cookie className="h-4 w-4" /> Save profile
      </button>
      {err && <p className="mt-2 text-sm text-rose-600">{err}</p>}

      {isLoading ? (
        <Spinner />
      ) : (
        <table className="mt-4 w-full">
          <thead>
            <tr className="border-b border-slate-100">
              <th className="th">Name</th>
              <th className="th">Method</th>
              <th className="th">Created</th>
              <th className="th text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {(data?.items ?? []).map((p) => (
              <tr key={p.id}>
                <td className="td font-medium">{p.name}</td>
                <td className="td font-mono text-xs">{p.method}</td>
                <td className="td text-xs text-slate-500">{formatDate(p.created_at)}</td>
                <td className="td text-right">
                  <button
                    className="btn-ghost px-2 py-1 text-xs text-slate-400 hover:text-rose-600"
                    onClick={() => deleteMut.mutate(p.id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
            {(data?.items ?? []).length === 0 && (
              <tr>
                <td className="td text-center text-slate-400" colSpan={4}>
                  No auth profiles yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  )
}

function WordlistsSection() {
  const qc = useQueryClient()
  const { selected } = useWorkspace()
  const [name, setName] = useState('')
  const [kind, setKind] = useState('generic')
  const [file, setFile] = useState<File | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['wordlists'],
    queryFn: wordlistApi.list,
  })

  const uploadMut = useMutation({
    mutationFn: () =>
      wordlistApi.upload(
        name.trim() || file!.name,
        file!,
        kind,
        selected === 'personal' ? undefined : selected,
      ),
    onSuccess: () => {
      setName('')
      setFile(null)
      setErr(null)
      qc.invalidateQueries({ queryKey: ['wordlists'] })
    },
    onError: (e) => setErr(e instanceof Error ? e.message : 'upload failed'),
  })
  const deleteMut = useMutation({
    mutationFn: wordlistApi.remove,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['wordlists'] }),
  })

  return (
    <section className="card p-6">
      <h2 className="mb-1 text-sm font-semibold text-slate-700">Wordlists</h2>
      <p className="mb-4 text-xs text-slate-400">
        Upload lists for directory brute-force, vhost, and password-audit plugins (max 16 MB).
      </p>
      <div className="mb-4 flex flex-wrap items-end gap-2">
        <input
          className="input max-w-[200px]"
          placeholder="name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select className="input w-auto" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="generic">generic</option>
          <option value="dirs">dirs</option>
          <option value="vhosts">vhosts</option>
          <option value="passwords">passwords</option>
        </select>
        <input
          type="file"
          accept=".txt,.lst,.dic"
          className="text-xs text-slate-500"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        <button
          className="btn-secondary"
          disabled={!file || uploadMut.isPending}
          onClick={() => uploadMut.mutate()}
        >
          <BookOpen className="h-4 w-4" /> Upload
        </button>
      </div>
      {err && <p className="mb-2 text-sm text-rose-600">{err}</p>}
      {isLoading ? (
        <Spinner />
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-100">
              <th className="th">Name</th>
              <th className="th">Kind</th>
              <th className="th">Words</th>
              <th className="th">Source</th>
              <th className="th text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {(data?.items ?? []).map((w) => (
              <tr key={w.id}>
                <td className="td font-medium">{w.name}</td>
                <td className="td text-xs">{w.kind}</td>
                <td className="td text-xs text-slate-500">{w.word_count}</td>
                <td className="td text-xs">{w.source}</td>
                <td className="td text-right">
                  {w.source !== 'builtin' && (
                    <button
                      className="btn-ghost px-2 py-1 text-xs text-slate-400 hover:text-rose-600"
                      onClick={() => deleteMut.mutate(w.id)}
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
                  No wordlists yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  )
}

function NotificationsSection() {
  const qc = useQueryClient()
  const { selected } = useWorkspace()
  const [name, setName] = useState('')
  const [trigger, setTrigger] = useState('vuln_high')
  const [channel, setChannel] = useState('webhook')
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [email, setEmail] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [logId, setLogId] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['notifications'],
    queryFn: notificationApi.list,
  })
  const log = useQuery({
    queryKey: ['notification-log', logId],
    queryFn: () => notificationApi.log(logId!),
    enabled: !!logId,
  })

  function buildRules(): Record<string, unknown> {
    const triggers =
      trigger === 'scan_done'
        ? [{ kind: 'scan_status', status: 'completed' }]
        : [{ kind: 'vuln_found', severity: '>=high' }]
    const actions =
      channel === 'email'
        ? [{ kind: 'email', to: [email.trim()] }]
        : [
            {
              kind: 'webhook',
              url: url.trim(),
              ...(secret.trim() ? { secret: secret.trim() } : {}),
            },
          ]
    return { triggers, actions }
  }

  const createMut = useMutation({
    mutationFn: () =>
      notificationApi.create({
        name: name.trim(),
        rules: buildRules(),
        workspace_id: selected === 'personal' ? undefined : selected,
      }),
    onSuccess: () => {
      setName('')
      setUrl('')
      setSecret('')
      setEmail('')
      setErr(null)
      qc.invalidateQueries({ queryKey: ['notifications'] })
    },
    onError: (e) => setErr(e instanceof Error ? e.message : 'failed'),
  })
  const toggleMut = useMutation({
    mutationFn: (r: NotificationRule) =>
      notificationApi.update(r.id, { name: r.name, rules: r.rules, enabled: !r.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['notifications'] }),
  })
  const deleteMut = useMutation({
    mutationFn: notificationApi.remove,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['notifications'] }),
  })

  return (
    <section className="card p-6">
      <h2 className="mb-1 text-sm font-semibold text-slate-700">Notifications</h2>
      <p className="mb-4 text-xs text-slate-400">
        Fire a webhook or email when a scan finishes or a high+ finding lands. Loopback and
        RFC1918 webhook URLs are rejected.
      </p>
      <div className="mb-4 flex flex-wrap items-end gap-2">
        <input
          className="input max-w-[180px]"
          placeholder="rule name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select className="input w-auto" value={trigger} onChange={(e) => setTrigger(e.target.value)}>
          <option value="vuln_high">finding ≥ high</option>
          <option value="scan_done">scan completed</option>
        </select>
        <select className="input w-auto" value={channel} onChange={(e) => setChannel(e.target.value)}>
          <option value="webhook">webhook</option>
          <option value="email">email</option>
        </select>
        {channel === 'email' ? (
          <input
            className="input max-w-[220px]"
            placeholder="security@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        ) : (
          <>
            <input
              className="input min-w-[220px] flex-1"
              placeholder="https://hooks.example.com/…"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <input
              className="input max-w-[160px]"
              placeholder="HMAC secret"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </>
        )}
        <button
          className="btn-secondary"
          disabled={!name.trim() || createMut.isPending}
          onClick={() => createMut.mutate()}
        >
          <Bell className="h-4 w-4" /> Add rule
        </button>
      </div>
      {err && <p className="mb-2 text-sm text-rose-600">{err}</p>}
      {isLoading ? (
        <Spinner />
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-100">
              <th className="th">Name</th>
              <th className="th">Enabled</th>
              <th className="th">Created</th>
              <th className="th text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {(data?.items ?? []).map((r) => (
              <tr key={r.id}>
                <td className="td font-medium">{r.name}</td>
                <td className="td">
                  <label className="flex items-center gap-2 text-xs text-slate-600">
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-brand-600"
                      checked={r.enabled}
                      onChange={() => toggleMut.mutate(r)}
                    />
                    {r.enabled ? 'on' : 'off'}
                  </label>
                </td>
                <td className="td text-xs text-slate-500">{formatDate(r.created_at)}</td>
                <td className="td text-right">
                  <button
                    className="btn-ghost px-2 py-1 text-xs text-slate-500"
                    onClick={() => setLogId(r.id)}
                  >
                    log
                  </button>
                  <button
                    className="btn-ghost px-2 py-1 text-xs text-slate-400 hover:text-rose-600"
                    onClick={() => deleteMut.mutate(r.id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
            {(data?.items ?? []).length === 0 && (
              <tr>
                <td className="td text-center text-slate-400" colSpan={4}>
                  No notification rules yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
      {logId && (
        <div className="mt-4 rounded-lg border border-slate-100 bg-slate-50 p-3">
          <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Delivery log
          </div>
          {(log.data?.items ?? []).length === 0 ? (
            <p className="text-sm text-slate-400">No deliveries yet.</p>
          ) : (
            <ul className="space-y-1 font-mono text-xs text-slate-600">
              {(log.data?.items ?? []).map((l) => (
                <li key={l.id}>
                  {formatDate(l.sent_at)} · {l.channel} · {l.status}
                  {l.error ? ` · ${l.error}` : ''}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  )
}

function BrandingSection({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['branding'],
    queryFn: brandingApi.get,
  })
  const [org, setOrg] = useState('')
  const [primary, setPrimary] = useState('0f766e')
  const [accent, setAccent] = useState('0369a1')
  const [footer, setFooter] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [saved, setSaved] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  if (data && !loaded) {
    setOrg(data.org_name)
    setPrimary(data.primary_color || '0f766e')
    setAccent(data.accent_color || '0369a1')
    setFooter(data.footer_text || '')
    setLoaded(true)
  }

  const saveMut = useMutation({
    mutationFn: () =>
      brandingApi.update({
        org_name: org.trim(),
        primary_color: primary.replace('#', ''),
        accent_color: accent.replace('#', ''),
        footer_text: footer,
      }),
    onSuccess: () => {
      setSaved(true)
      setErr(null)
      setTimeout(() => setSaved(false), 1500)
      qc.invalidateQueries({ queryKey: ['branding'] })
    },
    onError: (e) => setErr(e instanceof Error ? e.message : 'failed'),
  })
  const logoMut = useMutation({
    mutationFn: (file: File) => brandingApi.uploadLogo(file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['branding'] }),
    onError: (e) => setErr(e instanceof Error ? e.message : 'logo upload failed'),
  })

  if (isLoading) return <Spinner />

  return (
    <section className="card p-6">
      <h2 className="mb-1 text-sm font-semibold text-slate-700">Report branding</h2>
      <p className="mb-4 text-xs text-slate-400">
        Organization name, colors, and PNG logo applied to HTML/PDF reports. Admin-only edits.
      </p>
      <div className="grid gap-3 md:grid-cols-2">
        <input
          className="input"
          placeholder="Organization"
          value={org}
          disabled={!canEdit}
          onChange={(e) => setOrg(e.target.value)}
        />
        <input
          className="input"
          placeholder="Footer"
          value={footer}
          disabled={!canEdit}
          onChange={(e) => setFooter(e.target.value)}
        />
        <label className="flex items-center gap-2 text-sm text-slate-600">
          Primary
          <input
            type="color"
            className="h-8 w-12 cursor-pointer rounded border border-slate-200"
            value={`#${primary.replace('#', '')}`}
            disabled={!canEdit}
            onChange={(e) => setPrimary(e.target.value.replace('#', ''))}
          />
          <span className="font-mono text-xs">{primary.replace('#', '')}</span>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-600">
          Accent
          <input
            type="color"
            className="h-8 w-12 cursor-pointer rounded border border-slate-200"
            value={`#${accent.replace('#', '')}`}
            disabled={!canEdit}
            onChange={(e) => setAccent(e.target.value.replace('#', ''))}
          />
          <span className="font-mono text-xs">{accent.replace('#', '')}</span>
        </label>
      </div>
      {canEdit && (
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button className="btn-primary" onClick={() => saveMut.mutate()}>
            <Palette className="h-4 w-4" /> Save branding
          </button>
          {saved && <span className="text-sm text-emerald-600">Saved ✓</span>}
          <label className="btn-secondary cursor-pointer text-xs">
            Upload PNG logo
            <input
              type="file"
              accept="image/png"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) logoMut.mutate(f)
              }}
            />
          </label>
          {data?.has_logo && (
            <span className="text-xs text-slate-400">logo on file ({data.logo_size ?? 0} B)</span>
          )}
        </div>
      )}
      {err && <p className="mt-2 text-sm text-rose-600">{err}</p>}
    </section>
  )
}
