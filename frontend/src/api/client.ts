// Fetch wrapper: JSON API client with automatic single-flight token refresh.
// The access token lives in memory only; the refresh token is an httpOnly
// cookie scoped to the API origin (same-origin in production, proxied in dev).

import type { ApiErrorShape, User } from './types'

const BASE = '/api/v1'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// --- token state (module-scoped) -------------------------------------------

let accessToken: string | null = null
export function setAccessToken(t: string | null) {
  accessToken = t
}
export function getAccessToken() {
  return accessToken
}

// --- single-flight refresh ---------------------------------------------------

export interface RefreshResult {
  ok: boolean
  accessToken?: string
  user?: unknown
}

let refreshInFlight: Promise<RefreshResult> | null = null

export async function tryRefresh(): Promise<RefreshResult> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const res = await fetch(`${BASE}/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
        })
        if (!res.ok) return { ok: false }
        const body = await res.json()
        accessToken = body.access_token ?? null
        return { ok: accessToken != null, accessToken: accessToken ?? undefined, user: body.user }
      } catch {
        return { ok: false }
      } finally {
        setTimeout(() => (refreshInFlight = null), 0)
      }
    })()
  }
  return refreshInFlight
}

// --- core request helper ------------------------------------------------------

interface RequestOptions {
  method?: string
  body?: unknown
  raw?: boolean
  signal?: AbortSignal
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const doFetch = () =>
    fetch(`${BASE}${path}`, {
      method: opts.method ?? 'GET',
      credentials: 'include',
      signal: opts.signal,
      headers: {
        ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    })

  let res = await doFetch()

  // One transparent refresh+retry on 401 (login/refresh themselves report
  // their own failures).
  if (res.status === 401 && !path.startsWith('/auth/login') && !path.startsWith('/auth/refresh')) {
    const { ok } = await tryRefresh()
    if (ok) {
      res = await doFetch()
    } else {
      // Session is truly gone — let the app redirect to /login.
      window.dispatchEvent(new CustomEvent('secuscan:unauthorized'))
    }
  }

  if (opts.raw) {
    return res as unknown as T
  }
  if (!res.ok) {
    let message = `request failed (${res.status})`
    try {
      const body = (await res.json()) as ApiErrorShape
      if (body?.error?.message) message = body.error.message
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message)
  }
  if (res.status === 204) {
    return undefined as T
  }
  return (await res.json()) as T
}

// --- auth API -------------------------------------------------------------------

export interface LoginResponse {
  access_token: string
  token_type: string
  user: User
}

export const authApi = {
  async login(email: string, password: string): Promise<LoginResponse> {
    const body = await request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: { email, password },
    })
    accessToken = body.access_token
    return body
  },
  async logout(): Promise<void> {
    try {
      await request<void>('/auth/logout', { method: 'POST', raw: false })
    } finally {
      accessToken = null
    }
  },
  me: () => request<User>('/auth/me'),
}

// --- authenticated download (reports) ---------------------------------------------

export async function downloadFile(path: string, filename: string): Promise<void> {
  const res = await request<Response>(path, { raw: true })
  if (!res.ok) throw new ApiError(res.status, 'download failed')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// --- workspaces + targets ---------------------------------------------------------

import type { Workspace, WorkspaceList, ScanTarget } from './types'

export const workspaceApi = {
  list: () => request<WorkspaceList>('/workspaces'),
  create: (name: string, description: string) =>
    request<Workspace>('/workspaces', { method: 'POST', body: { name, description } }),
  update: (id: string, patch: { name?: string; description?: string }) =>
    request<Workspace>(`/workspaces/${id}`, { method: 'PATCH', body: patch }),
  remove: (id: string) => request<void>(`/workspaces/${id}`, { method: 'DELETE' }),
  targets: (workspaceId: string) =>
    request<{ items: ScanTarget[] }>(`/workspaces/${workspaceId}/targets`),
  createTarget: (workspaceId: string, name: string, description: string) =>
    request<ScanTarget>(`/workspaces/${workspaceId}/targets`, {
      method: 'POST',
      body: { name, description },
    }),
  updateTarget: (id: string, patch: { name?: string; description?: string }) =>
    request<ScanTarget>(`/targets/${id}`, { method: 'PATCH', body: patch }),
  removeTarget: (id: string) => request<void>(`/targets/${id}`, { method: 'DELETE' }),
}

// --- async report jobs ---------------------------------------------------------

import type { ReportJob, ReportJobList } from './types'

export const reportApi = {
  list: (params?: { task_id?: string }) => {
    const q = params?.task_id ? `?task_id=${encodeURIComponent(params.task_id)}` : ''
    return request<ReportJobList>(`/reports${q}`)
  },
  create: (
    taskId: string,
    body: {
      format: string
      severity?: string
      webhook_url?: string
      webhook_secret?: string
    },
  ) => request<ReportJob>(`/tasks/${taskId}/reports`, { method: 'POST', body }),
  remove: (id: string) => request<void>(`/reports/${id}`, { method: 'DELETE' }),
}

// --- recurring scan schedules --------------------------------------------------

import type { Schedule, ScheduleList, Task } from './types'

export const scheduleApi = {
  list: () => request<ScheduleList>('/schedules'),
  create: (body: {
    name: string
    plugin_id: string
    inputs: Record<string, unknown>
    preset?: string
    interval_seconds: number
    consent_granted: boolean
    workspace_id?: string
  }) => request<Schedule>('/schedules', { method: 'POST', body }),
  update: (
    id: string,
    patch: {
      name?: string
      inputs?: Record<string, unknown>
      preset?: string | null
      interval_seconds?: number
      enabled?: boolean
      workspace_id?: string | null
    },
  ) => request<Schedule>(`/schedules/${id}`, { method: 'PATCH', body: patch }),
  remove: (id: string) => request<void>(`/schedules/${id}`, { method: 'DELETE' }),
  runNow: (id: string) =>
    request<{ task_id: string; next_run_at: string }>(`/schedules/${id}/run`, {
      method: 'POST',
    }),
  runs: (id: string) =>
    request<{ items: Task[]; total: number }>(`/schedules/${id}/runs`),
}

// --- v3.1.0: VPN profiles (OpenVPN) -------------------------------------------

import type { VpnProfile } from './types'

export const vpnApi = {
  list: () => request<{ items: VpnProfile[] }>('/vpn-profiles'),
  get: (id: string) => request<VpnProfile>(`/vpn-profiles/${id}`),
  create: (name: string, configText: string) =>
    request<VpnProfile>('/vpn-profiles', {
      method: 'POST',
      body: { name, config_text: configText },
    }),
  remove: (id: string) => request<void>(`/vpn-profiles/${id}`, { method: 'DELETE' }),
  connect: (id: string) =>
    request<VpnProfile>(`/vpn-profiles/${id}/connect`, { method: 'POST' }),
  disconnect: (id: string) =>
    request<VpnProfile>(`/vpn-profiles/${id}/disconnect`, { method: 'POST' }),
  workspaceProfile: (workspaceId: string) =>
    request<{ profile: Pick<VpnProfile, 'id' | 'name' | 'status' | 'interface' | 'last_error' | 'connected_at' | 'openvpn_available'> | null }>(
      `/workspaces/${workspaceId}/vpn`,
    ),
  attachToWorkspace: (workspaceId: string, vpnProfileId: string | null) =>
    request<void>(`/workspaces/${workspaceId}/vpn`, {
      method: 'PUT',
      body: { vpn_profile_id: vpnProfileId },
    }),
}

// --- v3.1.0: Sniper Auto-Exploiter ----------------------------------------------

import type { SniperRun } from './types'

export const sniperApi = {
  list: (params?: { finding_id?: string }) => {
    const q = params?.finding_id ? `?finding_id=${encodeURIComponent(params.finding_id)}` : ''
    return request<{ items: SniperRun[] }>(`/sniper/runs${q}`)
  },
  get: (id: string) => request<SniperRun>(`/sniper/runs/${id}`),
  run: (findingId: string, workspaceId?: string) =>
    request<{ run_id: string; finding_id: string; status: string }>('/sniper/run', {
      method: 'POST',
      body: { finding_id: findingId, workspace_id: workspaceId },
    }),
  cancel: (id: string) =>
    request<{ cancelled_tasks: number }>(`/sniper/runs/${id}/cancel`, { method: 'POST' }),
}
