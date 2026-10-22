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

let refreshInFlight: Promise<boolean> | null = null

export async function tryRefresh(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const res = await fetch(`${BASE}/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
        })
        if (!res.ok) return false
        const body = await res.json()
        accessToken = body.access_token ?? null
        return accessToken != null
      } catch {
        return false
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

  // One transparent refresh+retry on 401.
  if (res.status === 401 && !path.startsWith('/auth/')) {
    const ok = await tryRefresh()
    if (ok) {
      res = await doFetch()
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
