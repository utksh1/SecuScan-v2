import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { authApi, setAccessToken, tryRefresh } from '@/api/client'
import type { User } from '@/api/types'

interface AuthState {
  user: User | null
  ready: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [ready, setReady] = useState(false)
  const queryClient = useQueryClient()

  // On mount: try silent refresh (cookie) to restore the session. Uses the
  // module-level single-flight refresh so React StrictMode's double-mount
  // cannot race two refresh calls (the second would 401 after rotation).
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { ok, accessToken, user: refreshed } = await tryRefresh()
        if (ok && accessToken && !cancelled) {
          setAccessToken(accessToken)
          if (refreshed) setUser(refreshed as User)
        }
      } catch {
        /* offline / not logged in */
      } finally {
        if (!cancelled) setReady(true)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  // Global 401-after-refresh-failure handler: clear state and cache so the
  // router sends the user to /login instead of showing raw errors forever.
  useEffect(() => {
    const onUnauthorized = () => {
      setAccessToken(null)
      setUser(null)
      queryClient.clear()
    }
    window.addEventListener('secuscan:unauthorized', onUnauthorized)
    return () => window.removeEventListener('secuscan:unauthorized', onUnauthorized)
  }, [queryClient])

  const login = useCallback(async (email: string, password: string) => {
    const res = await authApi.login(email, password)
    setUser(res.user)
  }, [])

  const logout = useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      // Always clear local state + cached queries, even if the server call
      // failed (e.g. backend briefly down).
      setAccessToken(null)
      setUser(null)
      queryClient.clear()
    }
  }, [queryClient])

  const refreshUser = useCallback(async () => {
    const me = await authApi.me()
    setUser(me)
  }, [])

  return (
    <AuthContext.Provider value={{ user, ready, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
