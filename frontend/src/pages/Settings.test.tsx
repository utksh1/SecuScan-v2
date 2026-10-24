import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SettingsPage } from '@/pages/Settings'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'

function route(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('SettingsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/auth/refresh')) {
          return route({
            access_token: 't',
            user: { id: 'u1', email: 'a@b.c', name: 'A', role: 'admin', created_at: '' },
          })
        }
        if (url.includes('/workspaces')) {
          return route({ items: [], personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 } })
        }
        if (url.includes('/auth/api-keys')) return route({ items: [] })
        if (url.includes('/auth-profiles')) return route({ items: [] })
        if (url.includes('/wordlists')) return route({ items: [] })
        if (url.includes('/notifications')) return route({ items: [] })
        if (url.includes('/branding')) {
          return route({
            id: 'default',
            org_name: 'SecuScan',
            has_logo: false,
            primary_color: '0f766e',
            accent_color: '0369a1',
            footer_text: '',
          })
        }
        if (url.includes('/admin/users')) return route({ items: [] })
        if (url.includes('/admin/network-policy')) return route({ allow: [], deny: [] })
        if (url.includes('/admin/audit')) return route({ items: [] })
        if (url.includes('/admin/settings')) return route({ require_consent: true })
        return route({})
      }),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('renders cockpit settings sections for an admin', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <AuthProvider>
            <WorkspaceProvider>
              <SettingsPage />
            </WorkspaceProvider>
          </AuthProvider>
        </QueryClientProvider>
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByText('Auth profiles')).toBeInTheDocument()
    })
    expect(screen.getByText('Wordlists')).toBeInTheDocument()
    expect(screen.getByText('Notifications')).toBeInTheDocument()
    expect(screen.getByText('Report branding')).toBeInTheDocument()
    expect(screen.getByText('No auth profiles yet.')).toBeInTheDocument()
    expect(screen.getByText('No wordlists yet.')).toBeInTheDocument()
    expect(screen.getByText('No notification rules yet.')).toBeInTheDocument()
  })
})
