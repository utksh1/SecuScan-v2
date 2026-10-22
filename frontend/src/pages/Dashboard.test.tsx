import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DashboardPage } from '@/pages/Dashboard'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'

const SUMMARY = {
  tasks: { total: 12, running: 1, queued: 0, completed: 10, failed: 1, cancelled: 0 },
  findings: { critical: 2, high: 3, medium: 1, low: 4, info: 20, new: 5 },
  plugins: { total: 13, available: 6, enabled: 13, load_issues: 0 },
  users_total: 2,
  workflows_total: 1,
  recent_tasks: [
    {
      id: 't-1',
      user_id: 'u1',
      plugin_id: 'port-scanner',
      plugin_name: 'TCP Port Scanner',
      target: '127.0.0.1',
      status: 'completed',
      inputs: {},
      options: {},
      output_truncated: false,
      created_at: new Date().toISOString(),
    },
  ],
}

function route(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('DashboardPage', () => {
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
        if (url.includes('/dashboard/summary')) {
          return route(SUMMARY)
        }
        return route({})
      }),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('renders stats, severity bars and recent tasks', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <AuthProvider>
            <WorkspaceProvider>
              <DashboardPage />
            </WorkspaceProvider>
          </AuthProvider>
        </QueryClientProvider>
      </MemoryRouter>,
    )

    await waitFor(() => {
      expect(screen.getByText('Total tasks')).toBeInTheDocument()
    })
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('Critical + High')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument() // 2+3
    expect(screen.getByText('Scanners available')).toBeInTheDocument()
    expect(screen.getByText('6/13')).toBeInTheDocument()
    expect(screen.getByText('Findings by severity')).toBeInTheDocument()
    expect(screen.getByText('TCP Port Scanner')).toBeInTheDocument()
    // triage banner
    expect(screen.getByText(/5 finding\(s\) awaiting triage/i)).toBeInTheDocument()
  })

  it('links stat cards to filtered views', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <AuthProvider>
            <WorkspaceProvider>
              <DashboardPage />
            </WorkspaceProvider>
          </AuthProvider>
        </QueryClientProvider>
      </MemoryRouter>,
    )
    await waitFor(() => {
      expect(screen.getByText('Total tasks')).toBeInTheDocument()
    })
    const link = screen.getByRole('link', { name: /critical \+ high/i })
    expect(link).toHaveAttribute('href', '/findings?severity=critical&severity=high')
  })
})
