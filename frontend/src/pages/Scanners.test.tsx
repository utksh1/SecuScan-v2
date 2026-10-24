import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ScannersPage } from '@/pages/Scanners'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'
import type { Plugin } from '@/api/types'

function plugin(partial: Partial<Plugin> & Pick<Plugin, 'id' | 'name' | 'category'>): Plugin {
  return {
    version: '1.0.0',
    description: `${partial.name} scanner`,
    tags: partial.tags ?? [partial.category],
    engine: { type: 'native', native: partial.id, timeout_seconds: 30 },
    fields: [],
    presets: {},
    safety: {
      level: 'safe',
      requires_consent: true,
      allowed_targets: [],
      max_concurrent: 1,
      max_per_hour: 10,
      capabilities: [],
    },
    dependencies: { binaries: [] },
    available: true,
    missing_binaries: [],
    enabled: true,
    ...partial,
  }
}

const CATALOG = {
  items: [
    plugin({ id: 'nuclei', name: 'Vulnerability Templates (nuclei)', category: 'web', tags: ['cve'] }),
    plugin({ id: 'port-scanner', name: 'TCP Port Scanner', category: 'network' }),
    plugin({
      id: 'feroxbuster',
      name: 'Feroxbuster',
      category: 'web',
      engine: { type: 'cli', binary: 'feroxbuster', timeout_seconds: 600 },
      available: false,
      missing_binaries: ['feroxbuster'],
    }),
  ],
}

function route(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <WorkspaceProvider>
            <ScannersPage />
          </WorkspaceProvider>
        </AuthProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('ScannersPage', () => {
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
          return route({
            items: [],
            personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 },
          })
        }
        if (url.includes('/plugins')) {
          return route(CATALOG)
        }
        return route({})
      }),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('renders the catalog and filters by search and category', async () => {
    const user = userEvent.setup()
    renderPage()

    await waitFor(() => {
      expect(screen.getByTestId('plugin-nuclei')).toBeInTheDocument()
    })
    expect(screen.getByText('Vulnerability Templates (nuclei)')).toBeInTheDocument()
    expect(screen.getByText('TCP Port Scanner')).toBeInTheDocument()
    expect(screen.getByText('Missing binaries:')).toBeInTheDocument()
    expect(screen.getByText('feroxbuster')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'All 3' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'network 1' }))
    expect(screen.getByTestId('plugin-port-scanner')).toBeInTheDocument()
    expect(screen.queryByTestId('plugin-nuclei')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'All 3' }))
    await user.type(screen.getByLabelText('Search scanners'), 'nuclei')
    expect(screen.getByTestId('plugin-nuclei')).toBeInTheDocument()
    expect(screen.queryByTestId('plugin-port-scanner')).not.toBeInTheDocument()
  })
})
