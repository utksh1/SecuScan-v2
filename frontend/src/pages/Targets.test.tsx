import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TargetsPage } from '@/pages/Targets'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider, useWorkspace } from '@/auth/WorkspaceContext'

function route(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const ADMIN = { id: 'u1', email: 'a@b.c', name: 'A', role: 'admin', created_at: '' }
const VIEWER = { id: 'u2', email: 'v@b.c', name: 'V', role: 'viewer', created_at: '' }

const WORKSPACES = {
  items: [
    {
      id: 'ws-1',
      name: 'Acme Corp',
      description: 'Client engagement',
      created_by: 'u1',
      created_at: '2026-01-01T00:00:00Z',
      tasks_total: 4,
      tasks_active: 1,
      targets_total: 2,
    },
  ],
  personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 },
}

const TARGETS = [
  {
    id: 'tg-1',
    workspace_id: 'ws-1',
    name: 'example.com',
    kind: 'hostname',
    description: 'Production site',
    created_by: 'u1',
    created_at: '2026-01-02T00:00:00Z',
    scans_total: 3,
    last_scanned_at: '2026-01-05T00:00:00Z',
  },
  {
    id: 'tg-2',
    workspace_id: 'ws-1',
    name: '192.168.1.10',
    kind: 'ip_address',
    description: '',
    created_by: 'u1',
    created_at: '2026-01-03T00:00:00Z',
    scans_total: 0,
  },
]

type SetupOpts = { role?: 'admin' | 'viewer'; selected?: string }

function setup({ role = 'admin', selected = 'ws-1' }: SetupOpts = {}) {
  const calls: string[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.includes('/auth/refresh')) {
      return route({ access_token: 't', user: role === 'admin' ? ADMIN : VIEWER })
    }
    if (url.includes('/workspaces/ws-1/targets')) {
      if ((init?.method ?? 'GET') === 'POST') {
        const body = JSON.parse(String(init?.body ?? '{}'))
        return route(
          {
            id: 'tg-new',
            workspace_id: 'ws-1',
            name: body.name,
            kind: 'hostname',
            description: body.description ?? '',
            created_by: 'u1',
            created_at: new Date().toISOString(),
            scans_total: 0,
          },
          201,
        )
      }
      return route({ items: TARGETS })
    }
    if (url.includes('/workspaces')) {
      return route(WORKSPACES)
    }
    if (url.match(/\/targets\/[\w-]+$/) && init?.method === 'DELETE') {
      return new Response(null, { status: 204 })
    }
    return route({})
  })
  vi.stubGlobal('fetch', fetchMock)

  localStorage.setItem('secuscan:workspace', selected)
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <WorkspaceProvider>
            <TargetsPage />
          </WorkspaceProvider>
        </AuthProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
  return { calls }
}

describe('TargetsPage', () => {
  beforeEach(() => localStorage.clear())
  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  it('lists workspace targets with kind badges, scan counts and last-scanned', async () => {
    setup()
    expect(await screen.findByText('example.com')).toBeTruthy()
    expect(screen.getByText('Production site')).toBeTruthy()
    expect(screen.getByText('Hostname')).toBeTruthy()
    expect(screen.getByText('IP address')).toBeTruthy()
    expect(screen.getByText('3')).toBeTruthy() // scans_total for tg-1
    expect(screen.getAllByTitle('Scan this target').length).toBe(2)
  })

  it('adds a target through the form (POSTs to the workspace)', async () => {
    const { calls } = setup()
    await screen.findByText('example.com')
    fireEvent.change(screen.getByPlaceholderText(/example\.com/), {
      target: { value: 'newtarget.example.org' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Add target/i }))
    await waitFor(() =>
      expect(calls).toContainEqual('POST /api/v1/workspaces/ws-1/targets'),
    )
  })

  it('hides mutation controls for viewers', async () => {
    setup({ role: 'viewer' })
    await screen.findByText('example.com')
    expect(screen.queryByRole('button', { name: /Add target/i })).toBeNull()
    expect(screen.queryByTitle('Delete')).toBeNull()
    expect(screen.queryByTitle('Edit')).toBeNull()
  })

  it('Personal scope renders the workspace overview instead of a target list', async () => {
    setup({ selected: 'personal' })
    expect(await screen.findByText('Personal scope')).toBeTruthy()
    expect(await screen.findByText('Acme Corp')).toBeTruthy()
    // workspace management form is available to admins
    expect(screen.getByPlaceholderText('New workspace name…')).toBeTruthy()
  })

  it('falls back to Personal when the stored workspace disappears', async () => {
    setup({ selected: 'ws-deleted' })
    // The overview (Personal) renders because ws-deleted is not in the list.
    expect(await screen.findByText('Personal scope')).toBeTruthy()
  })
})

describe('WorkspaceContext', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  it('exposes scopeParam "none" for Personal and the id otherwise', async () => {
    const captured: { scopeParam?: string; selected?: string } = {}
    function Probe() {
      const ws = useWorkspace()
      captured.scopeParam = ws.scopeParam
      captured.selected = ws.selected
      return null
    }
    localStorage.setItem('secuscan:workspace', 'ws-1')
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/auth/refresh')) return route({ access_token: 't', user: ADMIN })
        if (url.includes('/workspaces')) return route(WORKSPACES)
        return route({})
      }),
    )
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <WorkspaceProvider>
            <Probe />
          </WorkspaceProvider>
        </AuthProvider>
      </QueryClientProvider>,
    )
    await waitFor(() => expect(captured.scopeParam).toBe('ws-1'))
    expect(captured.selected).toBe('ws-1')
  })

  it('defaults to Personal when nothing is stored', async () => {
    const captured: { scopeParam?: string } = {}
    function Probe() {
      captured.scopeParam = useWorkspace().scopeParam
      return null
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/auth/refresh')) return route({ access_token: 't', user: ADMIN })
        if (url.includes('/workspaces')) return route(WORKSPACES)
        return route({})
      }),
    )
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <WorkspaceProvider>
            <Probe />
          </WorkspaceProvider>
        </AuthProvider>
      </QueryClientProvider>,
    )
    await waitFor(() => expect(captured.scopeParam).toBe('none'))
  })
})
