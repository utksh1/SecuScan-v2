import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReportsPage } from '@/pages/Reports'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'

function route(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const ADMIN = { id: 'u1', email: 'a@b.c', name: 'A', role: 'admin', created_at: '' }

const JOBS = {
  items: [
    {
      id: 'rj-1',
      task_id: 't-1',
      format: 'pdf',
      severity_filter: 'high',
      status: 'finished',
      error: null,
      file_bytes: 20480,
      webhook_url: 'https://example.com/hook',
      webhook_attempts: 1,
      created_at: '2026-01-03T00:00:00Z',
      started_at: '2026-01-03T00:00:01Z',
      finished_at: '2026-01-03T00:00:02Z',
      download_path: '/api/v1/reports/rj-1/download',
    },
    {
      id: 'rj-2',
      task_id: 't-2',
      format: 'xlsx',
      severity_filter: null,
      status: 'in_progress',
      error: null,
      file_bytes: null,
      webhook_url: null,
      webhook_attempts: 0,
      created_at: '2026-01-04T00:00:00Z',
      started_at: '2026-01-04T00:00:01Z',
      finished_at: null,
      download_path: null,
    },
    {
      id: 'rj-3',
      task_id: 't-3',
      format: 'md',
      severity_filter: null,
      status: 'failed',
      error: 'renderer exploded',
      file_bytes: null,
      webhook_url: null,
      webhook_attempts: 0,
      created_at: '2026-01-05T00:00:00Z',
      started_at: '2026-01-05T00:00:01Z',
      finished_at: '2026-01-05T00:00:02Z',
      download_path: null,
    },
  ],
  total: 3,
  limit: 50,
  offset: 0,
}

function setup(jobs: unknown = JOBS) {
  const calls: Array<{ method: string; url: string; body?: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      const body = init?.body ? JSON.parse(String(init.body)) : undefined
      calls.push({ method, url, body })
      if (url.includes('/auth/refresh')) return route({ access_token: 't', user: ADMIN })
      if (url.includes('/workspaces'))
        return route({
          items: [],
          personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 },
        })
      if (url.match(/\/reports\/[^/]+$/)) return new Response(null, { status: 204 })
      if (url.includes('/reports')) return route(jobs)
      return route({}, 404)
    }),
  )
  return { calls }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <WorkspaceProvider>
          <MemoryRouter initialEntries={['/reports']}>
            <ReportsPage />
          </MemoryRouter>
        </WorkspaceProvider>
      </AuthProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
  // jsdom lacks blob URLs; the download helper only needs them to exist.
  Object.defineProperty(URL, 'createObjectURL', {
    value: vi.fn(() => 'blob:mock'),
    writable: true,
  })
  Object.defineProperty(URL, 'revokeObjectURL', { value: vi.fn(), writable: true })
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
})

describe('ReportsPage', () => {
  it('lists report jobs with status, format, size, webhook columns', async () => {
    setup()
    renderPage()

    expect(await screen.findByText('pdf')).toBeInTheDocument()
    expect(screen.getByText('xlsx')).toBeInTheDocument()
    expect(screen.getByText('md')).toBeInTheDocument()
    expect(screen.getByText('finished')).toBeInTheDocument()
    expect(screen.getByText('rendering')).toBeInTheDocument()
    expect(screen.getByText('failed')).toBeInTheDocument()
    expect(screen.getByText('20.0 KB')).toBeInTheDocument()
    expect(screen.getByText('1 attempt')).toBeInTheDocument()
    expect(screen.getByText('high+')).toBeInTheDocument()
    // Two rows have no severity filter.
    expect(screen.getAllByText('all')).toHaveLength(2)
    // Failure reason surfaces.
    expect(screen.getByText('renderer exploded')).toBeInTheDocument()
    // Live-polling banner appears while a job is active.
    expect(screen.getByText(/1 rendering/)).toBeInTheDocument()
  })

  it('shows the empty state when there are no jobs', async () => {
    setup({ items: [], total: 0, limit: 50, offset: 0 })
    renderPage()

    expect(await screen.findByText('No report jobs')).toBeInTheDocument()
    expect(screen.getByText('Browse tasks')).toBeInTheDocument()
  })

  it('downloads finished artifacts and deletes jobs', async () => {
    const { calls } = setup()
    renderPage()

    // Only finished jobs offer a download button.
    const dl = await screen.findAllByTitle('Download artifact')
    expect(dl).toHaveLength(1)
    dl[0].click()
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/reports/rj-1/download') && c.method === 'GET')).toBe(
        true,
      ),
    )

    // Delete fires a DELETE to the job row (one per row).
    const del = screen.getAllByTitle('Delete job and artifact')
    expect(del).toHaveLength(3)
    fireEvent.click(del[1])
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/reports/rj-2') && c.method === 'DELETE')).toBe(true),
    )
  })

  it('links each row back to its task', async () => {
    setup()
    renderPage()

    const links = await screen.findAllByText(/t-1…/)
    expect(links[0]).toHaveAttribute('href', '/tasks/t-1')
  })
})
