import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TaskDetailPage } from '@/pages/TaskDetail'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'

function route(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const ADMIN = { id: 'u1', email: 'a@b.c', name: 'A', role: 'admin', created_at: '' }

const TASK = {
  id: 't-9',
  user_id: 'u1',
  plugin_id: 'port-scanner',
  plugin_name: 'TCP Port Scanner',
  target: 'example.com',
  status: 'completed',
  inputs: { target: 'example.com' },
  options: {},
  exit_code: 0,
  stats: { findings: 2, duration_ms: 1200 },
  output_truncated: false,
  created_at: '2026-01-02T00:00:00Z',
  started_at: '2026-01-02T00:00:01Z',
  finished_at: '2026-01-02T00:00:02Z',
}

const JOBS = {
  items: [
    {
      id: 'rj-1',
      task_id: 't-9',
      format: 'pdf',
      severity_filter: null,
      status: 'waiting',
      error: null,
      file_bytes: null,
      webhook_url: null,
      webhook_attempts: 0,
      created_at: '2026-01-03T00:00:00Z',
      started_at: null,
      finished_at: null,
      download_path: null,
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
}

interface Call {
  method: string
  url: string
  body?: unknown
}

function setup() {
  const calls: Call[] = []
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
      if (url.match(/\/tasks\/[^/]+\/reports$/)) return route(JOBS.items[0], 202)
      if (url.includes('/reports')) return route(JOBS)
      if (url.match(/\/tasks\/[^/]+$/)) return route(TASK)
      if (url.includes('/findings')) return route({ items: [], total: 0 })
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
          <MemoryRouter initialEntries={['/tasks/t-9']}>
            <Routes>
              <Route path="/tasks/:id" element={<TaskDetailPage />} />
            </Routes>
          </MemoryRouter>
        </WorkspaceProvider>
      </AuthProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
  Object.defineProperty(URL, 'createObjectURL', {
    value: vi.fn(() => 'blob:mock'),
    writable: true,
  })
  Object.defineProperty(URL, 'revokeObjectURL', { value: vi.fn(), writable: true })
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
})

describe('TaskDetail Reports tab', () => {
  it('renders the tab, instant downloads for all 8 formats, and the job form', async () => {
    setup()
    renderPage()

    const tab = await screen.findByRole('button', { name: /reports/i })
    fireEvent.click(tab)

    expect(await screen.findByText('Instant download')).toBeInTheDocument()
    // The header dropdown and the instant-download chips both offer every
    // format, so assert presence, not uniqueness.
    for (const f of ['md', 'html', 'csv', 'sarif', 'json', 'pdf', 'docx', 'xlsx']) {
      expect(screen.getAllByText(`.${f}`).length).toBeGreaterThanOrEqual(1)
    }
    expect(screen.getByText('Generate in background')).toBeInTheDocument()
    expect(screen.getByLabelText(/Format/)).toBeInTheDocument()
    expect(screen.getByLabelText(/Severity filter/)).toBeInTheDocument()
    expect(screen.getByText('Queue report job')).toBeInTheDocument()
  })

  it('submits a background job with the chosen format and severity filter', async () => {
    const { calls } = setup()
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /reports/i }))

    const formatSelect = await screen.findByLabelText(/Format/)
    fireEvent.change(formatSelect, { target: { value: 'docx' } })
    const sevSelect = screen.getByLabelText(/Severity filter/)
    fireEvent.change(sevSelect, { target: { value: 'high' } })

    fireEvent.click(screen.getByText('Queue report job'))

    await waitFor(() => {
      const create = calls.find((c) => c.url.endsWith('/tasks/t-9/reports') && c.method === 'POST')
      expect(create).toBeDefined()
      expect(create?.body).toEqual({ format: 'docx', severity: 'high' })
    })
  })

  it('surfaces validation errors from the API', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/auth/refresh')) return route({ access_token: 't', user: ADMIN })
        if (url.includes('/workspaces'))
          return route({
            items: [],
            personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 },
          })
        if (url.match(/\/tasks\/[^/]+\/reports$/) && (init?.method ?? 'GET') === 'POST')
          return route({ error: { code: 400, message: 'unknown report format `exe`' } }, 400)
        if (url.includes('/reports')) return route({ items: [], total: 0, limit: 50, offset: 0 })
        if (url.match(/\/tasks\/[^/]+$/)) return route(TASK)
        if (url.includes('/findings')) return route({ items: [], total: 0 })
        return route({}, 404)
      }),
    )
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /reports/i }))
    await screen.findByText('Instant download')
    fireEvent.click(screen.getByText('Queue report job'))

    expect(
      await screen.findByText(/unknown report format `exe`/),
    ).toBeInTheDocument()
  })

  it('shows this task job history via the shared table', async () => {
    setup()
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /reports/i }))

    expect(await screen.findByText('Report jobs for this task')).toBeInTheDocument()
    // The table data arrives after the (static) heading — wait for the row.
    expect(await screen.findByText('waiting')).toBeInTheDocument()
    // The format chip renders (the <select> option also says "pdf").
    expect(screen.getAllByText('pdf').length).toBeGreaterThanOrEqual(2)
  })
})
