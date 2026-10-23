import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SchedulesPage } from '@/pages/Schedules'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'

function route(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const ADMIN = { id: 'u1', email: 'a@b.c', name: 'A', role: 'admin', created_at: '' }
const VIEWER = { id: 'u2', email: 'v@b.c', name: 'V', role: 'viewer', created_at: '' }

const PLUGINS = {
  items: [
    {
      id: 'port-scanner',
      name: 'Port Scanner',
      version: '1.0.0',
      description: 'scans ports',
      category: 'network',
      tags: [],
      engine: { type: 'native', timeout_seconds: 60 },
      fields: [
        {
          id: 'target',
          label: 'Target',
          type: 'string',
          required: true,
        },
        {
          id: 'ports',
          label: 'Ports',
          type: 'string',
          required: false,
          default: '1-1024',
        },
      ],
      presets: {},
      safety: {
        level: 'safe',
        requires_consent: false,
        allowed_targets: [],
        max_concurrent: 2,
        max_per_hour: 0,
        capabilities: [],
      },
      dependencies: { binaries: [] },
      available: true,
      missing_binaries: [],
      enabled: true,
    },
  ],
}

const SCHEDULES = {
  items: [
    {
      id: 'sch-1',
      user_id: 'u1',
      workspace_id: null,
      name: 'Daily port sweep',
      plugin_id: 'port-scanner',
      inputs: { target: '10.0.0.5' },
      preset: null,
      target: '10.0.0.5',
      interval_seconds: 86_400,
      enabled: true,
      next_run_at: '2026-01-02T00:00:00.000Z',
      last_run_at: '2026-01-01T00:00:00.000Z',
      last_task_id: 't-1',
      last_error: null,
      created_at: '2025-12-31T00:00:00.000Z',
      updated_at: null,
    },
    {
      id: 'sch-2',
      user_id: 'u1',
      workspace_id: 'ws-1',
      name: 'Paused TLS check',
      plugin_id: 'tls-check',
      inputs: { target: 'example.com' },
      preset: null,
      target: 'example.com',
      interval_seconds: 3_600,
      enabled: false,
      next_run_at: '2026-01-01T00:00:00.000Z',
      last_run_at: null,
      last_task_id: null,
      last_error: 'plugin `tls-check` is disabled by the administrator',
      created_at: '2025-12-30T00:00:00.000Z',
      updated_at: null,
    },
  ],
  total: 2,
  limit: 100,
  offset: 0,
}

function setup(user = ADMIN, schedules: unknown = SCHEDULES) {
  const calls: Array<{ method: string; url: string; body?: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      const body = init?.body ? JSON.parse(String(init.body)) : undefined
      calls.push({ method, url, body })
      if (url.includes('/auth/refresh')) return route({ access_token: 't', user })
      if (url.includes('/auth/me')) return route(user)
      if (url.includes('/workspaces'))
        return route({
          items: [
            {
              id: 'ws-1',
              name: 'Acme',
              description: '',
              created_by: 'u1',
              created_at: '',
              tasks_total: 0,
              tasks_active: 0,
              targets_total: 0,
            },
          ],
          personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 },
        })
      if (url.includes('/plugins')) return route(PLUGINS)
      if (url.match(/\/schedules\/[^/]+\/run$/)) return route({ task_id: 't-new' })
      if (url.match(/\/schedules\/[^/]+$/))
        return route({ ...SCHEDULES.items[0], ...(body ?? {}) })
      if (url.includes('/schedules')) return route(schedules)
      return route({}, 404)
    }),
  )
  return { calls }
}

function renderPage(entry = '/schedules') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <WorkspaceProvider>
          <MemoryRouter initialEntries={[entry]}>
            <SchedulesPage />
          </MemoryRouter>
        </WorkspaceProvider>
      </AuthProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('SchedulesPage', () => {
  it('lists schedules with interval, next run, last run and error visibility', async () => {
    setup()
    renderPage()

    expect(await screen.findByText('Daily port sweep')).toBeInTheDocument()
    expect(screen.getByText('every day')).toBeInTheDocument()
    expect(screen.getByText('every hour')).toBeInTheDocument()
    expect(screen.getByText('port-scanner')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
    expect(screen.getByText('example.com')).toBeInTheDocument()
    // Paused schedule shows "paused" instead of a next-run date.
    expect(screen.getByText('paused')).toBeInTheDocument()
    // Last run links to the task.
    const link = screen.getByText('task')
    expect(link).toHaveAttribute('href', '/tasks/t-1')
    expect(screen.getByText('never')).toBeInTheDocument()
    // Rejection reason surfaces.
    expect(
      screen.getByText(/last attempt rejected: plugin `tls-check` is disabled/),
    ).toBeInTheDocument()
  })

  it('toggles, runs now and deletes via the API', async () => {
    const { calls } = setup()
    renderPage()
    await screen.findByText('Daily port sweep')

    // Toggle the second (paused) schedule on.
    const toggles = screen.getAllByRole('switch')
    fireEvent.click(toggles[1])
    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.method === 'PATCH' &&
            c.url.includes('/schedules/sch-2') &&
            (c.body as Record<string, unknown>)?.enabled === true,
        ),
      ).toBe(true),
    )

    // Run now on the first.
    fireEvent.click(screen.getAllByText('Run now')[0])
    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.includes('/schedules/sch-1/run')),
      ).toBe(true),
    )

    // Delete the first.
    fireEvent.click(screen.getAllByTitle(/Delete schedule/)[0])
    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'DELETE' && c.url.includes('/schedules/sch-1')),
      ).toBe(true),
    )
  })

  it('creates a schedule from the form (interval, inputs, workspace)', async () => {
    const { calls } = setup()
    renderPage()
    await screen.findByText('Daily port sweep')

    fireEvent.click(screen.getByText('New schedule'))

    const name = await screen.findByLabelText(/Name/)
    fireEvent.change(name, { target: { value: 'Weekly sweep' } })

    // Plugin select.
    fireEvent.change(screen.getByLabelText(/Scanner/), { target: { value: 'port-scanner' } })

    // Fill the required target field (seeded defaults keep `ports`).
    fireEvent.change(await screen.findByLabelText(/Target/), { target: { value: '10.0.0.9' } })

    // Pick "every week".
    fireEvent.change(screen.getByLabelText(/Interval/), { target: { value: String(7 * 86_400) } })

    // Personal workspace (default) — no workspace_id expected.
    fireEvent.click(screen.getByText('Create schedule'))

    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.method === 'POST' &&
            c.url.endsWith('/schedules') &&
            (c.body as Record<string, unknown>)?.name === 'Weekly sweep' &&
            (c.body as Record<string, unknown>)?.interval_seconds === 7 * 86_400 &&
            (c.body as Record<string, unknown>)?.consent_granted === false &&
            ((c.body as Record<string, unknown>)?.inputs as Record<string, unknown>)
              ?.target === '10.0.0.9',
        ),
      ).toBe(true),
    )
    // No workspace_id key when Personal is selected.
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/schedules'))
    expect((post!.body as Record<string, unknown>).workspace_id).toBeUndefined()
  })

  it('edits an existing schedule via PATCH', async () => {
    const { calls } = setup()
    renderPage()
    await screen.findByText('Daily port sweep')

    fireEvent.click(screen.getAllByTitle('Edit schedule')[0])

    const name = await screen.findByLabelText(/Name/)
    expect((name as HTMLInputElement).value).toBe('Daily port sweep')
    fireEvent.change(name, { target: { value: 'Renamed' } })
    fireEvent.change(screen.getByLabelText(/Interval/), { target: { value: String(3_600) } })

    fireEvent.click(screen.getByText('Save changes'))
    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.method === 'PATCH' &&
            c.url.includes('/schedules/sch-1') &&
            (c.body as Record<string, unknown>)?.name === 'Renamed' &&
            (c.body as Record<string, unknown>)?.interval_seconds === 3_600 &&
            (c.body as Record<string, unknown>)?.workspace_id === null,
        ),
      ).toBe(true),
    )
  })

  it('hides write controls from viewers', async () => {
    setup(VIEWER)
    renderPage()

    await screen.findByText('Daily port sweep')
    expect(screen.queryByText('New schedule')).toBeNull()
    expect(screen.queryByText('Run now')).toBeNull()
    expect(screen.queryByTitle('Edit schedule')).toBeNull()
    // Toggles render but are disabled.
    const toggles = screen.getAllByRole('switch')
    expect((toggles[0] as HTMLButtonElement).disabled).toBe(true)
  })

  it('opens the form pre-linked from the targets page (?create=1&plugin=&target=)', async () => {
    setup()
    renderPage('/schedules?create=1&plugin=port-scanner&target=10.0.0.7')

    const name = await screen.findByLabelText(/Name/)
    expect(name).toBeInTheDocument()
    await waitFor(() =>
      expect((screen.getByLabelText(/Scanner/) as HTMLSelectElement).value).toBe('port-scanner'),
    )
    await waitFor(() =>
      expect((screen.getByLabelText(/Target/) as HTMLInputElement).value).toBe('10.0.0.7'),
    )
  })
})
