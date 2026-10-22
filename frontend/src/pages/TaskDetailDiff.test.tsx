import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
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
  id: 't-2',
  user_id: 'u1',
  plugin_id: 'port-scanner',
  plugin_name: 'TCP Port Scanner',
  target: 'example.com',
  status: 'completed',
  inputs: { target: 'example.com' },
  options: {},
  exit_code: 0,
  stats: { findings: 4, duration_ms: 1200 },
  output_truncated: false,
  created_at: '2026-01-02T00:00:00Z',
  started_at: '2026-01-02T00:00:01Z',
  finished_at: '2026-01-02T00:00:02Z',
}

const DIFF = {
  task: { id: 't-2', plugin_id: 'port-scanner', plugin_name: 'TCP Port Scanner', target: 'example.com', created_at: '2026-01-02T00:00:00Z' },
  baseline: {
    id: 't-1',
    created_at: '2026-01-01T00:00:00Z',
    plugin_id: 'port-scanner',
    plugin_name: 'TCP Port Scanner',
    target: 'example.com',
    status: 'completed',
  },
  auto_baseline: true,
  summary: { new: 1, fixed: 1, regressed: 1, improved: 1, unchanged: 1 },
  items: [
    {
      status: 'new',
      finding: {
        id: 'f-5', task_id: 't-2', plugin_id: 'port-scanner', severity: 'low',
        kind: 'observation', analyst_status: 'new', category: 'Network Service',
        title: 'New port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-02T00:00:02Z',
      },
    },
    {
      status: 'regressed',
      previous_severity: 'high',
      finding: {
        id: 'f-6', task_id: 't-2', plugin_id: 'port-scanner', severity: 'critical',
        kind: 'suspected_issue', analyst_status: 'new', category: 'Network Service',
        title: 'Worse port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-02T00:00:02Z',
      },
      previous_finding: {
        id: 'f-2', task_id: 't-1', plugin_id: 'port-scanner', severity: 'high',
        kind: 'observation', analyst_status: 'new', category: 'Network Service',
        title: 'Worse port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-01T00:00:02Z',
      },
    },
    {
      status: 'fixed',
      previous_finding: {
        id: 'f-1', task_id: 't-1', plugin_id: 'port-scanner', severity: 'critical',
        kind: 'observation', analyst_status: 'new', category: 'Network Service',
        title: 'Gone port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-01T00:00:02Z',
      },
    },
    {
      status: 'improved',
      previous_severity: 'critical',
      finding: {
        id: 'f-7', task_id: 't-2', plugin_id: 'port-scanner', severity: 'low',
        kind: 'observation', analyst_status: 'new', category: 'Network Service',
        title: 'Better port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-02T00:00:02Z',
      },
      previous_finding: {
        id: 'f-4', task_id: 't-1', plugin_id: 'port-scanner', severity: 'critical',
        kind: 'observation', analyst_status: 'new', category: 'Network Service',
        title: 'Better port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-01T00:00:02Z',
      },
    },
    {
      status: 'unchanged',
      finding: {
        id: 'f-8', task_id: 't-2', plugin_id: 'port-scanner', severity: 'medium',
        kind: 'observation', analyst_status: 'new', category: 'Network Service',
        title: 'Same port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-02T00:00:02Z',
      },
      previous_finding: {
        id: 'f-3', task_id: 't-1', plugin_id: 'port-scanner', severity: 'medium',
        kind: 'observation', analyst_status: 'new', category: 'Network Service',
        title: 'Same port', description: '', remediation: '', proof: '',
        metadata: {}, created_at: '2026-01-01T00:00:02Z',
      },
    },
  ],
}

function setup(diffStatus: number = 200, diffBody: unknown = DIFF) {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      calls.push(`${init?.method ?? 'GET'} ${url}`)
      if (url.includes('/auth/refresh')) return route({ access_token: 't', user: ADMIN })
      if (url.includes('/workspaces'))
        return route({
          items: [],
          personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 },
        })
      if (url.includes('/diff')) {
        if (diffStatus !== 200)
          return route({ error: { code: diffStatus, message: 'no earlier completed run of `x` against `y` to diff against; pass ?against=<task_id> to compare with a specific run' } }, diffStatus)
        return route(diffBody)
      }
      if (url.match(/\/tasks\/[^/]+$/)) return route(TASK)
      if (url.includes('/findings')) return route({ items: [], total: 0 })
      return route({})
    }),
  )
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <WorkspaceProvider>
          <MemoryRouter initialEntries={['/tasks/t-2']}>
            <Routes>
              <Route path="/tasks/:id" element={<TaskDetailPage />} />
            </Routes>
          </MemoryRouter>
        </WorkspaceProvider>
      </AuthProvider>
    </QueryClientProvider>,
  )
  return { calls }
}

describe('TaskDetail — Diff tab', () => {
  beforeEach(() => localStorage.clear())
  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  it('shows the diff tab only for completed tasks and renders the diff on open', async () => {
    const { calls } = setup()
    // Header renders first.
    await waitFor(() => expect(screen.getByText('TCP Port Scanner')).toBeTruthy())
    // Diff tab is present for completed tasks.
    const diffTab = screen.getByRole('button', { name: /Diff vs previous run/i })
    expect(diffTab).toBeTruthy()
    // Not fetched until opened.
    expect(calls.some((c) => c.includes('/diff'))).toBe(false)

    fireEvent.click(diffTab)
    await waitFor(() => expect(screen.getByText('New port')).toBeTruthy())

    // Summary chips.
    expect(screen.getByText('1 new')).toBeTruthy()
    expect(screen.getByText('1 regressed')).toBeTruthy()
    expect(screen.getByText('1 fixed')).toBeTruthy()
    expect(screen.getByText('1 improved')).toBeTruthy()
    expect(screen.getByText('1 unchanged')).toBeTruthy()

    // Baseline link + auto-selected marker.
    expect(screen.getByText('auto-selected')).toBeTruthy()

    // All five item statuses rendered with their findings.
    expect(screen.getByText('Worse port')).toBeTruthy()
    expect(screen.getByText('Gone port')).toBeTruthy()
    expect(screen.getByText('Better port')).toBeTruthy()
    expect(screen.getByText('Same port')).toBeTruthy()

    // The diff endpoint was called once with the right path.
    expect(calls).toContainEqual('GET /api/v1/tasks/t-2/diff')
  })

  it('renders a friendly empty state when no baseline exists (404)', async () => {
    setup(404)
    await waitFor(() => expect(screen.getByText('TCP Port Scanner')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /Diff vs previous run/i }))
    await waitFor(() =>
      expect(
        screen.getByText(/No earlier completed run of this scanner against the same target/i),
      ).toBeTruthy(),
    )
  })
})
