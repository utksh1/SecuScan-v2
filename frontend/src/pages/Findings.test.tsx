import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { FindingsPage } from '@/pages/Findings'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'

const FINDINGS = {
  items: [
    {
      id: 'f1',
      task_id: 't1',
      plugin_id: 'port-scanner',
      severity: 'critical',
      kind: 'suspected_issue',
      analyst_status: 'new',
      category: 'Injection',
      title: 'SQLi confirmed',
      description: 'x',
      remediation: 'y',
      proof: 'z',
      metadata: {},
      created_at: new Date().toISOString(),
    },
    {
      id: 'f2',
      task_id: 't1',
      plugin_id: 'http-headers',
      severity: 'high',
      kind: 'observation',
      analyst_status: 'new',
      category: 'HTTP',
      title: 'Missing HSTS',
      description: 'x',
      remediation: 'y',
      proof: 'z',
      metadata: {},
      created_at: new Date().toISOString(),
    },
    {
      id: 'fp1',
      task_id: 't1',
      plugin_id: 'website-scanner',
      severity: 'medium',
      kind: 'suspected_issue',
      analyst_status: 'false_positive',
      category: 'XSS',
      title: 'Reflected input (XSS candidate)',
      description: 'x',
      remediation: 'y',
      proof: 'z',
      metadata: {},
      created_at: new Date().toISOString(),
    },
  ],
  total: 3,
}

// Single-finding GET payload carrying the FP-memory audit trail
// (Max-Parity Sprint 1.1 task 1.3).
const FP_FINDING_DETAIL = {
  ...FINDINGS.items[2],
  fp_memory: {
    decided_by: 'u1',
    decided_by_email: 'analyst@corp.test',
    decided_at: '2026-10-01T12:00:00Z',
    reason: 'reflected only in our canary, not attacker-controllable',
  },
}

function renderPage(initialEntries: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={initialEntries}>
        <AuthProvider>
          <WorkspaceProvider>
            <FindingsPage />
          </WorkspaceProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('FindingsPage — filter → API contract', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/auth/refresh')) {
          return new Response(
            JSON.stringify({
              access_token: 't',
              user: { id: 'u1', email: 'a@b.c', name: 'A', role: 'scanner', created_at: '' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          )
        }
        if (url.includes('/workspaces')) {
          return new Response(
            JSON.stringify({
              items: [],
              personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          )
        }
        if (url.includes('/findings/fp1')) {
          return new Response(JSON.stringify(FP_FINDING_DETAIL), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        }
        if (url.includes('/findings')) {
          return new Response(JSON.stringify(FINDINGS), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        }
        return new Response(JSON.stringify({}), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('sends repeated severity params for the multi-severity URL', async () => {
    renderPage(['/findings?severity=critical&severity=high'])
    await waitFor(() => {
      expect(screen.getByText('SQLi confirmed')).toBeInTheDocument()
    })
    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [string][]
    const findingsCall = calls.find(([u]) => u.includes('/findings'))
    expect(findingsCall).toBeTruthy()
    const url = new URL(findingsCall![0], 'http://x')
    // the backend accepts repeated severity values (Vec<String>)
    expect(url.searchParams.getAll('severity')).toEqual(['critical', 'high'])
  })

  it('sends a single severity param as-is', async () => {
    renderPage(['/findings?severity=critical'])
    await waitFor(() => {
      expect(screen.getByText('SQLi confirmed')).toBeInTheDocument()
    })
    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [string][]
    const url = new URL(calls.find(([u]) => u.includes('/findings'))![0], 'http://x')
    expect(url.searchParams.getAll('severity')).toEqual(['critical'])
  })

  it('renders severity badges and triage dropdowns', async () => {
    renderPage(['/findings'])
    await waitFor(() => {
      expect(screen.getByTestId('severity-critical')).toBeInTheDocument()
      expect(screen.getByTestId('severity-high')).toBeInTheDocument()
    })
    expect(screen.getByText('SQLi confirmed')).toBeInTheDocument()
    expect(screen.getByText('Missing HSTS')).toBeInTheDocument()
  })

  it('collects a reason when marking false_positive and sends it in the PATCH body', async () => {
    // Max-Parity Sprint 1.1 task 1.3: selecting false_positive opens an
    // inline reason input; Mark FP sends { analyst_status, reason }.
    renderPage(['/findings'])
    await waitFor(() => {
      expect(screen.getByText('SQLi confirmed')).toBeInTheDocument()
    })
    const select = screen.getAllByLabelText('Triage')[0]
    fireEvent.change(select, { target: { value: 'false_positive' } })
    const reasonInput = await screen.findByLabelText('False-positive reason')
    expect(reasonInput).toBeInTheDocument()
    fireEvent.change(reasonInput, { target: { value: 'benign banner text' } })
    fireEvent.click(screen.getByRole('button', { name: /Mark FP/i }))
    await waitFor(() => {
      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [
        string,
        RequestInit,
      ][]
      const patch = calls.find(([u]) => u.includes('/findings/f1/triage'))
      expect(patch).toBeTruthy()
      const body = JSON.parse(patch![1].body as string)
      expect(body.analyst_status).toBe('false_positive')
      expect(body.reason).toBe('benign banner text')
    })
  })

  it('shows the FP-memory audit trail in the expanded false-positive row', async () => {
    // The expanded row lazy-fetches GET /findings/:id and renders who
    // marked the FP, when, and why.
    renderPage(['/findings'])
    await waitFor(() => {
      expect(screen.getByText('Reflected input (XSS candidate)')).toBeInTheDocument()
    })
    // The title cell sits in the clickable <tr>; click it to expand.
    fireEvent.click(screen.getByText('Reflected input (XSS candidate)'))
    const audit = await screen.findByTestId('fp-audit')
    expect(audit).toBeInTheDocument()
    expect(audit.textContent).toContain('analyst@corp.test')
    expect(audit.textContent).toContain('reflected only in our canary, not attacker-controllable')
    expect(audit.textContent).toContain('auto-suppress')
  })
})
