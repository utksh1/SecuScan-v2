import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { FindingsPage } from '@/pages/Findings'
import { AuthProvider } from '@/auth/AuthContext'

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
  ],
  total: 2,
}

function renderPage(initialEntries: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={initialEntries}>
        <AuthProvider>
          <FindingsPage />
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
})
