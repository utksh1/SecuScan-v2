import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { NewTaskPage } from '@/pages/NewTask'
import { AuthProvider } from '@/auth/AuthContext'
import { WorkspaceProvider } from '@/auth/WorkspaceContext'

const PLUGINS = {
  items: [
    {
      id: 'port-scanner',
      name: 'TCP Port Scanner',
      version: '1.0.0',
      description: 'scan ports',
      category: 'network',
      tags: [],
      engine: { type: 'native', native: 'port_scanner', timeout_seconds: 600 },
      fields: [
        {
          id: 'target',
          label: 'Target',
          type: 'string',
          required: true,
          pattern: '^[a-zA-Z0-9.]+$',
        },
        { id: 'safe_mode', label: 'Safe mode', type: 'boolean', required: false, default: true },
      ],
      presets: { quick: { target: '127.0.0.1' } },
      safety: {
        level: 'safe',
        requires_consent: true,
        consent_message: 'Only scan authorized targets.',
        allowed_targets: ['127.0.0.1'],
        max_concurrent: 4,
        max_per_hour: 60,
        capabilities: ['network'],
      },
      dependencies: { binaries: [] },
      available: true,
      missing_binaries: [],
      enabled: true,
    },
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
    <MemoryRouter initialEntries={['/tasks/new?plugin=port-scanner']}>
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <WorkspaceProvider>
            <NewTaskPage />
          </WorkspaceProvider>
        </AuthProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('NewTaskPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/auth/refresh')) {
          return route({
            access_token: 'test-token',
            user: { id: 'u1', email: 'a@b.c', name: 'A', role: 'scanner', created_at: '' },
          })
        }
        if (url.includes('/workspaces')) {
          return route({ items: [], personal: { id: null, name: 'Personal', tasks_total: 0, tasks_active: 0 } })
        }
        if (url.includes('/preview')) {
          return route({ command: 'native:port_scanner' })
        }
        if (url.includes('/plugins')) {
          return route(PLUGINS)
        }
        if (url.includes('/tasks') && !url.includes('/tasks/new')) {
          return route({ id: 'new-task-id' }, 201)
        }
        return route({})
      }),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('renders the wizard with the preselected plugin', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/TCP Port Scanner/)).toBeInTheDocument()
    })
    expect(screen.getByLabelText(/^target/i)).toBeInTheDocument()
  })

  it('blocks start until consent is granted', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/TCP Port Scanner/)).toBeInTheDocument()
    })
    const start = screen.getByRole('button', { name: /start scan/i })
    expect(start).toBeDisabled()

    // grant consent (the authorization checkbox, not the safe_mode field)
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized to scan/i }))
    expect(start).toBeEnabled()
  })

  it('sends consent + inputs to the API', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/TCP Port Scanner/)).toBeInTheDocument()
    })
    await userEvent.type(screen.getByLabelText(/^target/i), '127.0.0.1')
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized to scan/i }))
    await userEvent.click(screen.getByRole('button', { name: /start scan/i }))

    await waitFor(() => {
      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [string, RequestInit][]
      const taskCall = calls.find(([u]) => String(u).endsWith('/tasks'))
      expect(taskCall).toBeTruthy()
      if (!taskCall) throw new Error('no task call recorded')
      const body = JSON.parse(taskCall[1].body as string)
      expect(body.plugin_id).toBe('port-scanner')
      expect(body.consent_granted).toBe(true)
      expect(body.inputs.target).toBe('127.0.0.1')
    })
  })

  it('shows the command preview', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/TCP Port Scanner/)).toBeInTheDocument()
    })
    await userEvent.click(screen.getByRole('button', { name: /preview command/i }))
    await waitFor(() => {
      expect(screen.getByText('native:port_scanner')).toBeInTheDocument()
    })
  })
})
