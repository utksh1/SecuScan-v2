import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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
      presets: {
        quick: { target: '127.0.0.1', safe_mode: false },
        deep: { safe_mode: true },
      },
      preset_meta: {
        quick: {
          label: 'Quick',
          description: 'Fast top-port triage profile.',
          badge: 'fast',
        },
        deep: {
          label: 'Deep',
          description: 'Full port set with longer timeouts.',
          badge: 'thorough',
        },
      },
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
    {
      // v4.2.2: a second scanner in a DIFFERENT category so the grouped
      // browser (and its profile chips) can be tested end-to-end.
      id: 'http-headers-x',
      name: 'HTTP Headers X',
      version: '1.0.0',
      description: 'audit security headers',
      category: 'web',
      tags: [],
      engine: { type: 'native', native: 'http_headers', timeout_seconds: 60 },
      fields: [
        {
          id: 'target',
          label: 'Target URL',
          type: 'string',
          required: true,
          pattern: '.*',
        },
      ],
      presets: {
        quick: { follow_redirects: false, timeout_ms: 5000 },
        full: { follow_redirects: true, timeout_ms: 15000 },
      },
      preset_meta: {
        quick: {
          label: 'Quick',
          description: 'First response only.',
          badge: 'fast',
        },
        full: {
          label: 'Full',
          description: 'Follow the redirect chain.',
          badge: 'thorough',
        },
      },
      safety: {
        level: 'safe',
        requires_consent: true,
        consent_message: 'Only scan authorized targets.',
        allowed_targets: [],
        max_concurrent: 4,
        max_per_hour: 120,
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

/** The step-2 profile card grid (scoped so browser chips don't collide). */
function profileCards() {
  return within(screen.getByRole('group', { name: 'Scan profile' }))
}

/** The step-1 category-grouped scanner browser. */
function scannerBrowser() {
  return within(screen.getByRole('group', { name: 'Browse scanners by category' }))
}

async function loaded() {
  await waitFor(() => {
    expect(screen.getAllByText(/TCP Port Scanner/).length).toBeGreaterThan(0)
  })
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
    await loaded()
    expect(screen.getByLabelText(/^target/i)).toBeInTheDocument()
  })

  it('blocks start until consent is granted', async () => {
    renderPage()
    await loaded()
    const start = screen.getByRole('button', { name: /start scan/i })
    expect(start).toBeDisabled()

    // grant consent (the authorization checkbox, not the safe_mode field)
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized to scan/i }))
    expect(start).toBeEnabled()
  })

  it('sends consent + inputs to the API', async () => {
    renderPage()
    await loaded()
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
    await loaded()
    await userEvent.click(screen.getByRole('button', { name: /preview command/i }))
    await waitFor(() => {
      expect(screen.getByText('native:port_scanner')).toBeInTheDocument()
    })
  })

  it('renders scan profile cards with labels, badges and a Custom option', async () => {
    renderPage()
    await loaded()
    // Profile cards render the human labels + badges from preset_meta.
    const cards = profileCards()
    expect(cards.getByText('Quick')).toBeInTheDocument()
    expect(cards.getByText('Deep')).toBeInTheDocument()
    expect(cards.getByText(/fast top-port triage profile/i)).toBeInTheDocument()
    expect(cards.getAllByText('fast').length).toBeGreaterThan(0) // badge chip
    expect(cards.getByText('Custom')).toBeInTheDocument()
  })

  it('shows estimated runtime hints derived from the profile badge', async () => {
    renderPage()
    await loaded()
    // v4.2.2: each profile card carries a badge-derived ETA hint.
    const cards = profileCards()
    expect(cards.getByText(/est\. seconds/i)).toBeInTheDocument() // fast badge
    expect(cards.getByText(/est\. a few minutes/i)).toBeInTheDocument() // thorough badge
  })

  it('renders the category-grouped scanner browser with profile chips', async () => {
    renderPage()
    await loaded()
    // v4.2.2: scanners are grouped by category (network before web), each
    // row surfacing its scan profiles as chips.
    const browser = scannerBrowser()
    expect(browser.getByText('Network')).toBeInTheDocument()
    expect(browser.getByText('Web')).toBeInTheDocument()
    // Every chip is reachable via its contextual aria-label.
    expect(
      browser.getByRole('button', { name: 'TCP Port Scanner: Quick profile' }),
    ).toBeInTheDocument()
    expect(
      browser.getByRole('button', { name: 'HTTP Headers X: Full profile' }),
    ).toBeInTheDocument()
  })

  it('clicking a profile chip jumps to that scanner with the preset applied', async () => {
    renderPage()
    await loaded()
    // Click the Full chip of the (not yet selected) web scanner.
    await userEvent.click(
      scannerBrowser().getByRole('button', { name: 'HTTP Headers X: Full profile' }),
    )
    // The scanner switch landed and the Full profile is applied: the
    // follow_redirects default (absent on this plugin's fields, seeded
    // from the preset values map) is visible in the task payload.
    await userEvent.type(screen.getByLabelText(/^target/i), 'https://example.com')
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized to scan/i }))
    await userEvent.click(screen.getByRole('button', { name: /start scan/i }))

    await waitFor(() => {
      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [string, RequestInit][]
      const taskCall = calls.find(([u]) => String(u).endsWith('/tasks'))
      expect(taskCall).toBeTruthy()
      if (!taskCall) throw new Error('no task call recorded')
      const body = JSON.parse(taskCall[1].body as string)
      expect(body.plugin_id).toBe('http-headers-x')
      expect(body.preset).toBe('full')
      expect(body.inputs.follow_redirects).toBe(true)
      expect(body.inputs.timeout_ms).toBe('15000')
    })
  })

  it('clicking a chip for the already-selected scanner applies the preset directly', async () => {
    renderPage()
    await loaded()
    // port-scanner is preselected via ?plugin=; its Quick chip must apply
    // without a plugin switch.
    await userEvent.click(
      scannerBrowser().getByRole('button', { name: 'TCP Port Scanner: Quick profile' }),
    )
    await waitFor(() => {
      expect(screen.getByLabelText(/^target/i)).toHaveValue('127.0.0.1')
    })
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized to scan/i }))
    await userEvent.click(screen.getByRole('button', { name: /start scan/i }))

    await waitFor(() => {
      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [string, RequestInit][]
      const taskCall = calls.find(([u]) => String(u).endsWith('/tasks'))
      expect(taskCall).toBeTruthy()
      if (!taskCall) throw new Error('no task call recorded')
      const body = JSON.parse(taskCall[1].body as string)
      expect(body.plugin_id).toBe('port-scanner')
      expect(body.preset).toBe('quick')
      expect(body.inputs.safe_mode).toBe(false)
    })
  })

  it('applying a profile seeds the form and sends the preset with the task', async () => {
    renderPage()
    await loaded()
    // Click the Quick profile card (in the step-2 card grid).
    await userEvent.click(profileCards().getByRole('button', { name: /quick/i }))
    // The target field is seeded from the preset.
    await waitFor(() => {
      expect(screen.getByLabelText(/^target/i)).toHaveValue('127.0.0.1')
    })
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized to scan/i }))
    await userEvent.click(screen.getByRole('button', { name: /start scan/i }))

    await waitFor(() => {
      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [string, RequestInit][]
      const taskCall = calls.find(([u]) => String(u).endsWith('/tasks'))
      expect(taskCall).toBeTruthy()
      if (!taskCall) throw new Error('no task call recorded')
      const body = JSON.parse(taskCall[1].body as string)
      expect(body.preset).toBe('quick')
      expect(body.inputs.target).toBe('127.0.0.1')
      expect(body.inputs.safe_mode).toBe(false)
    })
  })

  it('switching back to Custom clears the preset selection', async () => {
    renderPage()
    await loaded()
    await userEvent.click(profileCards().getByRole('button', { name: /quick/i }))
    await waitFor(() => {
      expect(screen.getByLabelText(/^target/i)).toHaveValue('127.0.0.1')
    })
    // Switch to Custom.
    await userEvent.click(profileCards().getByRole('button', { name: /custom/i }))
    await userEvent.click(screen.getByRole('checkbox', { name: /authorized to scan/i }))
    await userEvent.type(screen.getByLabelText(/^target/i), '127.0.0.1')
    await userEvent.click(screen.getByRole('button', { name: /start scan/i }))

    await waitFor(() => {
      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [string, RequestInit][]
      const taskCall = calls.find(([u]) => String(u).endsWith('/tasks'))
      expect(taskCall).toBeTruthy()
      if (!taskCall) throw new Error('no task call recorded')
      const body = JSON.parse(taskCall[1].body as string)
      expect(body.preset).toBeUndefined()
    })
  })
})
