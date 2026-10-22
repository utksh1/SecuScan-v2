import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { LoginPage } from '@/pages/Login'
import { AuthProvider } from '@/auth/AuthContext'

function renderLogin() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/login']}>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('LoginPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: 401, message: 'invalid email or password' } }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    )
  })
  afterEach(() => vi.unstubAllGlobals())

  it('disables submit until both fields are filled', async () => {
    renderLogin()
    const submit = screen.getByRole('button', { name: /sign in/i })
    expect(submit).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/email/i), 'admin@test.local')
    expect(submit).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/password/i), 'secret')
    expect(submit).toBeEnabled()
  })

  it('shows an error message on failed login', async () => {
    renderLogin()
    await userEvent.type(screen.getByLabelText(/email/i), 'admin@test.local')
    await userEvent.type(screen.getByLabelText(/password/i), 'wrong-password')
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('invalid email or password')
    })
  })

  it('does not submit an invalid email', async () => {
    renderLogin()
    await userEvent.type(screen.getByLabelText(/email/i), 'not-an-email')
    await userEvent.type(screen.getByLabelText(/password/i), 'secret')
    expect(screen.getByRole('button', { name: /sign in/i })).toBeDisabled()
  })
})
