import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from '@/components/SeverityBadge'
import { StatusBadge } from '@/components/StatusBadge'
import { SafetyBadge } from '@/components/SafetyBadge'

describe('SeverityBadge', () => {
  it.each(['critical', 'high', 'medium', 'low', 'info'] as const)(
    'renders %s with the right class',
    (sev) => {
      render(<SeverityBadge severity={sev} />)
      const el = screen.getByTestId(`severity-${sev}`)
      expect(el).toHaveTextContent(sev)
    },
  )

  it('falls back to info styling for unknown values', () => {
    render(<SeverityBadge severity="weird" />)
    expect(screen.getByTestId('severity-weird')).toHaveTextContent('weird')
  })
})

describe('StatusBadge', () => {
  it('shows running with spinner', () => {
    render(<StatusBadge status="running" />)
    expect(screen.getByText('running')).toBeInTheDocument()
  })
  it('shows completed', () => {
    render(<StatusBadge status="completed" />)
    expect(screen.getByText('completed')).toBeInTheDocument()
  })
})

describe('SafetyBadge', () => {
  it('labels exploit level', () => {
    render(<SafetyBadge level="exploit" />)
    expect(screen.getByText('exploit')).toBeInTheDocument()
  })
  it('labels safe level', () => {
    render(<SafetyBadge level="safe" />)
    expect(screen.getByText('safe')).toBeInTheDocument()
  })
})
