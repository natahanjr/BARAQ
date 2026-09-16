import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import RiskBadge from '../RiskBadge'

describe('RiskBadge', () => {
  it('renders CRITICAL level', () => {
    render(<RiskBadge level="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('renders HIGH level', () => {
    render(<RiskBadge level="HIGH" />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('renders MEDIUM level', () => {
    render(<RiskBadge level="MEDIUM" />)
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
  })

  it('renders LOW level', () => {
    render(<RiskBadge level="LOW" />)
    expect(screen.getByText('LOW')).toBeInTheDocument()
  })

  it('shows score when provided', () => {
    render(<RiskBadge level="HIGH" score={85} />)
    expect(screen.getByText('85')).toBeInTheDocument()
  })

  it('formats score to integer', () => {
    render(<RiskBadge level="MEDIUM" score={42.7} />)
    expect(screen.getByText('43')).toBeInTheDocument()
  })

  it('normalizes lowercase to uppercase', () => {
    render(<RiskBadge level="critical" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('defaults to LOW styling for unknown level', () => {
    const { container } = render(<RiskBadge level="UNKNOWN" />)
    expect(container.querySelector('.text-emerald-300')).toBeInTheDocument()
  })
})
