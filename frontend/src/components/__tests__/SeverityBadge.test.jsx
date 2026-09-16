import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import SeverityBadge from '../SeverityBadge'

describe('SeverityBadge', () => {
  it('renders critical severity', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('renders high severity', () => {
    render(<SeverityBadge severity="high" />)
    expect(screen.getByText('high')).toBeInTheDocument()
  })

  it('renders medium severity', () => {
    render(<SeverityBadge severity="medium" />)
    expect(screen.getByText('medium')).toBeInTheDocument()
  })

  it('renders low severity', () => {
    render(<SeverityBadge severity="low" />)
    expect(screen.getByText('low')).toBeInTheDocument()
  })

  it('falls back to info styling for unknown severity', () => {
    const { container } = render(<SeverityBadge severity="unknown" />)
    expect(container.querySelector('.text-slate-400')).toBeInTheDocument()
  })

  it('normalizes uppercase to lowercase', () => {
    render(<SeverityBadge severity="CRITICAL" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('applies custom className', () => {
    const { container } = render(<SeverityBadge severity="high" className="custom-class" />)
    expect(container.firstChild).toHaveClass('custom-class')
  })

  it('defaults to info when no severity given', () => {
    render(<SeverityBadge />)
    expect(screen.getByText('info')).toBeInTheDocument()
  })
})
