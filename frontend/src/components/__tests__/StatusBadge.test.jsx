import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import StatusBadge from '../StatusBadge'

describe('StatusBadge', () => {
  it('renders open status', () => {
    render(<StatusBadge status="open" />)
    expect(screen.getByText('open')).toBeInTheDocument()
  })

  it('renders in_progress status', () => {
    render(<StatusBadge status="in_progress" />)
    expect(screen.getByText('in_progress')).toBeInTheDocument()
  })

  it('renders closed status', () => {
    render(<StatusBadge status="closed" />)
    expect(screen.getByText('closed')).toBeInTheDocument()
  })

  it('renders resolved status', () => {
    render(<StatusBadge status="resolved" />)
    expect(screen.getByText('resolved')).toBeInTheDocument()
  })

  it('renders investigating status', () => {
    render(<StatusBadge status="investigating" />)
    expect(screen.getByText('investigating')).toBeInTheDocument()
  })

  it('falls back to open for unknown status', () => {
    render(<StatusBadge status="unknown" />)
    expect(screen.getByText('unknown')).toBeInTheDocument()
  })

  it('normalizes uppercase', () => {
    render(<StatusBadge status="OPEN" />)
    expect(screen.getByText('open')).toBeInTheDocument()
  })

  it('applies custom className', () => {
    const { container } = render(<StatusBadge status="open" className="test" />)
    expect(container.firstChild).toHaveClass('test')
  })
})
