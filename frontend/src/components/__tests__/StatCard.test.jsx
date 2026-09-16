import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import StatCard from '../StatCard'

describe('StatCard', () => {
  it('renders label and value', () => {
    render(<StatCard label="Total Alerts" value={42} />)
    expect(screen.getByText('Total Alerts')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders subtitle', () => {
    render(<StatCard label="Events" value={1000} sub="last 24h" />)
    expect(screen.getByText('last 24h')).toBeInTheDocument()
  })

  it('renders hint', () => {
    render(<StatCard label="Risk" value="Low" hint="No action required" />)
    expect(screen.getByText('No action required')).toBeInTheDocument()
  })

  it('renders with icon', () => {
    render(<StatCard label="Agents" value={10} icon="🖥️" />)
    expect(screen.getByText('🖥️')).toBeInTheDocument()
  })

  it('renders string values', () => {
    render(<StatCard label="Status" value="Operational" />)
    expect(screen.getByText('Operational')).toBeInTheDocument()
  })

  it('renders zero value', () => {
    render(<StatCard label="Errors" value={0} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })

  it('applies accent color class', () => {
    const { container } = render(<StatCard label="Test" value={1} accent="text-emerald-400" />)
    expect(container.querySelector('.text-emerald-400')).toBeInTheDocument()
  })
})
