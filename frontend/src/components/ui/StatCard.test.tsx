import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import StatCard from './StatCard'

describe('StatCard', () => {
  it('renders label and numeric value with locale formatting', () => {
    render(<StatCard label="Auth Events" value={1247} />)

    expect(screen.getByText('Auth Events')).toBeInTheDocument()
    expect(screen.getByText('1,247')).toBeInTheDocument()
  })

  it('renders string values unchanged', () => {
    render(<StatCard label="Status" value="HEALTHY" />)

    expect(screen.getByText('HEALTHY')).toBeInTheDocument()
  })

  it('renders an optional hint', () => {
    render(<StatCard label="Alerts" value={12} hint="last 24h" />)

    expect(screen.getByText('last 24h')).toBeInTheDocument()
  })

  it('omits the hint element when not provided', () => {
    const { container } = render(<StatCard label="Alerts" value={12} />)

    expect(container.querySelector('.stat-sub')).toBeNull()
  })
})
