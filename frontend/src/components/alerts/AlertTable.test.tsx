import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import AlertTable from './AlertTable'
import { alertFixture, criticalAlertFixture } from '../../test/fixtures'

describe('AlertTable', () => {
  it('renders column headers', () => {
    render(<AlertTable alerts={[alertFixture]} />)

    for (const header of [
      'Severity',
      'Detection',
      'Source IP',
      'Username',
      'Service',
      'Confidence',
      'Time',
    ]) {
      expect(
        screen.getByRole('columnheader', { name: header }),
      ).toBeInTheDocument()
    }
  })

  it('renders one row per alert with human-readable detection labels', () => {
    render(<AlertTable alerts={[alertFixture, criticalAlertFixture]} />)

    const rows = screen.getAllByRole('row')
    // header row + 2 alert rows
    expect(rows).toHaveLength(3)

    expect(screen.getByText('Single Account Brute Force')).toBeInTheDocument()
    expect(screen.getByText('Failed -> Success')).toBeInTheDocument()
  })

  it('shows alert data values', () => {
    render(<AlertTable alerts={[alertFixture]} />)

    expect(screen.getByText('192.168.1.44')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('SSH')).toBeInTheDocument()
    expect(screen.getByText('65%')).toBeInTheDocument()
  })

  it('renders em-dash placeholders for missing values', () => {
    const empty = { ...alertFixture, source_ip: null, username: null, service: null }
    render(<AlertTable alerts={[empty]} />)

    const row = screen.getAllByRole('row')[1]
    expect(within(row).getAllByText('—')).toHaveLength(3)
  })

  it('renders an empty tbody when no alerts exist', () => {
    const { container } = render(<AlertTable alerts={[]} />)

    expect(container.querySelector('tbody')?.children).toHaveLength(0)
  })
})
