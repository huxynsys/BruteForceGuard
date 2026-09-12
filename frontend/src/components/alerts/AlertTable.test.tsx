import { describe, expect, it, vi } from 'vitest'
import { render, screen, within, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AlertTable from './AlertTable'
import { alertFixture, criticalAlertFixture } from '../../test/fixtures'

function renderWithRouter(alerts = [alertFixture]) {
  return render(
    <MemoryRouter initialEntries={['/alerts']}>
      <Routes>
        <Route path="/alerts" element={<AlertTable alerts={alerts} />} />
        <Route path="/alerts/:id" element={<div>ALERT DETAIL PAGE</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('AlertTable', () => {
  it('renders column headers', () => {
    renderWithRouter()

    for (const header of [
      'Severity',
      'Detection',
      'Source IP',
      'Username',
      'Service',
      'Confidence',
      'Risk',
      'Time',
    ]) {
      expect(
        screen.getByRole('columnheader', { name: header }),
      ).toBeInTheDocument()
    }
  })

  it('renders one row per alert with human-readable detection labels', () => {
    renderWithRouter([alertFixture, criticalAlertFixture])

    const rows = screen.getAllByRole('row')
    // header row + 2 alert rows
    expect(rows).toHaveLength(3)

    expect(screen.getByText('Single Account Brute Force')).toBeInTheDocument()
    expect(screen.getByText('Failed -> Success')).toBeInTheDocument()
  })

  it('shows alert data values', () => {
    renderWithRouter()

    expect(screen.getByText('192.168.1.44')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('SSH')).toBeInTheDocument()
    expect(screen.getByText('65%')).toBeInTheDocument()
  })

  it('shows the Phase 7 risk score column', () => {
    renderWithRouter()
    expect(screen.getByRole('columnheader', { name: 'Risk' })).toBeInTheDocument()
    expect(screen.getByText('72')).toBeInTheDocument()
  })

  it('renders em-dash placeholders for missing values', () => {
    const empty = { ...alertFixture, source_ip: null, username: null, service: null }
    renderWithRouter([empty])

    const row = screen.getAllByRole('row')[1]
    expect(within(row).getAllByText('—')).toHaveLength(3)
  })

  it('renders an empty tbody when no alerts exist', () => {
    const { container } = renderWithRouter([])

    expect(container.querySelector('tbody')?.children).toHaveLength(0)
  })

  it('navigates to the alert detail page when a row is clicked', () => {
    renderWithRouter()

    fireEvent.click(screen.getByLabelText('Open alert 1'))

    expect(screen.getByText('ALERT DETAIL PAGE')).toBeInTheDocument()
  })
})
