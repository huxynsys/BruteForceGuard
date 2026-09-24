import { describe, expect, it, vi } from 'vitest'
import { render, screen, within, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AlertTable from './AlertTable'
import type { Alert, AlertStatus } from '../../types'
import { alertFixture } from '../../test/fixtures'

const noop = vi.fn()

function renderTable(
  alerts: Alert[] = [alertFixture],
  {
    onStatusChange = noop,
    pendingId = null,
  }: {
    onStatusChange?: (alert: Alert, status: AlertStatus) => void
    pendingId?: number | null
  } = {},
) {
  return render(
    <MemoryRouter initialEntries={['/alerts']}>
      <Routes>
        <Route
          path="/alerts"
          element={
            <AlertTable
              alerts={alerts}
              onStatusChange={onStatusChange}
              pendingId={pendingId}
            />
          }
        />
        <Route path="/alerts/:id" element={<div>ALERT DETAIL PAGE</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('AlertTable', () => {
  it('renders the work-queue column headers', () => {
    renderTable()

    for (const header of [
      'Timestamp',
      'Severity',
      'Detection Type',
      'Source IP',
      'Username',
      'Failed Attempts',
      'Status',
      'Actions',
    ]) {
      expect(
        screen.getByRole('columnheader', { name: header }),
      ).toBeInTheDocument()
    }
  })

  it('renders one row per alert with human-readable detection labels', () => {
    renderTable([
      alertFixture,
      { ...alertFixture, id: 2, alert_type: 'failed_then_success' },
    ])

    // header row + 2 alert rows
    expect(screen.getAllByRole('row')).toHaveLength(3)

    expect(screen.getByText('Single Account Brute Force')).toBeInTheDocument()
    expect(screen.getByText('Failed -> Success')).toBeInTheDocument()
  })

  it('shows the alert data values', () => {
    renderTable()

    expect(screen.getByText('192.168.1.44')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
    // failed attempts come from the detection evidence
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('Open')).toBeInTheDocument()
  })

  it('renders em-dash placeholders for missing values', () => {
    renderTable([
      { ...alertFixture, source_ip: null, username: null, evidence: {} },
    ])

    const row = screen.getAllByRole('row')[1]
    expect(within(row).getAllByText('—')).toHaveLength(3)
  })

  it('renders an empty tbody when no alerts exist', () => {
    const { container } = renderTable([])

    expect(container.querySelector('tbody')?.children).toHaveLength(0)
  })

  it('offers View details, Acknowledge and Resolve actions', () => {
    renderTable()

    expect(
      screen.getByRole('link', { name: 'View details for alert 1' }),
    ).toHaveAttribute('href', '/alerts/1')
    expect(
      screen.getByRole('button', { name: 'Acknowledge alert 1' }),
    ).toBeEnabled()
    expect(
      screen.getByRole('button', { name: 'Resolve alert 1' }),
    ).toBeEnabled()
  })

  it('reports the acknowledged transition through onStatusChange without navigating', () => {
    const onStatusChange = vi.fn()
    renderTable([alertFixture], { onStatusChange })

    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge alert 1' }))

    expect(onStatusChange).toHaveBeenCalledWith(alertFixture, 'acknowledged')
    expect(screen.queryByText('ALERT DETAIL PAGE')).not.toBeInTheDocument()
  })

  it('reports the resolved transition through onStatusChange', () => {
    const onStatusChange = vi.fn()
    renderTable([alertFixture], { onStatusChange })

    fireEvent.click(screen.getByRole('button', { name: 'Resolve alert 1' }))

    expect(onStatusChange).toHaveBeenCalledWith(alertFixture, 'resolved')
  })

  it('hides Acknowledge for already-acknowledged alerts', () => {
    renderTable([{ ...alertFixture, id: 9, status: 'acknowledged' }])

    expect(
      screen.getByRole('button', { name: 'Acknowledge alert 9' }),
    ).toBeDisabled()
    expect(
      screen.getByRole('button', { name: 'Resolve alert 9' }),
    ).toBeEnabled()
  })

  it('disables both transitions for closed alerts', () => {
    renderTable([{ ...alertFixture, id: 10, status: 'resolved' }])

    expect(
      screen.getByRole('button', { name: 'Acknowledge alert 10' }),
    ).toBeDisabled()
    expect(
      screen.getByRole('button', { name: 'Resolve alert 10' }),
    ).toBeDisabled()
  })

  it('disables and marks the actions of the alert currently being updated', () => {
    renderTable([alertFixture], { pendingId: alertFixture.id })

    expect(
      screen.getByRole('button', { name: 'Acknowledge alert 1' }),
    ).toBeDisabled()
    expect(
      screen.getByRole('button', { name: 'Acknowledge alert 1' }),
    ).toHaveAttribute('aria-busy', 'true')
    expect(
      screen.getByRole('button', { name: 'Resolve alert 1' }),
    ).toBeDisabled()
  })
})
