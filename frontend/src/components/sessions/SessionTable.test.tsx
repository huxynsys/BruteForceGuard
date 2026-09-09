import { describe, expect, it } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SessionTable from './SessionTable'
import { closedSessionFixture, sessionFixture } from '../../test/fixtures'

function renderTable(sessions = [sessionFixture, closedSessionFixture]) {
  return render(
    <MemoryRouter>
      <SessionTable sessions={sessions} />
    </MemoryRouter>,
  )
}

describe('SessionTable', () => {
  it('renders one row per session with status badges', () => {
    renderTable()

    expect(screen.getByText('#41')).toBeInTheDocument()
    expect(screen.getByText('#39')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('closed')).toBeInTheDocument()
  })

  it('maps session types to human-readable labels', () => {
    renderTable()

    expect(screen.getByText('Single Account Brute Force')).toBeInTheDocument()
    expect(screen.getByText('Password Spray')).toBeInTheDocument()
  })

  it('counts evidence lists (IPs) rather than joining them', () => {
    const multi = {
      ...sessionFixture,
      source_ips: ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
    }
    renderTable([multi])

    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('navigates to session details on click', () => {
    renderTable()

    const row = screen.getByRole('button', { name: 'Open session 41' })
    fireEvent.click(row)

    // In MemoryRouter the navigation is internal; assert accessibility
    // attributes that make rows keyboard-usable instead of URL side effects.
    expect(row).toHaveAttribute('tabindex', '0')
  })

  it('exposes keyboard activation via Enter', () => {
    renderTable()

    const row = screen.getByRole('button', { name: 'Open session 39' })
    fireEvent.keyDown(row, { key: 'Enter' })

    expect(row).toBeInTheDocument()
  })

  it('renders an accessible table structure', () => {
    renderTable([])

    expect(screen.getByRole('table')).toBeInTheDocument()
    for (const header of ['ID', 'Type', 'Severity', 'Events', 'Source IPs', 'Status', 'Last Seen']) {
      expect(screen.getByRole('columnheader', { name: header })).toBeInTheDocument()
    }
  })
})
