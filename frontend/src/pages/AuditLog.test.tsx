import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import AuditLog from './AuditLog'
import { auditLogPageFixture, emptyAuditLogPageFixture } from '../test/fixtures'

// Mock at the API boundary so the test exercises the full render path:
// fetch -> hook -> page -> table rows -> expanded detail.
vi.mock('../api/audit', () => ({
  fetchAuditLog: vi.fn(),
}))

import { fetchAuditLog } from '../api/audit'

const mocked = {
  fetchAuditLog: vi.mocked(fetchAuditLog),
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AuditLog />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mocked.fetchAuditLog.mockResolvedValue(auditLogPageFixture)
})

describe('Audit log page (read-only evidence)', () => {
  it('renders the recorded evidence for every entry', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('analyst-1')).toBeInTheDocument()
    })

    // Newest-first first page, no filters applied.
    expect(mocked.fetchAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        skip: 0,
        limit: 25,
        action: undefined,
        result: undefined,
        user: undefined,
      }),
    )

    // Row content only: the filter dropdowns carry the same labels.
    const table = within(screen.getByRole('table'))

    // Action labels plus the raw codes the backend records.
    expect(table.getByText('Alert status change')).toBeInTheDocument()
    expect(table.getByText('alert.status_change')).toBeInTheDocument()
    expect(table.getByText('Authentication failed')).toBeInTheDocument()
    expect(table.getByText('IP blocked')).toBeInTheDocument()

    // Result badges stay text-first (never colour alone).
    expect(table.getAllByText('Success')).toHaveLength(2)
    expect(table.getByText('Denied')).toBeInTheDocument()

    // Roles and source IPs come straight from the stored row.
    expect(table.getByText('admin')).toBeInTheDocument()
    expect(table.getByText('203.0.113.7')).toBeInTheDocument()

    // Alert targets link to the investigation page; IP entries show the value.
    expect(screen.getByRole('link', { name: 'Alert #1' })).toHaveAttribute(
      'href',
      '/alerts/1',
    )
    expect(
      table.getByText('blacklist_entry 192.168.1.44'),
    ).toBeInTheDocument()
    expect(table.getByText('PATCH /api/v1/alerts/1')).toBeInTheDocument()

    // Detail summaries keep the server-side redaction visible.
    expect(table.getByText(/token=\[REDACTED\]/)).toBeInTheDocument()
    expect(table.getByText(/from_status=open/)).toBeInTheDocument()
  })

  it('expands an entry into the recorded detail and note', async () => {
    renderPage()

    const toggle = await screen.findByRole('button', {
      name: /Authentication failed/,
    })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(toggle)

    await waitFor(() => {
      expect(toggle).toHaveAttribute('aria-expanded', 'true')
    })

    expect(
      screen.getByText(/Analyst tokens cannot reopen closed alerts/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Recorded detail \(sanitized server-side\)/),
    ).toBeInTheDocument()
    expect(screen.getByText(/"token": "\[REDACTED\]"/)).toBeInTheDocument()

    fireEvent.click(toggle)
    await waitFor(() => {
      expect(toggle).toHaveAttribute('aria-expanded', 'false')
    })
    expect(
      screen.queryByText(/Analyst tokens cannot reopen closed alerts/),
    ).not.toBeInTheDocument()
  })

  it('passes the action and result filters to the API', async () => {
    renderPage()
    await screen.findByText('analyst-1')

    fireEvent.change(screen.getByLabelText('Filter by action'), {
      target: { value: 'auth.failed' },
    })

    await waitFor(() => {
      expect(mocked.fetchAuditLog).toHaveBeenLastCalledWith(
        expect.objectContaining({ action: 'auth.failed', skip: 0 }),
      )
    })

    fireEvent.change(screen.getByLabelText('Filter by result'), {
      target: { value: 'denied' },
    })

    await waitFor(() => {
      expect(mocked.fetchAuditLog).toHaveBeenLastCalledWith(
        expect.objectContaining({
          action: 'auth.failed',
          result: 'denied',
          skip: 0,
        }),
      )
    })
  })

  it('passes the trimmed actor filter to the API on submit', async () => {
    renderPage()
    await screen.findByText('analyst-1')

    fireEvent.change(screen.getByLabelText('Filter by actor'), {
      target: { value: '  analyst-1  ' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Filter' }))

    await waitFor(() => {
      expect(mocked.fetchAuditLog).toHaveBeenLastCalledWith(
        expect.objectContaining({ user: 'analyst-1', skip: 0 }),
      )
    })
  })

  it('sends the time range as an absolute instant', async () => {
    renderPage()
    await screen.findByText('analyst-1')

    fireEvent.change(screen.getByLabelText('Recorded at or after'), {
      target: { value: '2026-09-08T10:00' },
    })

    await waitFor(() => {
      expect(mocked.fetchAuditLog).toHaveBeenLastCalledWith(
        expect.objectContaining({
          since: new Date('2026-09-08T10:00').toISOString(),
        }),
      )
    })
  })

  it('pages server-side without changing the newest-first order', async () => {
    mocked.fetchAuditLog.mockResolvedValue({
      items: auditLogPageFixture.items,
      total: 60,
    })

    renderPage()

    await waitFor(() => {
      expect(screen.getByText(/Page 1 of 3/)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(mocked.fetchAuditLog).toHaveBeenLastCalledWith(
        expect.objectContaining({ skip: 25 }),
      )
    })
    expect(screen.getByText(/Page 2 of 3/)).toBeInTheDocument()
  })

  it('shows the empty state when nothing has been audited yet', async () => {
    mocked.fetchAuditLog.mockResolvedValue(emptyAuditLogPageFixture)

    renderPage()

    await waitFor(() => {
      expect(screen.getByText('No audited actions yet')).toBeInTheDocument()
    })
  })

  it('offers a clear-filters action when filters exclude everything', async () => {
    renderPage()
    await screen.findByText('analyst-1')

    mocked.fetchAuditLog.mockResolvedValue(emptyAuditLogPageFixture)

    fireEvent.change(screen.getByLabelText('Filter by action'), {
      target: { value: 'auth.login' },
    })

    await waitFor(() => {
      expect(
        screen.getByText('No entries match these filters'),
      ).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Show all entries' }))

    await waitFor(() => {
      expect(mocked.fetchAuditLog).toHaveBeenLastCalledWith(
        expect.objectContaining({
          action: undefined,
          result: undefined,
          user: undefined,
        }),
      )
    })
  })

  it('surfaces the authentication requirement when the API rejects the read', async () => {
    mocked.fetchAuditLog.mockRejectedValue(
      new Error('Reading the audit log requires the admin role.'),
    )

    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    expect(screen.getByText('Unable to load data')).toBeInTheDocument()
    expect(screen.getByText(/requires the admin role/)).toBeInTheDocument()
  })

  it('keeps stale entries visible with a warning when a refresh fails', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('analyst-1')).toBeInTheDocument()
    })

    mocked.fetchAuditLog.mockRejectedValue(new Error('boom'))

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))

    await waitFor(() => {
      expect(
        screen.getByText(/Showing the last loaded entries/),
      ).toBeInTheDocument()
    })
    expect(screen.getByText('analyst-1')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load data')).not.toBeInTheDocument()
  })
})
