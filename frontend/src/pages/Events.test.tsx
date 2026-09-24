import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import Events from './Events'
import { eventGroupsFixture, emptyEventGroupsFixture } from '../test/fixtures'

// Mock at the API boundary so the test exercises the full render path:
// fetch -> hook -> page -> group rows -> expanded event table.
vi.mock('../api/events', () => ({
  fetchEventGroups: vi.fn(),
}))

import { fetchEventGroups } from '../api/events'

const mocked = {
  fetchEventGroups: vi.mocked(fetchEventGroups),
}

function renderPage() {
  return render(
    <MemoryRouter>
      <Events />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mocked.fetchEventGroups.mockResolvedValue(eventGroupsFixture)
})

describe('Events page (server-side grouped events)', () => {
  it('renders collapsed group fields from the groups endpoint', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('10.0.0.10')).toBeInTheDocument()
    })

    expect(mocked.fetchEventGroups).toHaveBeenCalledWith(
      expect.objectContaining({ skip: 0, limit: 20 }),
    )
    expect(screen.getByText('admin, root')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument() // total events
    expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(2) // success + failure
    expect(screen.getByText('Single Account Brute Force')).toBeInTheDocument()
    expect(screen.getByText('Target username(s)')).toBeInTheDocument()
    expect(screen.getByText('Start')).toBeInTheDocument()
    expect(screen.getByText('End')).toBeInTheDocument()
    expect(screen.getByText('Detection type')).toBeInTheDocument()
  })

  it('expands a group into the per-event table', async () => {
    renderPage()

    const toggle = await screen.findByRole('button', { name: /10\.0\.0\.10/ })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(toggle)

    await waitFor(() => {
      expect(toggle).toHaveAttribute('aria-expanded', 'true')
    })

    // Per-event rows: username, port, session correlation and raw JSON.
    expect(screen.getByText('root')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getAllByText('22').length).toBe(2) // both events: SSH port
    expect(screen.getAllByText('#41').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('linux').length).toBe(2) // event type fallback
    expect(screen.getByText(/Failed password for admin/)).toBeInTheDocument()

    // Collapsing hides the expanded table again.
    fireEvent.click(toggle)
    await waitFor(() => {
      expect(toggle).toHaveAttribute('aria-expanded', 'false')
    })
    expect(screen.queryByText('root')).not.toBeInTheDocument()
  })

  it('passes the search term to the groups endpoint on submit', async () => {
    renderPage()
    await screen.findByRole('button', { name: /10\.0\.0\.10/ })

    fireEvent.change(
      screen.getByLabelText('Search events by source IP or username'),
      { target: { value: '  10.0.0 ' } },
    )
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => {
      expect(mocked.fetchEventGroups).toHaveBeenLastCalledWith(
        expect.objectContaining({ search: '10.0.0' }),
      )
    })
  })

  it('passes the result filter to the groups endpoint', async () => {
    renderPage()
    await screen.findByRole('button', { name: /10\.0\.0\.10/ })

    fireEvent.change(screen.getByLabelText('Filter by result'), {
      target: { value: 'failure' },
    })

    await waitFor(() => {
      expect(mocked.fetchEventGroups).toHaveBeenLastCalledWith(
        expect.objectContaining({ result: 'failure' }),
      )
    })
  })

  it('pages server-side when the result set spans multiple pages', async () => {
    mocked.fetchEventGroups.mockResolvedValue({
      items: eventGroupsFixture.items,
      total: 41,
    })

    renderPage()

    await waitFor(() => {
      expect(screen.getByText(/Page 1 of 3/)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(mocked.fetchEventGroups).toHaveBeenLastCalledWith(
        expect.objectContaining({ skip: 20 }),
      )
    })
  })

  it('shows the empty state when no events exist', async () => {
    mocked.fetchEventGroups.mockResolvedValue(emptyEventGroupsFixture)

    renderPage()

    await waitFor(() => {
      expect(
        screen.getByText('No authentication events yet'),
      ).toBeInTheDocument()
    })
  })

  it('offers a clear-filters action when filters exclude everything', async () => {
    renderPage()
    await screen.findByRole('button', { name: /10\.0\.0\.10/ })

    mocked.fetchEventGroups.mockResolvedValue(emptyEventGroupsFixture)

    fireEvent.change(screen.getByLabelText('Filter by result'), {
      target: { value: 'success' },
    })

    await waitFor(() => {
      expect(
        screen.getByText('No event groups match your filters'),
      ).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))

    await waitFor(() => {
      expect(mocked.fetchEventGroups).toHaveBeenLastCalledWith(
        expect.objectContaining({ result: undefined }),
      )
    })
  })

  it('shows the error state with retry when the API is unreachable', async () => {
    mocked.fetchEventGroups.mockRejectedValue(new Error('Network Error'))

    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    expect(screen.getByText('Unable to load data')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('keeps stale groups visible with a warning when a refresh fails', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('10.0.0.10')).toBeInTheDocument()
    })

    mocked.fetchEventGroups.mockRejectedValue(new Error('boom'))

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))

    await waitFor(() => {
      expect(
        screen.getByText(/Showing the last loaded event groups/),
      ).toBeInTheDocument()
    })
    expect(screen.getByText('10.0.0.10')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load data')).not.toBeInTheDocument()
  })
})
