import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import DashboardPage from './DashboardPage'
import {
  alertFixture,
  analyticsFixture,
  sessionFixture,
  summaryFixture,
} from '../test/fixtures'

// Mock the four dashboard data sources at the API boundary so the test
// exercises the full render path: fetch -> hook -> page -> panels.
vi.mock('../api/dashboard', () => ({
  fetchSummary: vi.fn(),
  fetchAnalytics: vi.fn(),
}))
vi.mock('../api/sessions', () => ({
  fetchSessions: vi.fn(),
}))
vi.mock('../api/alerts', () => ({
  fetchAlerts: vi.fn(),
}))

import { fetchAnalytics, fetchSummary } from '../api/dashboard'
import { fetchSessions } from '../api/sessions'
import { fetchAlerts } from '../api/alerts'

const mocked = {
  fetchSummary: vi.mocked(fetchSummary),
  fetchAnalytics: vi.mocked(fetchAnalytics),
  fetchSessions: vi.mocked(fetchSessions),
  fetchAlerts: vi.mocked(fetchAlerts),
}

function renderPage() {
  return render(
    <MemoryRouter>
      <DashboardPage />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mocked.fetchSummary.mockResolvedValue(summaryFixture)
  mocked.fetchAnalytics.mockResolvedValue(analyticsFixture)
  mocked.fetchSessions.mockResolvedValue([sessionFixture])
  mocked.fetchAlerts.mockResolvedValue([alertFixture])
})

describe('DashboardPage (UI flow)', () => {
  it('loads KPI cards from the summary endpoint', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('1,247')).toBeInTheDocument()
    })

    expect(screen.getByText('Auth Events')).toBeInTheDocument()
    expect(screen.getByText('Active Alerts')).toBeInTheDocument()
    expect(screen.getByText('Active Sessions')).toBeInTheDocument()
    expect(screen.getByText('Unique Source IPs')).toBeInTheDocument()
    expect(mocked.fetchSummary).toHaveBeenCalled()
  })

  it('renders severity distribution and recent alerts', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Severity Distribution')).toBeInTheDocument()
    })

    // Severity rows show both text and count (accessibility: not color-only)
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('Recent Alerts')).toBeInTheDocument()
    expect(screen.getByText('Single Account Brute Force')).toBeInTheDocument()
  })

  it('shows the active attack from the sessions endpoint', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('192.168.1.44')).toBeInTheDocument()
    })
  })

  it('renders empty state when there are no active attacks or alerts', async () => {
    mocked.fetchSessions.mockResolvedValue([])
    mocked.fetchAlerts.mockResolvedValue([])

    renderPage()

    await waitFor(() => {
      expect(screen.getByText(/No active attacks/i)).toBeInTheDocument()
    })
    expect(screen.getByText('No alerts yet')).toBeInTheDocument()
  })

  it('shows the error state with retry when the API is unreachable', async () => {
    mocked.fetchSummary.mockRejectedValue(new Error('Network Error'))

    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    expect(screen.getByText('Unable to load data')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('keeps showing stale data instead of an error when a refresh fails', async () => {
    renderPage()

    // First load succeeds...
    await waitFor(() => {
      expect(screen.getByText('1,247')).toBeInTheDocument()
    })

    // ...then a later poll fails: DashboardPage keeps last good data
    // (error && !summary.data guard) so the analyst is not left blind.
    mocked.fetchAlerts.mockRejectedValue(new Error('boom'))

    await waitFor(() => {
      expect(screen.getByText('1,247')).toBeInTheDocument()
    })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
