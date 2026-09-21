import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import DashboardPage from './DashboardPage'
import {
  alertFixture,
  analyticsFixture,
  criticalAlertFixture,
  healthFixture,
  notReadyFixture,
  readinessFixture,
  summaryFixture,
} from '../test/fixtures'

// Mock the API boundary (not the hooks) so the full path is exercised:
// fetch -> useApi -> DashboardPage -> overview panels.
vi.mock('../api/dashboard', () => ({
  fetchSummary: vi.fn(),
  fetchAnalytics: vi.fn(),
  fetchHealth: vi.fn(),
  fetchReadiness: vi.fn(),
}))
vi.mock('../api/alerts', () => ({
  fetchAlerts: vi.fn(),
}))

import {
  fetchAnalytics,
  fetchHealth,
  fetchReadiness,
  fetchSummary,
} from '../api/dashboard'
import { fetchAlerts } from '../api/alerts'

const mocked = {
  fetchSummary: vi.mocked(fetchSummary),
  fetchAnalytics: vi.mocked(fetchAnalytics),
  fetchHealth: vi.mocked(fetchHealth),
  fetchReadiness: vi.mocked(fetchReadiness),
  fetchAlerts: vi.mocked(fetchAlerts),
}

function renderPage() {
  return render(
    <MemoryRouter>
      <DashboardPage />
    </MemoryRouter>,
  )
}

/** Wait for the KPI band, the backbone of the overview. */
async function waitForOverview() {
  await waitFor(() => {
    expect(screen.getByText('Total Events')).toBeInTheDocument()
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mocked.fetchSummary.mockResolvedValue(summaryFixture)
  mocked.fetchAnalytics.mockResolvedValue(analyticsFixture)
  mocked.fetchHealth.mockResolvedValue(healthFixture)
  mocked.fetchReadiness.mockResolvedValue(readinessFixture)
  mocked.fetchAlerts.mockResolvedValue([alertFixture])
})

describe('DashboardPage (security overview)', () => {
  it('shows the four posture KPIs from the summary endpoint', async () => {
    renderPage()

    await waitForOverview()

    expect(screen.getByText('1,247')).toBeInTheDocument() // total_events
    expect(screen.getByText('Active Alerts')).toBeInTheDocument()
    expect(screen.getByText('Active Sessions')).toBeInTheDocument()
    expect(screen.getByText('Unique Source IPs')).toBeInTheDocument()
    expect(mocked.fetchSummary).toHaveBeenCalled()
  })

  it('lists only the three most recent alerts, each linking to its detail page', async () => {
    mocked.fetchAlerts.mockResolvedValue([
      criticalAlertFixture,
      alertFixture,
      { ...alertFixture, id: 11, source_ip: '203.0.113.9' },
      { ...alertFixture, id: 12 },
      { ...alertFixture, id: 13 },
    ])

    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Recent alerts')).toBeInTheDocument()
    })

    // Three is requested from the API and never exceeded in the DOM.
    expect(mocked.fetchAlerts).toHaveBeenCalledWith(3)

    const links = screen.getAllByRole('link', {
      name: /view details for alert/i,
    })
    expect(links).toHaveLength(3)
    expect(links[0]).toHaveAttribute('href', '/alerts/2')
    expect(links[1]).toHaveAttribute('href', '/alerts/1')

    // Severity, source IP and timestamp are visible without opening a page.
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText(/10\.0\.0\.8/)).toBeInTheDocument()
    expect(screen.getAllByText(/ago\)/).length).toBeGreaterThan(0)
  })

  it('summarises critical sessions and links to the sessions page', async () => {
    renderPage()

    await waitForOverview()

    expect(screen.getByText('Critical sessions')).toBeInTheDocument()
    // summary.high_risk_sessions is backend-computed (active, high/critical).
    expect(screen.getAllByText('2').length).toBeGreaterThan(0)

    const link = screen.getByRole('link', { name: /open attack sessions/i })
    expect(link).toHaveAttribute('href', '/sessions')
  })

  // --- Attack trend, health panel and page-level states ---------------

  it('renders the 24-hour attack trend from the analytics endpoint', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Attack trend')).toBeInTheDocument()
    })

    expect(screen.getByText('Failures')).toBeInTheDocument()
    expect(screen.getByText('Peak failure hour')).toBeInTheDocument()
    // Two buckets: 12 + 31 failures, 4 + 2 successes.
    expect(
      screen.getByRole('img', { name: /43 failures and 6 successes/ }),
    ).toBeInTheDocument()
    expect(mocked.fetchAnalytics).toHaveBeenCalled()
  })

  it('shows the trend empty state instead of a flat chart when nothing happened', async () => {
    mocked.fetchAnalytics.mockResolvedValue({
      ...analyticsFixture,
      activity: [{ time: '2026-09-08T10:00', failure: 0, success: 0 }],
    })

    renderPage()

    await waitFor(() => {
      expect(
        screen.getByText(/No authentication activity in the last 24 hours/i),
      ).toBeInTheDocument()
    })

    expect(screen.queryByText('Peak failure hour')).not.toBeInTheDocument()
  })

  it('isolates a trend failure: the rest of the overview still renders', async () => {
    mocked.fetchAnalytics.mockRejectedValue(new Error('analytics unavailable'))

    renderPage()

    await waitForOverview()

    expect(screen.getByText('analytics unavailable')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(screen.getByText('1,247')).toBeInTheDocument()
  })

  it('reports every monitoring component as healthy when both probes answer', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('System health')).toBeInTheDocument()
    })

    expect(mocked.fetchHealth).toHaveBeenCalled()
    expect(mocked.fetchReadiness).toHaveBeenCalled()
    expect(
      screen.getByText('All monitoring components are healthy'),
    ).toBeInTheDocument()
    expect(screen.getByText('Backend API')).toBeInTheDocument()
    expect(screen.getByText('Database')).toBeInTheDocument()
    expect(screen.getByText('Detection engine')).toBeInTheDocument()
    expect(screen.getAllByText('OK')).toHaveLength(3)
    expect(screen.getByText('PostgreSQL reachable')).toBeInTheDocument()
    expect(screen.getByText('bruteforceguard-api v0.5.0')).toBeInTheDocument()
  })

  it('names the failing dependency when readiness answers not_ready', async () => {
    // The 503 body is turned into data by the API layer, not thrown away.
    mocked.fetchReadiness.mockResolvedValue(notReadyFixture)

    renderPage()

    await waitFor(() => {
      expect(
        screen.getByText('Degraded: a monitoring component is failing'),
      ).toBeInTheDocument()
    })

    expect(screen.getByText('FAILED')).toBeInTheDocument()
    expect(
      screen.getByText('Unavailable - see server logs'),
    ).toBeInTheDocument()
    expect(screen.getAllByText('OK')).toHaveLength(2)
  })

  it('never claims OK for an unreachable readiness probe', async () => {
    mocked.fetchReadiness.mockRejectedValue(new Error('probe unreachable'))

    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Component status unknown')).toBeInTheDocument()
    })

    expect(screen.getAllByText('UNKNOWN')).toHaveLength(2)
    expect(screen.getAllByText('Readiness probe unreachable')).toHaveLength(2)
  })

  it('keeps the full alerts and sessions tables off the overview', async () => {
    const { container } = renderPage()

    await waitForOverview()

    // Only the two compact lists (alert feed, system status) may remain.
    expect(container.querySelectorAll('table')).toHaveLength(0)
    expect(screen.getAllByRole('list')).toHaveLength(2)
  })

  it('shows the alert empty state instead of inventing detections', async () => {
    mocked.fetchAlerts.mockResolvedValue([])

    renderPage()

    await waitFor(() => {
      expect(screen.getByText('No alerts yet')).toBeInTheDocument()
    })
  })

  it('shows the page error state with retry when the overview cannot load', async () => {
    mocked.fetchSummary.mockRejectedValue(new Error('Network Error'))

    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Unable to load data')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('keeps the last good KPIs visible when a later poll fails', async () => {
    renderPage()

    await waitForOverview()

    // The error && !data guard keeps the overview populated for the analyst.
    mocked.fetchSummary.mockRejectedValue(new Error('boom'))

    expect(screen.getByText('1,247')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load data')).not.toBeInTheDocument()
  })
})
