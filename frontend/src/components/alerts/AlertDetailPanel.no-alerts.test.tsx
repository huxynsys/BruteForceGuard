import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import AlertDetailPanel from './AlertDetailPanel'
import { fetchAlertsPage } from '../../api/alerts'
import { fetchBlacklistEntries } from '../../api/blacklist'
import { fetchEventGroups } from '../../api/events'
import { getReputation } from '../../api/intelligence'
import {
  alertEventGroupFixture,
  alertFixture,
  reputationFixture,
} from '../../test/fixtures'
import type { Alert, AlertStats } from '../../types'

vi.mock('../../api/alerts', () => ({ fetchAlertsPage: vi.fn() }))
vi.mock('../../api/blacklist', () => ({
  fetchBlacklistEntries: vi.fn(),
}))
vi.mock('../../api/events', () => ({ fetchEventGroups: vi.fn() }))
vi.mock('../../api/intelligence', () => ({ getReputation: vi.fn() }))

const mockedFetchAlertsPage = vi.mocked(fetchAlertsPage)
const mockedFetchBlacklist = vi.mocked(fetchBlacklistEntries)
const mockedFetchEventGroups = vi.mocked(fetchEventGroups)
const mockedGetReputation = vi.mocked(getReputation)

const statsFixture: AlertStats = {
  total: 0,
  by_status: { open: 0 },
  by_severity: { high: 0 },
  by_alert_type: { single_account_bruteforce: 0 },
}

function renderPanel(alert: Alert = alertFixture) {
  const onStatusChange = vi.fn(async () => {})
  const onClose = vi.fn()

  const utils = render(
    <MemoryRouter>
      <AlertDetailPanel
        alert={alert}
        onStatusChange={onStatusChange}
        onClose={onClose}
      />
    </MemoryRouter>,
  )

  return { ...utils, onStatusChange, onClose }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockedFetchEventGroups.mockResolvedValue({
    items: [alertEventGroupFixture],
    total: 1,
  })
  mockedFetchAlertsPage.mockResolvedValue({
    items: [],
    total: 0,
    stats: statsFixture,
  })
  mockedGetReputation.mockResolvedValue({
    ...reputationFixture,
    alert_count: 0,
  })
  mockedFetchBlacklist.mockResolvedValue([])
})

describe('AlertDetailPanel IP history (no alerts)', () => {
  it('shows a history with no related alerts from the same IP', async () => {
    renderPanel()

    const history = screen.getByRole('region', { name: 'IP history' })

    await waitFor(() => {
      expect(
        within(history).getByText('Previous alerts from this IP (0)'),
      ).toBeInTheDocument()
    })

    expect(
      within(history).getByText(/No alerts recorded from this IP yet/),
    ).toBeInTheDocument()
    expect(
      within(history).queryByRole('link', { name: '#11' }),
    ).not.toBeInTheDocument()
  })
})