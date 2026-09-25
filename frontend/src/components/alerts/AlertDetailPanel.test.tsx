import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import AlertDetailPanel from './AlertDetailPanel'
import { fetchAlertsPage } from '../../api/alerts'
import { blockIpAddress, fetchBlacklistEntries } from '../../api/blacklist'
import { fetchEventGroups } from '../../api/events'
import { getReputation } from '../../api/intelligence'
import {
  alertEventGroupFixture,
  alertFixture,
  blacklistEntryFixture,
  criticalAlertFixture,
  reputationFixture,
} from '../../test/fixtures'
import type { Alert, AlertStats, AlertStatus } from '../../types'

vi.mock('../../api/alerts', () => ({ fetchAlertsPage: vi.fn() }))
vi.mock('../../api/blacklist', () => ({
  blockIpAddress: vi.fn(),
  fetchBlacklistEntries: vi.fn(),
}))
vi.mock('../../api/events', () => ({ fetchEventGroups: vi.fn() }))
vi.mock('../../api/intelligence', () => ({ getReputation: vi.fn() }))

const mockedFetchAlertsPage = vi.mocked(fetchAlertsPage)
const mockedFetchBlacklist = vi.mocked(fetchBlacklistEntries)
const mockedBlockIp = vi.mocked(blockIpAddress)
const mockedFetchEventGroups = vi.mocked(fetchEventGroups)
const mockedGetReputation = vi.mocked(getReputation)

const statsFixture: AlertStats = {
  total: 2,
  by_status: { open: 1, critical: 1 },
  by_severity: { high: 1, critical: 1 },
  by_alert_type: { single_account_bruteforce: 1, failed_then_success: 1 },
}

/** A second alert from `alertFixture`'s source IP (the IP-history list). */
const historyAlert: Alert = {
  ...criticalAlertFixture,
  source_ip: '192.168.1.44',
}

interface RenderOptions {
  onStatusChange?: (alert: Alert, status: AlertStatus) => Promise<void>
  onClose?: () => void
  pending?: boolean
}

function renderPanel(alert: Alert = alertFixture, options: RenderOptions = {}) {
  const onStatusChange = options.onStatusChange ?? vi.fn(async () => {})
  const onClose = options.onClose ?? vi.fn()

  const utils = render(
    <MemoryRouter>
      <AlertDetailPanel
        alert={alert}
        onStatusChange={onStatusChange}
        onClose={onClose}
        pending={options.pending}
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
    items: [historyAlert, alertFixture],
    total: 2,
    stats: statsFixture,
  })
  mockedGetReputation.mockResolvedValue(reputationFixture)
  mockedFetchBlacklist.mockResolvedValue([])
})

describe('AlertDetailPanel metadata and source', () => {
  it('renders the alert metadata from the alert record', () => {
    renderPanel()

    expect(
      screen.getByRole('dialog', { name: 'Alert 1 details' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Alert #1')).toBeInTheDocument()
    // Detection type, severity and status appear as header badges and facts.
    expect(
      screen.getAllByText('Single Account Brute Force').length,
    ).toBeGreaterThan(0)
    expect(screen.getAllByText('high').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Open').length).toBeGreaterThan(0)
    expect(screen.getByText('65%')).toBeInTheDocument()

    const metadata = screen.getByRole('region', { name: 'Alert' })
    expect(
      within(metadata).getByTitle('2026-09-08T10:42:00Z'),
    ).toBeInTheDocument()
    expect(within(metadata).getByText('#1')).toBeInTheDocument()
  })

  it('renders the source information from the alert', () => {
    renderPanel()

    const source = screen.getByRole('region', { name: 'Source' })
    expect(within(source).getByText('192.168.1.44')).toBeInTheDocument()
    expect(within(source).getByText('admin')).toBeInTheDocument()
    expect(within(source).getByText('SSH')).toBeInTheDocument()
  })

  it('derives the target port from the related events', async () => {
    renderPanel()

    const source = screen.getByRole('region', { name: 'Source' })

    await waitFor(() => {
      expect(within(source).getByText('22')).toBeInTheDocument()
    })
  })

  it('states that no port was recorded instead of inventing one', async () => {
    mockedFetchEventGroups.mockResolvedValue({ items: [], total: 0 })

    renderPanel()

    const source = screen.getByRole('region', { name: 'Source' })

    await waitFor(() => {
      expect(
        within(source).getByText(/stores no port, and none of the related/i),
      ).toBeInTheDocument()
    })
    expect(within(source).getByText('—')).toBeInTheDocument()
  })
})

describe('AlertDetailPanel detection explanation', () => {
  it('explains the rule, the threshold and the recorded evidence', () => {
    renderPanel()

    const detection = screen.getByRole('region', {
      name: 'Detection explanation',
    })

    // The requirement sentence comes from the backend rule context.
    expect(
      within(detection).getByText(
        /5 failed authentication attempts against the same account/,
      ),
    ).toBeInTheDocument()
    expect(within(detection).getByText('5')).toBeInTheDocument()
    expect(
      within(detection).getByText('Failed attempts against the same account'),
    ).toBeInTheDocument()
    expect(within(detection).getByText('Threshold reached')).toBeInTheDocument()
    expect(within(detection).getByText('5 min (300 s)')).toBeInTheDocument()
    // "Why the rule triggered" is the engine's own report.
    expect(
      within(detection).getByText('10 failed authentication attempts.'),
    ).toBeInTheDocument()
    expect(within(detection).getByText('Recorded failures')).toBeInTheDocument()
  })

  it('reports a below-threshold detection from the recorded numbers', () => {
    renderPanel({ ...alertFixture, evidence: { failure_count: 2 } })

    const detection = screen.getByRole('region', {
      name: 'Detection explanation',
    })

    expect(within(detection).getByText('Below threshold')).toBeInTheDocument()
  })

  it('states that no rule context exists instead of fabricating one', () => {
    renderPanel({ ...alertFixture, detection_rule: null, evidence: {} })

    const detection = screen.getByRole('region', {
      name: 'Detection explanation',
    })

    expect(
      within(detection).getByText(
        /no rule description for this detection type/i,
      ),
    ).toBeInTheDocument()
    expect(within(detection).getByText('Unavailable')).toBeInTheDocument()
  })
})

describe('AlertDetailPanel related events', () => {
  it('lists the raw events for the alert source IP', async () => {
    renderPanel()

    const related = screen.getByRole('region', { name: 'Related events' })

    await waitFor(() => {
      expect(
        within(related).getByRole('columnheader', { name: 'Port' }),
      ).toBeInTheDocument()
    })

    expect(
      within(related).getByRole('columnheader', { name: 'Service' }),
    ).toBeInTheDocument()
    expect(
      within(related).getByRole('columnheader', { name: 'Result' }),
    ).toBeInTheDocument()
    expect(within(related).getByText('failure')).toBeInTheDocument()
    expect(within(related).getByText('success')).toBeInTheDocument()
    expect(within(related).getAllByText('SSH').length).toBeGreaterThan(0)
    expect(within(related).getAllByText('22').length).toBeGreaterThan(0)

    expect(mockedFetchEventGroups).toHaveBeenCalledWith({
      search: '192.168.1.44',
      limit: 10,
      events_limit: 25,
      sort: 'recent',
    })
  })

  it('notes when the event list is a capped page', async () => {
    renderPanel()

    const related = screen.getByRole('region', { name: 'Related events' })

    await waitFor(() => {
      expect(
        within(related).getByText(/2 most recent of 3 recorded events/),
      ).toBeInTheDocument()
    })
  })

  it('never renders raw event payloads', async () => {
    renderPanel()

    const related = screen.getByRole('region', { name: 'Related events' })
    await waitFor(() => {
      expect(
        within(related).getByRole('columnheader', { name: 'Port' }),
      ).toBeInTheDocument()
    })

    // `raw_event` may carry credential material and must stay unrendered.
    expect(screen.queryByText(/Failed password for/)).not.toBeInTheDocument()
    expect(screen.queryByText(/raw_event/)).not.toBeInTheDocument()
  })

  it('ignores groups that are not the alert source IP', async () => {
    mockedFetchEventGroups.mockResolvedValue({
      items: [{ ...alertEventGroupFixture, group_key: '10.1.2.3' }],
      total: 1,
    })

    renderPanel()

    const related = screen.getByRole('region', { name: 'Related events' })

    await waitFor(() => {
      expect(
        within(related).getByText(/No raw authentication events are stored/i),
      ).toBeInTheDocument()
    })
  })
})

describe('AlertDetailPanel IP history', () => {
  it('shows the authoritative alert count and the recent activity', async () => {
    renderPanel()

    const history = screen.getByRole('region', { name: 'IP history' })

    await waitFor(() => {
      expect(within(history).getByText('Source Reputation')).toBeInTheDocument()
    })

    expect(within(history).getByText('78/100')).toBeInTheDocument()
    expect(
      within(history).getByText('Previous alerts from this IP (4)'),
    ).toBeInTheDocument()

    expect(mockedGetReputation).toHaveBeenCalledWith('192.168.1.44')
    expect(mockedFetchAlertsPage).toHaveBeenCalledWith({
      search: '192.168.1.44',
      limit: 20,
    })
  })

  it('lists the previous alerts and marks the selected one', async () => {
    renderPanel()

    const history = screen.getByRole('region', { name: 'IP history' })

    await waitFor(() => {
      expect(
        within(history).getByText('Previous alerts from this IP (4)'),
      ).toBeInTheDocument()
    })

    expect(within(history).getByRole('link', { name: '#2' })).toHaveAttribute(
      'href',
      '/alerts/2',
    )
    expect(within(history).getByRole('link', { name: '#1' })).toHaveAttribute(
      'href',
      '/alerts/1',
    )
    expect(within(history).getByText('(this alert)')).toBeInTheDocument()
  })

  it('excludes alerts whose source IP only substring-matches', async () => {
    mockedFetchAlertsPage.mockResolvedValue({
      items: [
        {
          ...alertFixture,
          id: 11,
          source_ip: '192.168.1.4',
          username: '192.168.1.44',
        },
      ],
      total: 1,
      stats: statsFixture,
    })

    renderPanel()

    const history = screen.getByRole('region', { name: 'IP history' })

    await waitFor(() => {
      expect(
        within(history).getByText('Previous alerts from this IP (4)'),
      ).toBeInTheDocument()
    })

    expect(
      within(history).queryByRole('link', { name: '#11' }),
    ).not.toBeInTheDocument()
    expect(
      within(history).getByText(/No alerts recorded from this IP yet/),
    ).toBeInTheDocument()
  })

  it('reports an unavailable history without hiding the panel', async () => {
    mockedGetReputation.mockRejectedValue(new Error('Network Error'))
    mockedFetchAlertsPage.mockRejectedValue(new Error('Network Error'))

    renderPanel()

    const history = screen.getByRole('region', { name: 'IP history' })

    await waitFor(() => {
      expect(
        within(history).getByText(/Could not load the IP history/),
      ).toBeInTheDocument()
    })

    // The rest of the panel stays usable.
    expect(screen.getByRole('button', { name: 'Acknowledge' })).toBeEnabled()
  })
})

describe('AlertDetailPanel actions', () => {
  it('persists Acknowledge through the page-owned handler', () => {
    const { onStatusChange } = renderPanel()

    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }))

    expect(onStatusChange).toHaveBeenCalledWith(alertFixture, 'acknowledged')
  })

  it('persists Resolve through the page-owned handler', () => {
    const { onStatusChange } = renderPanel()

    fireEvent.click(screen.getByRole('button', { name: 'Resolve' }))

    expect(onStatusChange).toHaveBeenCalledWith(alertFixture, 'resolved')
  })

  it('persists Mark False Positive through the page-owned handler', () => {
    const { onStatusChange } = renderPanel()

    fireEvent.click(screen.getByRole('button', { name: 'Mark False Positive' }))

    expect(onStatusChange).toHaveBeenCalledWith(alertFixture, 'false_positive')
  })

  it('applies the triage rules of the current status', () => {
    renderPanel({ ...alertFixture, status: 'resolved' })

    expect(screen.getByRole('button', { name: 'Acknowledge' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Resolve' })).toBeDisabled()
    expect(
      screen.getByRole('button', { name: 'Mark False Positive' }),
    ).toBeEnabled()
  })

  it('disables every action while a transition is in flight', () => {
    renderPanel(alertFixture, { pending: true })

    expect(screen.getByRole('button', { name: 'Acknowledge' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Resolve' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Block Source IP' })).toBeDisabled()
  })

  it('confirms before blocking, then persists the blacklist entry', async () => {
    mockedBlockIp.mockResolvedValue(blacklistEntryFixture)

    renderPanel()

    fireEvent.click(screen.getByRole('button', { name: 'Block Source IP' }))

    expect(mockedBlockIp).not.toHaveBeenCalled()
    expect(
      screen.getByText(/reject requests from this address/i),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Confirm block' }))

    await waitFor(() => {
      expect(mockedBlockIp).toHaveBeenCalledWith(
        '192.168.1.44',
        'Blocked from alert #1',
      )
    })
    await waitFor(() => {
      expect(
        screen.getByText(/is now blacklisted by the API/),
      ).toBeInTheDocument()
    })
  })

  it('cancels a pending block without calling the API', () => {
    renderPanel()

    fireEvent.click(screen.getByRole('button', { name: 'Block Source IP' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(
      screen.queryByRole('button', { name: 'Confirm block' }),
    ).not.toBeInTheDocument()
    expect(mockedBlockIp).not.toHaveBeenCalled()
  })

  it('reports a failed block without claiming success', async () => {
    mockedBlockIp.mockRejectedValue(
      new Error('Request failed with status code 400'),
    )

    renderPanel()

    fireEvent.click(screen.getByRole('button', { name: 'Block Source IP' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm block' }))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(
        /Could not block 192.168.1.44/,
      )
    })
    expect(screen.queryByText(/is now blacklisted/)).not.toBeInTheDocument()
  })

  it('disables blocking when the IP is already blacklisted', async () => {
    mockedFetchBlacklist.mockResolvedValue([blacklistEntryFixture])

    renderPanel()

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: 'Source IP blocked' }),
      ).toBeDisabled()
    })
  })

  it('does not offer blocking when the alert has no source IP', () => {
    renderPanel({ ...alertFixture, source_ip: null })

    expect(screen.getByRole('button', { name: 'Block Source IP' })).toBeDisabled()
    expect(mockedBlockIp).not.toHaveBeenCalled()
  })
})

describe('AlertDetailPanel accessibility', () => {
  it('moves focus to the close button when it opens', () => {
    renderPanel()

    expect(
      screen.getByRole('button', { name: 'Close alert details' }),
    ).toHaveFocus()
  })

  it('closes on Escape', () => {
    const { onClose } = renderPanel()

    fireEvent.keyDown(document, { key: 'Escape' })

    expect(onClose).toHaveBeenCalled()
  })

  it('closes from the close button and the backdrop', () => {
    const { onClose, container } = renderPanel()

    fireEvent.click(screen.getByRole('button', { name: 'Close alert details' }))
    expect(onClose).toHaveBeenCalledTimes(1)

    const backdrop = container.querySelector('.alert-panel__backdrop')
    expect(backdrop).not.toBeNull()
    fireEvent.click(backdrop as Element)
    expect(onClose).toHaveBeenCalledTimes(2)
  })
})
