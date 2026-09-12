import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AlertDetail from './AlertDetail'
import { fetchAlert } from '../api/alerts'
import {
  alertFixture,
  maliciousAlertFixture,
  noIntelAlertFixture,
} from '../test/fixtures'

vi.mock('../api/alerts', () => ({
  fetchAlert: vi.fn(),
}))

const mockedFetchAlert = vi.mocked(fetchAlert)

function renderAlert(id = '1') {
  return render(
    <MemoryRouter initialEntries={[`/alerts/${id}`]}>
      <Routes>
        <Route path="/alerts/:id" element={<AlertDetail />} />
        <Route path="/alerts" element={<div>ALERTS LIST</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockedFetchAlert.mockResolvedValue(alertFixture)
})

describe('AlertDetail page', () => {
  it('renders the alert information from the API', async () => {
    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('Possible Single-Account Brute Force')).toBeInTheDocument()
    })

    expect(screen.getAllByText('Single Account Brute Force').length).toBeGreaterThan(0)
    expect(screen.getAllByText('192.168.1.44').length).toBeGreaterThan(0)
    expect(screen.getByText('SSH')).toBeInTheDocument()
    expect(mockedFetchAlert).toHaveBeenCalledWith('1')
  })

  it('renders the Phase 7 risk score', async () => {
    renderAlert()

    await waitFor(() => {
      expect(screen.getByLabelText(/Risk score 72 out of 100/)).toBeInTheDocument()
    })
  })

  it('renders the risk factors with reasons', async () => {
    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('Risk Factors')).toBeInTheDocument()
    })

    expect(screen.getByText('Detection Severity')).toBeInTheDocument()
    expect(
      screen.getByText('Known indicator from local (confidence 90%)'),
    ).toBeInTheDocument()
  })

  it('renders threat intelligence for a known indicator', async () => {
    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('MATCH')).toBeInTheDocument()
    })
    expect(screen.getByText(/from local/i)).toBeInTheDocument()
  })

  it('does not imply an unknown indicator is safe', async () => {
    const unknown = {
      ...alertFixture,
      threat_intelligence: {
        known: false,
        confidence: null,
        categories: [],
        threat_type: null,
        source: 'local',
      },
    }
    mockedFetchAlert.mockResolvedValue(unknown)

    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('No match')).toBeInTheDocument()
    })
    expect(screen.queryByText('Clean')).not.toBeInTheDocument()
    expect(
      screen.getByText(/not evidence that the indicator is safe/i),
    ).toBeInTheDocument()
  })

  it('renders the source reputation panel', async () => {
    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('Source Reputation')).toBeInTheDocument()
    })

    expect(screen.getByText('78/100')).toBeInTheDocument()
    expect(screen.getAllByText('HIGH').length).toBeGreaterThan(0)
  })
})

describe('AlertDetail enrichment states', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockedFetchAlert.mockResolvedValue(alertFixture)
  })

  it('renders the MITRE technique', async () => {
    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('T1110.001')).toBeInTheDocument()
    })
    expect(screen.getByText('Password Guessing')).toBeInTheDocument()
    expect(screen.getByText('Credential Access')).toBeInTheDocument()
  })

  it('handles unknown MITRE mappings safely', async () => {
    const unmapped = {
      ...alertFixture,
      mitre_context: {
        technique_id: '',
        technique_name: '',
        tactic: '',
        description: '',
        is_mapped: false,
      },
    }
    mockedFetchAlert.mockResolvedValue(unmapped)

    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('Unmapped')).toBeInTheDocument()
    })
  })

  it('renders the detection evidence', async () => {
    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('Detection Evidence')).toBeInTheDocument()
    })

    expect(screen.getByText('failure_count')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
  })

  it('distinguishes unavailable intelligence from unknown indicators', async () => {
    mockedFetchAlert.mockResolvedValue(noIntelAlertFixture)

    renderAlert()

    await waitFor(() => {
      expect(screen.getByText('TI unavailable')).toBeInTheDocument()
    })
    expect(
      screen.getByText(/enrichment is unavailable for this alert/i),
    ).toBeInTheDocument()
  })

  it('renders a matching critical alert', async () => {
    mockedFetchAlert.mockResolvedValue(maliciousAlertFixture)

    renderAlert()

    await waitFor(() => {
      expect(screen.getByLabelText(/Risk score 88 out of 100/)).toBeInTheDocument()
    })
  })

  it('shows the loading state while fetching', async () => {
    let resolve!: (value: typeof alertFixture) => void
    mockedFetchAlert.mockReturnValue(
      new Promise<typeof alertFixture>((res) => {
        resolve = res
      }),
    )

    renderAlert()

    expect(screen.getByText('Loading alert...')).toBeInTheDocument()

    resolve(alertFixture)
    await waitFor(() => {
      expect(screen.getByText('Possible Single-Account Brute Force')).toBeInTheDocument()
    })
  })

  it('handles API failure with a retry button', async () => {
    mockedFetchAlert.mockRejectedValue(new Error('Network Error'))

    renderAlert()

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.getByText('Unable to load data')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('shows the not-found state for a missing alert', async () => {
    mockedFetchAlert.mockRejectedValue(new Error('Alert not found'))

    renderAlert('999')

    await waitFor(() => {
      expect(screen.getByText('Alert not found')).toBeInTheDocument()
    })
    expect(screen.getByText(/may have been removed/i)).toBeInTheDocument()
  })

  it('retries after an API failure', async () => {
    mockedFetchAlert.mockRejectedValueOnce(new Error('Network Error'))
    mockedFetchAlert.mockResolvedValue(alertFixture)

    renderAlert()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    })

    screen.getByRole('button', { name: 'Retry' }).click()

    await waitFor(() => {
      expect(screen.getByText('Possible Single-Account Brute Force')).toBeInTheDocument()
    })
    expect(mockedFetchAlert).toHaveBeenCalledTimes(2)
  })
})

