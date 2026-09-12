import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SessionDetails from './SessionDetails'
import { getReputation, listMitreMappings } from '../../api/intelligence'
import { sessionFixture } from '../../test/fixtures'
import type { MitreContext, ReputationResult } from '../../types/intelligence'

vi.mock('../../api/intelligence', () => ({
  getReputation: vi.fn(),
  listMitreMappings: vi.fn(),
}))

const mockedGetReputation = vi.mocked(getReputation)
const mockedListMitreMappings = vi.mocked(listMitreMappings)

const reputationFixture: ReputationResult = {
  source_ip: '192.168.1.44',
  internal_reputation_score: 78,
  internal_reputation_level: 'high',
  failure_rate: 1.0,
  unique_usernames: 1,
  unique_services: 1,
  attack_sessions: 3,
  alert_count: 4,
  first_seen: '2026-09-08T10:31:22Z',
  last_seen: '2026-09-08T10:34:18Z',
}

const mitreFixture: MitreContext[] = [
  {
    detection_type: 'single_account',
    technique_id: 'T1110.001',
    technique_name: 'Password Guessing',
    tactic: 'Credential Access',
    description: 'Password guessing against a single account.',
    is_mapped: true,
  },
  {
    detection_type: 'failed_success',
    technique_id: 'T1110',
    technique_name: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Failed attempts followed by success.',
    is_mapped: true,
  },
]

function renderDetails() {
  return render(
    <MemoryRouter>
      <SessionDetails
        session={sessionFixture}
        onClose={() => {}}
        closing={false}
      />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockedGetReputation.mockResolvedValue(reputationFixture)
  mockedListMitreMappings.mockResolvedValue(mitreFixture)
})

describe('SessionDetails (Phase 7 intelligence)', () => {
  it('preserves the existing session details', () => {
    renderDetails()

    expect(screen.getByText('ATTACK SESSION')).toBeInTheDocument()
    expect(screen.getByText('#41')).toBeInTheDocument()
    expect(screen.getByText('Single Account Brute Force')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.44')).toBeInTheDocument()
    expect(screen.getByText('SSH')).toBeInTheDocument()
  })

  it('renders the session risk score', () => {
    renderDetails()

    expect(screen.getByLabelText(/Risk score 64 out of 100/)).toBeInTheDocument()
  })

  it('renders the session risk factors', () => {
    renderDetails()

    expect(screen.getByText('Risk Factors')).toBeInTheDocument()
    expect(
      screen.getByText('6 failed attempts against 1 account'),
    ).toBeInTheDocument()
  })

  it('renders the behavioral profile', () => {
    renderDetails()

    expect(screen.getByText('Behavioral Profile')).toBeInTheDocument()
    expect(screen.getByText('Unique Source IPs')).toBeInTheDocument()
    expect(screen.getByText('Unique Usernames')).toBeInTheDocument()
    expect(screen.getByText('Unique Services')).toBeInTheDocument()
    expect(screen.getByText('Source Reputation Levels')).toBeInTheDocument()
    expect(screen.getAllByText('high').length).toBeGreaterThan(0)
  })

  it('renders the source reputation panel', async () => {
    renderDetails()

    await waitFor(() => {
      expect(screen.getByText('Source Reputation')).toBeInTheDocument()
    })

    expect(screen.getByText('78/100')).toBeInTheDocument()
    expect(mockedGetReputation).toHaveBeenCalledWith('192.168.1.44')
  })

  it('renders MITRE mappings for the session detection types', async () => {
    renderDetails()

    await waitFor(() => {
      expect(screen.getByText('T1110.001')).toBeInTheDocument()
    })

    expect(screen.getByText('Password Guessing')).toBeInTheDocument()
    expect(screen.getByText('T1110')).toBeInTheDocument()
    expect(screen.getAllByText('Brute Force').length).toBeGreaterThan(0)
  })

  it('handles unmapped detection types safely', async () => {
    mockedListMitreMappings.mockResolvedValue([
      {
        detection_type: 'single_account',
        technique_id: 'T1110.001',
        technique_name: 'Password Guessing',
        tactic: 'Credential Access',
        description: '',
        is_mapped: true,
      },
    ])

    renderDetails()

    await waitFor(() => {
      expect(screen.getByText('T1110.001')).toBeInTheDocument()
    })
    // failed_success has no mapping entry -> rendered as unmapped.
    expect(screen.getByText('Unmapped')).toBeInTheDocument()
  })

  it('degrades gracefully when the intelligence API fails', async () => {
    mockedGetReputation.mockRejectedValue(new Error('Network Error'))
    mockedListMitreMappings.mockRejectedValue(new Error('Network Error'))

    renderDetails()

    // Existing session details still render.
    expect(screen.getByText('ATTACK SESSION')).toBeInTheDocument()
    expect(screen.getByLabelText(/Risk score 64 out of 100/)).toBeInTheDocument()

    await waitFor(() => {
      expect(screen.getByText('No reputation data available.')).toBeInTheDocument()
    })
    expect(
      screen.getByText('MITRE mapping is unavailable.'),
    ).toBeInTheDocument()
  })

  it('handles sessions without a behavioral profile', () => {
    const bare = {
      ...sessionFixture,
      behavioral_profile: null,
      risk_factors: null,
    }
    render(
      <MemoryRouter>
        <SessionDetails session={bare} onClose={() => {}} closing={false} />
      </MemoryRouter>,
    )

    expect(screen.queryByText('Behavioral Profile')).not.toBeInTheDocument()
    expect(screen.getByText('No risk factors available.')).toBeInTheDocument()
  })
})
