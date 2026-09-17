import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import RiskFactors from './RiskFactors'
import type { RiskFactor } from '../../types/intelligence'

/**
 * The exact factor keys emitted by the backend risk scorer
 * (backend/app/intelligence/risk.py :: RiskScorer.score).
 */
const ALL_FACTORS: RiskFactor[] = [
  { factor: 'detection_severity', value: 24, reason: 'High severity detection' },
  { factor: 'confidence', value: 13, reason: 'Detection confidence 65%' },
  { factor: 'attack_frequency', value: 8, reason: '5 failed attempts' },
  {
    factor: 'threat_intelligence',
    value: 15,
    reason: 'Known indicator from local (confidence 90%)',
  },
  { factor: 'target_sensitivity', value: 6, reason: 'Privileged account targeted' },
]

describe('RiskFactors', () => {
  it('maps every backend factor key to a human-readable label', () => {
    render(<RiskFactors factors={ALL_FACTORS} />)

    expect(screen.getByText('Detection Severity')).toBeInTheDocument()
    expect(screen.getByText('Confidence')).toBeInTheDocument()
    expect(screen.getByText('Behavior')).toBeInTheDocument()
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument()
    expect(screen.getByText('Target Sensitivity')).toBeInTheDocument()
  })

  it('never leaks a raw backend factor key into the UI', () => {
    render(<RiskFactors factors={ALL_FACTORS} />)

    for (const factor of ALL_FACTORS) {
      expect(screen.queryByText(factor.factor)).not.toBeInTheDocument()
    }
  })

  it('shows each contribution reason and the running total', () => {
    render(<RiskFactors factors={ALL_FACTORS} />)

    expect(screen.getByText('High severity detection')).toBeInTheDocument()
    expect(screen.getByText('Total: 66/100')).toBeInTheDocument()
  })

  it('renders an explicit empty state', () => {
    render(<RiskFactors factors={[]} />)

    expect(screen.getByText('No risk factors available.')).toBeInTheDocument()
  })

  it('falls back to the raw key for an unknown future factor', () => {
    render(
      <RiskFactors
        factors={[{ factor: 'brand_new_factor', value: 5, reason: 'New signal' }]}
      />,
    )

    expect(screen.getByText('brand_new_factor')).toBeInTheDocument()
  })
})
