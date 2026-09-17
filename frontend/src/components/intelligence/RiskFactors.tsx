/**
 * Phase 7 - Risk Factors explanation component.
 *
 * Displays each risk contribution with its reason, making the score
 * explainable to an analyst.
 */

import type { RiskFactor } from '../../types/intelligence'

interface RiskFactorsProps {
  factors: RiskFactor[]
}

// Factor keys emitted by the backend risk scorer (app/intelligence/risk.py).
// Keep these in sync: `detection_severity` = base detection severity,
// `attack_frequency` = behavioural context.
const FACTOR_LABELS: Record<string, string> = {
  detection_severity: 'Detection Severity',
  confidence: 'Confidence',
  attack_frequency: 'Behavior',
  threat_intelligence: 'Threat Intelligence',
  target_sensitivity: 'Target Sensitivity',
}

function factorLabel(factor: string): string {
  return FACTOR_LABELS[factor] ?? factor
}

export default function RiskFactors({ factors }: RiskFactorsProps) {
  if (!factors || factors.length === 0) {
    return (
      <div className="risk-factors">
        <h3 className="page-section-title">Risk Factors</h3>
        <p className="text-muted">No risk factors available.</p>
      </div>
    )
  }

  const total = factors.reduce((sum, f) => sum + f.value, 0)

  return (
    <div className="risk-factors">
      <h3 className="page-section-title">Risk Factors</h3>
      <div className="risk-factors__list">
        {factors.map((factor, index) => (
          <div key={`${factor.factor}-${index}`} className="risk-factors__item">
            <div className="risk-factors__item-header">
              <span className="risk-factors__item-name">
                {factorLabel(factor.factor)}
              </span>
              <span className="risk-factors__item-value mono">
                +{factor.value}
              </span>
            </div>
            <div className="risk-factors__item-reason">
              {factor.reason}
            </div>
          </div>
        ))}
      </div>
      <div className="risk-factors__total mono">
        Total: {total}/100
      </div>
    </div>
  )
}