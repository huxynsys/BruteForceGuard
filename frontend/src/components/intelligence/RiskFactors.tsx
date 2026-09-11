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

const FACTOR_LABELS: Record<string, string> = {
  base_detection: 'Detection Severity',
  confidence: 'Confidence',
  behavior: 'Behavior',
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