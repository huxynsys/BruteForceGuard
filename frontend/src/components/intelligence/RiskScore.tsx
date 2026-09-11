/**
 * Phase 7 - Risk Score visualization component.
 *
 * Displays a numeric risk score with a visual bar and level indicator.
 * Uses restrained visualization for analyst clarity.
 */

import type { RiskLevel } from '../../types/intelligence'
import { riskLevelClass, riskLevelLabel } from '../../lib/risk'

interface RiskScoreProps {
  score: number
  level: RiskLevel | string
  showBar?: boolean
  size?: 'sm' | 'md' | 'lg'
}

export default function RiskScore({
  score,
  level,
  showBar = true,
  size = 'md',
}: RiskScoreProps) {
  const clamped = Math.max(0, Math.min(100, score))
  const levelCls = riskLevelClass(level)
  const label = riskLevelLabel(level)

  const fontSize = size === 'lg' ? 28 : size === 'sm' ? 14 : 20

  return (
    <div className={`risk-score risk-score--${levelCls}`} aria-label={`Risk score ${clamped} out of 100, level ${label}`}>
      <div className="risk-score__header">
        <span className="risk-score__label">RISK</span>
        <span
          className={`risk-score__level badge badge--${levelCls}`}
          aria-hidden="false"
        >
          {label}
        </span>
      </div>
      {showBar && (
        <div className="risk-score__bar" role="progressbar" aria-valuenow={clamped} aria-valuemin={0} aria-valuemax={100}>
          <div
            className="risk-score__bar-fill"
            style={{ width: `${clamped}%` }}
          />
        </div>
      )}
      <div className="risk-score__value" style={{ fontSize }}>
        {clamped}<span className="risk-score__value-max">/100</span>
      </div>
    </div>
  )
}