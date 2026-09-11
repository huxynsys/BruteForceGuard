/**
 * Phase 7 - Source Reputation panel component.
 *
 * Displays the internal behavioral reputation for a source IP.
 */

import type { ReputationResult } from '../../types/intelligence'
import { reputationLevelClass, reputationLevelLabel } from '../../lib/risk'

interface ReputationPanelProps {
  reputation: ReputationResult | null
  loading?: boolean
}

export default function ReputationPanel({ reputation, loading = false }: ReputationPanelProps) {
  if (loading) {
    return (
      <div className="reputation-panel">
        <h3 className="page-section-title">Source Reputation</h3>
        <p className="text-muted">Loading reputation...</p>
      </div>
    )
  }

  if (!reputation) {
    return (
      <div className="reputation-panel">
        <h3 className="page-section-title">Source Reputation</h3>
        <p className="text-muted">No reputation data available.</p>
      </div>
    )
  }

  const levelCls = reputationLevelClass(reputation.internal_reputation_level)
  const label = reputationLevelLabel(reputation.internal_reputation_level)
  const score = reputation.internal_reputation_score

  return (
    <div className="reputation-panel">
      <h3 className="page-section-title">Source Reputation</h3>

      <div className="reputation-panel__score">
        <span className={`badge badge--${levelCls}`}>{label}</span>
        <span className="mono">{score}/100</span>
      </div>

      <div className="reputation-panel__bar" role="progressbar" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}>
        <div
          className="reputation-panel__bar-fill"
          style={{ width: `${score}%` }}
        />
      </div>

      <dl className="reputation-panel__details">
        <dt>Source IP</dt>
        <dd className="mono">{reputation.source_ip}</dd>

        <dt>Failure Rate</dt>
        <dd className="mono">
          {reputation.failure_rate != null
            ? `${Math.round(reputation.failure_rate * 100)}%`
            : '—'}
        </dd>

        <dt>Unique Usernames</dt>
        <dd className="mono">{reputation.unique_usernames}</dd>

        <dt>Unique Services</dt>
        <dd className="mono">{reputation.unique_services}</dd>

        <dt>Attack Sessions</dt>
        <dd className="mono">{reputation.attack_sessions}</dd>

        <dt>Alert Count</dt>
        <dd className="mono">{reputation.alert_count}</dd>

        <dt>First Seen</dt>
        <dd className="mono">
          {reputation.first_seen
            ? new Date(reputation.first_seen).toLocaleString()
            : '—'}
        </dd>

        <dt>Last Seen</dt>
        <dd className="mono">
          {reputation.last_seen
            ? new Date(reputation.last_seen).toLocaleString()
            : '—'}
        </dd>
      </dl>
    </div>
  )
}