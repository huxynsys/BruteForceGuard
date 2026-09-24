import type { ReactNode } from 'react'
import type { AlertStatus, Severity } from '../../types'
import { ALERT_STATUSES, alertStatusLabel } from '../../lib/labels'

export function SeverityBadge({ severity }: { severity: string }) {
  const known = ['critical', 'high', 'medium', 'low'].includes(severity)
  const cls = known ? severity : 'muted'
  return (
    <span className={`badge badge-${cls}`}>
      {known ? (
        <span className="sev-dot" aria-hidden="true" />
      ) : null}
      {severity}
    </span>
  )
}

export function SeverityCount({
  severity,
  count,
}: {
  severity: Severity
  count: number
}) {
  return (
    <div className={`row spread sev-${severity}`} style={{ padding: '6px 0' }}>
      <span>
        <span className="sev-dot" aria-hidden="true" />
        {severity.toUpperCase()}
      </span>
      <strong className="mono">{count}</strong>
    </div>
  )
}

export function StatCard({
  label,
  value,
  sub,
}: {
  label: string
  value: ReactNode
  sub?: string
}) {
  return (
    <div className="neo-card hoverable">
      <div className="stat-label">{label}</div>
      <div className="stat-value mono">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export function ResultBadge({ result }: { result: string }) {
  return (
    <span
      className={`badge ${result === 'success' ? 'badge-success' : 'badge-high'}`}
    >
      {result}
    </span>
  )
}

/**
 * Alert triage status badge. The status name is always rendered as text, so
 * the state is never conveyed by colour alone.
 */
export function StatusBadge({ status }: { status: string }) {
  const known = ALERT_STATUSES.includes(status as AlertStatus)

  return (
    <span
      className={`badge status-badge status-badge--${known ? status : 'unknown'}`}
    >
      {alertStatusLabel(status)}
    </span>
  )
}
