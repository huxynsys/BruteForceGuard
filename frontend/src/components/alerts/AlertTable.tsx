import { Link } from 'react-router-dom'
import type { Alert, AlertStatus } from '../../types'
import { detectionLabel } from '../../lib/detectionLabels'
import { canAcknowledge, canResolve, failedAttempts } from '../../lib/alerts'
import { formatDateTime } from '../../lib/format'
import { SeverityBadge, StatusBadge } from '../ui/Cards'

interface AlertTableProps {
  alerts: Alert[]
  /** Persist a triage transition; the page owns the API call. */
  onStatusChange: (alert: Alert, status: AlertStatus) => void
  /** Alert currently being updated (its actions are disabled). */
  pendingId?: number | null
}
/**
 * Detailed alert work queue.
 *
 * Navigation to a single alert happens through the explicit "View details"
 * link in the actions cell; triage actions report through `onStatusChange`
 * so the page owns the API persistence.
 */
export default function AlertTable({
  alerts,
  onStatusChange,
  pendingId = null,
}: AlertTableProps) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th scope="col">Timestamp</th>
            <th scope="col">Severity</th>
            <th scope="col">Detection Type</th>
            <th scope="col">Source IP</th>
            <th scope="col">Username</th>
            <th scope="col">Failed Attempts</th>
            <th scope="col">Status</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const attempts = failedAttempts(alert)
            const busy = pendingId === alert.id

            return (
              <tr key={alert.id}>
                <td className="mono" title={alert.created_at}>
                  {formatDateTime(alert.created_at)}
                </td>
                <td>
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="strong">
                  {detectionLabel(alert.alert_type)}{' '}
                  <span className="mono" style={{ color: 'var(--text-muted)' }}>
                    #{alert.id}
                  </span>
                </td>
                <td className="mono">{alert.source_ip ?? '—'}</td>
                <td className="mono">{alert.username ?? '—'}</td>
                <td className="mono">{attempts ?? '—'}</td>
                <td>
                  <StatusBadge status={alert.status} />
                </td>
                <td>
                  <div
                    className="row-actions"
                    onClick={(event) => event.stopPropagation()}
                  >
                    <Link
                      className="neo-button neo-button--sm"
                      to={`/alerts/${alert.id}`}
                      aria-label={`View details for alert ${alert.id}`}
                    >
                      View details
                    </Link>
                    <button
                      type="button"
                      className="neo-button neo-button--sm"
                      disabled={busy || !canAcknowledge(alert.status)}
                      aria-busy={busy}
                      aria-label={`Acknowledge alert ${alert.id}`}
                      onClick={() => onStatusChange(alert, 'acknowledged')}
                    >
                      Acknowledge
                    </button>
                    <button
                      type="button"
                      className="neo-button neo-button--sm"
                      disabled={busy || !canResolve(alert.status)}
                      aria-busy={busy}
                      aria-label={`Resolve alert ${alert.id}`}
                      onClick={() => onStatusChange(alert, 'resolved')}
                    >
                      Resolve
                    </button>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
