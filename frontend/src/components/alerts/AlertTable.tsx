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
  /** Alert whose details panel is open (its row is highlighted). */
  selectedId?: number | null
  /** Select an alert; the page opens the details side panel. */
  onSelect?: (alert: Alert) => void
}
/**
 * Detailed alert work queue.
 *
 * Selecting a row - clicking anywhere on it or activating the detection-type
 * button in its first cell - opens the alert details side panel owned by the
 * page.  The explicit "View details" link still navigates to the full alert
 * page, and triage actions report through `onStatusChange` so the page owns the
 * API persistence.
 */
export default function AlertTable({
  alerts,
  onStatusChange,
  pendingId = null,
  selectedId = null,
  onSelect,
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
            const selected = selectedId === alert.id

            return (
              <tr
                key={alert.id}
                className={`clickable${selected ? ' is-selected' : ''}`}
                onClick={() => onSelect?.(alert)}
              >
                <td className="mono" title={alert.created_at}>
                  {formatDateTime(alert.created_at)}
                </td>
                <td>
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="strong">
                  <button
                    type="button"
                    className="alert-row__toggle"
                    aria-expanded={selected}
                    aria-label={`Open details for alert ${alert.id}`}
                    onClick={(event) => {
                      event.stopPropagation()
                      onSelect?.(alert)
                    }}
                  >
                    {detectionLabel(alert.alert_type)}{' '}
                    <span
                      className="mono"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      #{alert.id}
                    </span>
                  </button>
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
