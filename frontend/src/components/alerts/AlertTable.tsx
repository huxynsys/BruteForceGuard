import type { Alert } from '../../types'
import { detectionLabel, type Severity } from '../../types'
import { SeverityBadge } from '../ui/Cards'

function shortTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

export default function AlertTable({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Detection</th>
            <th scope="col">Source IP</th>
            <th scope="col">Username</th>
            <th scope="col">Service</th>
            <th scope="col">Confidence</th>
            <th scope="col">Time</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td>
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="strong">{detectionLabel(alert.alert_type)}</td>
              <td className="mono">{alert.source_ip ?? '—'}</td>
              <td className="mono">{alert.username ?? '—'}</td>
              <td>{(alert.service ?? '—').toUpperCase()}</td>
              <td className="mono">{alert.confidence}%</td>
              <td className="mono">{shortTime(alert.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export type { Severity }
