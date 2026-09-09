import { useNavigate } from 'react-router-dom'
import type { AttackSession } from '../../types'
import { detectionLabel } from '../../types'
import { SeverityBadge } from '../ui/Cards'

function shortTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
}

export default function SessionTable({ sessions }: { sessions: AttackSession[] }) {
  const navigate = useNavigate()

  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Type</th>
            <th scope="col">Severity</th>
            <th scope="col">Events</th>
            <th scope="col">Source IPs</th>
            <th scope="col">Status</th>
            <th scope="col">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => (
            <tr
              key={session.id}
              role="button"
              tabIndex={0}
              aria-label={`Open session ${session.id}`}
              onClick={() => navigate(`/sessions/${session.id}`)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') navigate(`/sessions/${session.id}`)
              }}
            >
              <td className="mono">#{session.id}</td>
              <td className="strong">{detectionLabel(session.session_type)}</td>
              <td>
                <SeverityBadge severity={session.severity} />
              </td>
              <td className="mono">{session.event_count}</td>
              <td className="mono">{session.source_ips?.length ?? 0}</td>
              <td>
                <span
                  className={`badge ${session.status === 'active' ? 'badge-success' : 'badge-muted'}`}
                >
                  {session.status}
                </span>
              </td>
              <td className="mono">{shortTime(session.last_seen_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
