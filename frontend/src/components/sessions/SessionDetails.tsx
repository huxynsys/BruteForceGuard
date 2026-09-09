import { useNavigate } from 'react-router-dom'
import { XCircle } from 'lucide-react'
import type { AttackSession } from '../../types'
import { detectionLabel } from '../../types'
import { SeverityBadge } from '../ui/Cards'

function fullTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleString()
}

export default function SessionDetails({
  session,
  onClose,
  closing,
}: {
  session: AttackSession
  onClose: () => void
  closing: boolean
}) {
  const navigate = useNavigate()
  const active = session.status === 'active'

  return (
    <article className="neo-card" aria-label={`Attack session ${session.id}`}>
      <div className="row spread" style={{ marginBottom: 16 }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>
          ATTACK SESSION <span className="mono">#{session.id}</span>
        </h2>
        {active && (
          <button
            className="neo-button danger"
            onClick={onClose}
            disabled={closing}
          >
            <XCircle size={14} style={{ marginRight: 6, verticalAlign: -2 }} />
            {closing ? 'Closing...' : 'Close Session'}
          </button>
        )}
      </div>

      <dl className="detail-grid">
        <dt>Status</dt>
        <dd>
          <span
            className={`badge ${active ? 'badge-success' : 'badge-muted'}`}
          >
            {session.status}
          </span>
        </dd>
        <dt>Severity</dt>
        <dd>
          <SeverityBadge severity={session.severity} />
        </dd>
        <dt>Session Type</dt>
        <dd>{detectionLabel(session.session_type)}</dd>
        <dt>Events</dt>
        <dd className="mono">{session.event_count}</dd>
        <dt>Started</dt>
        <dd className="mono">{fullTime(session.started_at)}</dd>
        <dt>Last Seen</dt>
        <dd className="mono">{fullTime(session.last_seen_at)}</dd>
      </dl>

      <h3 className="page-section-title">Detection Types</h3>
      <div>
        {session.detection_types?.map((type) => (
          <span key={type} className="chip">
            {detectionLabel(type)}
          </span>
        ))}
      </div>

      <div className="grid-two" style={{ marginTop: 18 }}>
        <div>
          <h3 className="page-section-title" style={{ margin: '0 0 6px' }}>
            Source IPs
          </h3>
          <ul className="list-plain mono">
            {(session.source_ips ?? []).map((ip) => (
              <li key={ip}>{ip}</li>
            ))}
          </ul>
        </div>
        <div>
          <h3 className="page-section-title" style={{ margin: '0 0 6px' }}>
            Usernames
          </h3>
          <ul className="list-plain mono">
            {(session.usernames ?? []).map((user) => (
              <li key={user}>{user}</li>
            ))}
          </ul>
        </div>
      </div>

      <h3 className="page-section-title">Services</h3>
      <div>
        {session.services?.map((service) => (
          <span key={service} className="chip mono">
            {service.toUpperCase()}
          </span>
        ))}
      </div>

      <div style={{ marginTop: 20 }}>
        <button
          className="neo-button"
          onClick={() => navigate('/sessions')}
        >
          ← Back to Sessions
        </button>
      </div>
    </article>
  )
}
