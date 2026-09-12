import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { XCircle } from 'lucide-react'
import type { AttackSession } from '../../types'
import { detectionLabel } from '../../lib/detectionLabels'
import { SeverityBadge } from '../ui/Cards'
import RiskScore from '../intelligence/RiskScore'
import RiskFactors from '../intelligence/RiskFactors'
import ReputationPanel from '../intelligence/ReputationPanel'
import MitreTechnique from '../intelligence/MitreTechnique'
import { getReputation, listMitreMappings } from '../../api/intelligence'
import type { MitreContext, ReputationResult } from '../../types/intelligence'

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
  const [reputation, setReputation] = useState<ReputationResult | null>(null)
  const [mitre, setMitre] = useState<MitreContext[] | null>(null)
  const primaryIp = session.source_ips?.[0]

  useEffect(() => {
    let cancelled = false
    if (primaryIp) {
      getReputation(primaryIp)
        .then((data) => {
          if (!cancelled) setReputation(data)
        })
        .catch(() => {
          if (!cancelled) setReputation(null)
        })
    }
    listMitreMappings()
      .then((mappings) => {
        if (!cancelled) setMitre(mappings)
      })
      .catch(() => {
        if (!cancelled) setMitre(null)
      })
    return () => {
      cancelled = true
    }
  }, [primaryIp])

  const profile = session.behavioral_profile
  const sessionMitres: MitreContext[] | null =
    mitre === null
      ? null
      : (session.detection_types ?? []).map((type) => {
          const found = mitre.find((mapping) => mapping.detection_type === type)
          return (
            found ?? {
              detection_type: type,
              technique_id: '',
              technique_name: '',
              tactic: '',
              description: '',
              is_mapped: false,
            }
          )
        })

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

      <div className="grid-two" style={{ marginTop: 18 }}>
        <div>
          <h3 className="page-section-title" style={{ margin: '0 0 6px' }}>
            Session Risk
          </h3>
          <RiskScore score={session.risk_score} level={session.risk_level} />
        </div>
        <RiskFactors factors={session.risk_factors ?? []} />
      </div>

      {profile && (
        <>
          <h3 className="page-section-title">Behavioral Profile</h3>
          <dl className="detail-grid">
            <dt>Unique Source IPs</dt>
            <dd className="mono">{profile.unique_source_ips}</dd>
            <dt>Unique Usernames</dt>
            <dd className="mono">{profile.unique_usernames}</dd>
            <dt>Unique Services</dt>
            <dd className="mono">{profile.unique_services}</dd>
            <dt>Detection Types</dt>
            <dd className="mono">
              {(profile.detection_types ?? []).join(', ') || '—'}
            </dd>
            <dt>Source Reputation Levels</dt>
            <dd className="mono">
              {(profile.source_reputation_levels ?? []).join(', ') || '—'}
            </dd>
          </dl>
        </>
      )}

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

      <div className="grid-two" style={{ marginTop: 18 }}>
        <div className="neo-card">
          <ReputationPanel reputation={reputation} />
        </div>
        <div>
          <h3 className="page-section-title" style={{ margin: '0 0 6px' }}>
            MITRE ATT&amp;CK
          </h3>
          {sessionMitres === null ? (
            <p className="text-muted">MITRE mapping is unavailable.</p>
          ) : sessionMitres.length === 0 ? (
            <p className="text-muted">No detection types mapped.</p>
          ) : (
            sessionMitres.map((context) => (
              <div key={context.detection_type} style={{ marginBottom: 10 }}>
                <span className="chip">{detectionLabel(context.detection_type)}</span>
                <MitreTechnique context={context} />
              </div>
            ))
          )}
        </div>
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
