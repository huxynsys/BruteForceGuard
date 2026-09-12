import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, RefreshCw } from 'lucide-react'
import { fetchAlert } from '../api/alerts'
import type { Alert } from '../types'
import { detectionLabel, type Severity } from '../types'
import RiskScore from '../components/intelligence/RiskScore'
import RiskFactors from '../components/intelligence/RiskFactors'
import ThreatIntelBadge from '../components/intelligence/ThreatIntelBadge'
import ReputationPanel from '../components/intelligence/ReputationPanel'
import MitreTechnique from '../components/intelligence/MitreTechnique'
import { SeverityBadge } from '../components/ui/Cards'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import type {
  MitreContext,
  ReputationResult,
  ThreatIntelLookup,
} from '../types/intelligence'

function fullTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
}

/**
 * Analyst investigation page for a single alert (Phase 7).
 *
 * Loads the alert (with its persisted intelligence enrichment) from the
 * backend and presents alert facts, risk, threat intelligence, reputation,
 * MITRE context and the original detection evidence.
 */
export default function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const [alert, setAlert] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)
  const [reloadTick, setReloadTick] = useState(0)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    setLoading(true)
    setNotFound(false)
    setError(null)
    fetchAlert(id)
      .then((data) => {
        if (!cancelled) setAlert(data)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const message =
          err instanceof Error ? err.message : 'Unknown error occurred'
        if (message === 'Alert not found') setNotFound(true)
        else setError(message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [id, reloadTick])

  if (loading && !alert) {
    return <LoadingState label="Loading alert..." />
  }

  if (notFound) {
    return (
      <div className="neo-card">
        <EmptyState
          title="Alert not found"
          hint="This alert may have been removed, or the ID is incorrect."
        />
        <div style={{ paddingBottom: 20, textAlign: 'center' }}>
          <Link to="/alerts" className="neo-button">
            <ArrowLeft size={14} style={{ marginRight: 6, verticalAlign: -2 }} />
            Back to Alerts
          </Link>
        </div>
      </div>
    )
  }

  if (error || !alert) {
    return (
      <ErrorState
        message={error ?? 'Unknown error'}
        onRetry={() => setReloadTick((t) => t + 1)}
      />
    )
  }

  return (
    <AlertDetailBody alert={alert} onRefresh={() => setReloadTick((t) => t + 1)} />
  )
}

function AlertDetailBody({
  alert,
  onRefresh,
}: {
  alert: Alert
  onRefresh: () => void
}) {
  // Map the persisted enrichment payloads onto the shared component types.
  const intel: ThreatIntelLookup | null = alert.threat_intelligence
    ? {
        indicator: alert.source_ip ?? '',
        indicator_type: 'ipv4',
        known: alert.threat_intelligence.known,
        confidence: alert.threat_intelligence.confidence,
        categories: alert.threat_intelligence.categories ?? [],
        threat_type: alert.threat_intelligence.threat_type,
        source: alert.threat_intelligence.source,
      }
    : null

  const reputation: ReputationResult | null = alert.source_reputation
    ? {
        source_ip: alert.source_ip ?? '',
        internal_reputation_score:
          alert.source_reputation.internal_reputation_score,
        internal_reputation_level:
          alert.source_reputation.internal_reputation_level,
        failure_rate: alert.source_reputation.failure_rate,
        unique_usernames: alert.source_reputation.unique_usernames,
        unique_services: alert.source_reputation.unique_services,
        attack_sessions: alert.source_reputation.attack_sessions,
        alert_count: alert.source_reputation.alert_count,
        first_seen: alert.source_reputation.first_seen ?? null,
        last_seen: alert.source_reputation.last_seen ?? null,
      }
    : null

  const mitre: MitreContext | null = alert.mitre_context
    ? {
        detection_type: alert.alert_type,
        technique_id: alert.mitre_context.technique_id,
        technique_name: alert.mitre_context.technique_name,
        tactic: alert.mitre_context.tactic,
        description: alert.mitre_context.description,
        is_mapped: alert.mitre_context.is_mapped,
      }
    : null

  const evidenceEntries = Object.entries(alert.evidence ?? {})

  return (
    <article aria-label={`Alert ${alert.id}`}>
      <div className="dashboard-heading">
        <div>
          <span className="eyebrow">BruteForceGuard / Alerts</span>
          <h2 className="dashboard-title">
            {alert.title}{' '}
            <span
              className="mono"
              style={{ fontSize: 14, color: 'var(--text-muted)' }}
            >
              #{alert.id}
            </span>
          </h2>
          <p className="dashboard-subtitle">{alert.description}</p>
        </div>
        <div className="dashboard-actions">
          <button
            className="toolbar-button"
            type="button"
            onClick={onRefresh}
            aria-label="Refresh alert"
          >
            <RefreshCw size={14} aria-hidden="true" /> Refresh
          </button>
          <Link to="/alerts" className="toolbar-button">
            <ArrowLeft size={14} aria-hidden="true" /> Back to Alerts
          </Link>
        </div>
      </div>

      <dl className="detail-grid">
        <dt>Alert ID</dt>
        <dd className="mono">{alert.id}</dd>
        <dt>Detection</dt>
        <dd>{detectionLabel(alert.alert_type)}</dd>
        <dt>Severity</dt>
        <dd>
          <SeverityBadge severity={alert.severity as Severity} />
        </dd>
        <dt>Confidence</dt>
        <dd className="mono">{alert.confidence}%</dd>
        <dt>Source IP</dt>
        <dd className="mono">{alert.source_ip ?? '—'}</dd>
        <dt>Username</dt>
        <dd className="mono">{alert.username ?? '—'}</dd>
        <dt>Service</dt>
        <dd>{(alert.service ?? '—').toUpperCase()}</dd>
        <dt>Status</dt>
        <dd>
          <span className="badge badge-muted">{alert.status}</span>
        </dd>
        <dt>Created</dt>
        <dd className="mono">{fullTime(alert.created_at)}</dd>
      </dl>

      <div className="grid-two" style={{ marginTop: 20 }}>
        <div className="neo-card">
          <h3 className="page-section-title">Risk Score</h3>
          <RiskScore score={alert.risk_score} level={alert.risk_level} size="lg" />
        </div>
        <div>
          <RiskFactors factors={alert.risk_factors ?? []} />
        </div>
      </div>

      <div className="grid-two" style={{ marginTop: 20 }}>
        <div className="neo-card">
          <h3 className="page-section-title">Threat Intelligence</h3>
          <p>
            <ThreatIntelBadge intel={intel} />
          </p>
          {intel?.known && (
            <dl className="reputation-panel__details">
              <dt>Source</dt>
              <dd className="mono">{intel.source ?? '—'}</dd>
              <dt>Threat Type</dt>
              <dd className="mono">{intel.threat_type ?? '—'}</dd>
              <dt>Categories</dt>
              <dd className="mono">
                {intel.categories.join(', ') || '—'}
              </dd>
              <dt>Confidence</dt>
              <dd className="mono">
                {intel.confidence != null ? `${intel.confidence}%` : '—'}
              </dd>
            </dl>
          )}
          {!intel && (
            <p className="text-muted">
              Threat-intelligence enrichment is unavailable for this alert.
            </p>
          )}
          {intel && !intel.known && (
            <p className="text-muted">
              Indicator is not present in the local threat-intelligence store.
              Absence of a match is not evidence that the indicator is safe.
            </p>
          )}
        </div>
        <div className="neo-card">
          <ReputationPanel reputation={reputation} />
        </div>
      </div>

      <div className="neo-card" style={{ marginTop: 20 }}>
        <h3 className="page-section-title">MITRE ATT&amp;CK</h3>
        <MitreTechnique context={mitre} />
      </div>

      <div className="neo-card" style={{ marginTop: 20 }}>
        <h3 className="page-section-title">Detection Evidence</h3>
        {evidenceEntries.length === 0 ? (
          <p className="text-muted">No evidence recorded for this alert.</p>
        ) : (
          <dl className="detail-grid">
            {evidenceEntries.map(([key, value]) => (
              <div
                key={key}
                style={{ gridColumn: '1 / -1', display: 'contents' }}
              >
                <dt className="mono">{key}</dt>
                <dd className="mono">
                  {typeof value === 'object'
                    ? JSON.stringify(value)
                    : String(value)}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </div>
    </article>
  )
}


