import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Ban, X } from 'lucide-react'
import { fetchAlertsPage } from '../../api/alerts'
import { blockIpAddress, fetchBlacklistEntries } from '../../api/blacklist'
import { fetchEventGroups } from '../../api/events'
import { getReputation } from '../../api/intelligence'
import { useApi } from '../../hooks/useApi'
import { LoadingState, Section } from '../ui/States'
import { ResultBadge, SeverityBadge, StatusBadge } from '../ui/Cards'
import ReputationPanel from '../intelligence/ReputationPanel'
import { detectionLabel } from '../../lib/detectionLabels'
import { alertStatusLabel } from '../../lib/labels'
import { formatDateTime, formatDuration } from '../../lib/format'
import {
  canAcknowledge,
  canMarkFalsePositive,
  canResolve,
  failedAttempts,
  thresholdReached,
} from '../../lib/alerts'
import type { Alert, AlertStatus } from '../../types'
import type { ReputationResult } from '../../types/intelligence'

/**
 * Alert details side panel.
 *
 * Opened when the analyst selects a row in the alerts work queue and shows the
 * alert metadata, source information, the detection explanation (rule +
 * recorded evidence), the related raw events, the source IP history and the
 * triage actions.
 *
 * Data sources - all existing endpoints, no new API surface:
 *
 *   alert + `detection_rule`  the list/detail/PATCH alert responses
 *   related events            ``GET /api/v1/events/groups`` scoped to the IP
 *   IP history                ``GET /api/v1/intelligence/reputation/{ip}``
 *                             (authoritative counts) plus a bounded
 *                             ``GET /api/v1/alerts/?search=<ip>`` list
 *   already blocked?          ``GET /api/v1/blacklist/``
 *   Block Source IP           ``POST /api/v1/blacklist/`` (SINGLE entry)
 *
 * Credential safety: only curated, non-sensitive fields are rendered.  Raw
 * collector payloads (``AuthEvent.raw_event`` may contain log lines such as
 * "Failed password for ...") are never dumped, and the detection `evidence`
 * blob - which is collector supplied JSON - is filtered through an explicit
 * allow-list instead of being printed verbatim.
 */

/** Related raw events rendered per alert (the backend caps groups at 100). */
const RELATED_EVENTS_LIMIT = 25

/** Previous alerts from the same source IP listed in the history section. */
const IP_HISTORY_LIMIT = 5

/** Rows fetched before filtering down to the exact source IP. */
const IP_HISTORY_FETCH_LIMIT = IP_HISTORY_LIMIT * 4

/**
 * Allow-list of `evidence` keys that are safe to render: values produced by the
 * detection engine itself.  Anything not listed is deliberately omitted.
 */
const EVIDENCE_LABELS: Record<string, string> = {
  failure_count: 'Recorded failures',
  failed_attempts: 'Recorded failures',
  distinct_users: 'Distinct accounts',
  distinct_source_ips: 'Distinct source IPs',
  active_intervals: 'Active intervals',
  successful_login: 'Successful login observed',
  first_seen: 'First seen',
  last_seen: 'Last seen',
}

/** Read a numeric value that may have been serialized as a string. */
function numericEvidence(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return null
}

/** Non-sensitive detection evidence, as label/value pairs (never nested data). */
function recordedEvidence(alert: Alert): [string, string][] {
  const evidence = alert.evidence ?? {}
  const entries: [string, string][] = []

  for (const [key, label] of Object.entries(EVIDENCE_LABELS)) {
    const value = evidence[key]
    if (value === undefined || value === null || value === '') continue
    if (typeof value === 'object') continue
    entries.push([
      label,
      typeof value === 'boolean' ? (value ? 'yes' : 'no') : String(value),
    ])
  }

  return entries
}

interface IpHistory {
  alerts: Alert[]
  reputation: ReputationResult | null
}

export interface AlertDetailPanelProps {
  alert: Alert
  /** Persist a triage transition; the alerts page owns the API call. */
  onStatusChange: (alert: Alert, status: AlertStatus) => Promise<void>
  onClose: () => void
  /** True while the page is persisting a transition for this alert. */
  pending?: boolean
}

export default function AlertDetailPanel({
  alert,
  onStatusChange,
  onClose,
  pending = false,
}: AlertDetailPanelProps) {
  const sourceIp = alert.source_ip
  const closeRef = useRef<HTMLButtonElement>(null)

  const [blockStage, setBlockStage] = useState<'idle' | 'confirm' | 'saving'>(
    'idle',
  )
  const [blockedTick, setBlockedTick] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  // A drawer must never trap the analyst: Escape always closes it.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  // Move focus into the panel so keyboard users land on the detail view.
  useEffect(() => {
    closeRef.current?.focus()
  }, [alert.id])

  const relatedFetcher = useCallback(async () => {
    if (!sourceIp) return null

    const page = await fetchEventGroups({
      search: sourceIp,
      limit: 10,
      events_limit: RELATED_EVENTS_LIMIT,
      sort: 'recent',
    })

    // The event search matches source IP *or* username, so select the group
    // whose correlation key is exactly this alert's source IP.
    return page.items.find((group) => group.group_key === sourceIp) ?? null
  }, [sourceIp])

  const related = useApi(
    relatedFetcher,
    undefined,
    `related:${alert.id}:${sourceIp ?? ''}`,
  )

  const historyFetcher = useCallback(async (): Promise<IpHistory> => {
    if (!sourceIp) return { alerts: [], reputation: null }

    const [page, reputation] = await Promise.all([
      fetchAlertsPage({ search: sourceIp, limit: IP_HISTORY_FETCH_LIMIT }),
      getReputation(sourceIp),
    ])

    // `search` is a substring match on source IP or username server-side, so
    // only exact source-IP matches belong in "previous alerts from this IP".
    const alerts = page.items.filter((item) => item.source_ip === sourceIp)

    return { alerts, reputation }
  }, [sourceIp])

  const history = useApi(
    historyFetcher,
    undefined,
    `history:${alert.id}:${sourceIp ?? ''}`,
  )

  const blacklistFetcher = useCallback(async () => {
    if (!sourceIp) return null

    // Bounded check over the newest entries the endpoint returns.
    const entries = await fetchBlacklistEntries()
    return (
      entries.find(
        (entry) =>
          entry.entry_type === 'SINGLE' && entry.ip_address === sourceIp,
      ) ?? null
    )
  }, [sourceIp])

  const blacklist = useApi(
    blacklistFetcher,
    undefined,
    `blacklist:${sourceIp ?? ''}:${blockedTick}`,
  )

  // ------------------------------------------------------------------
  // Derived view data
  // ------------------------------------------------------------------
  const attempts = failedAttempts(alert)
  const rule = alert.detection_rule ?? null
  const recordedWindow = numericEvidence(alert.evidence?.window_seconds)
  const windowSeconds = recordedWindow ?? rule?.window_seconds ?? null
  const reached = thresholdReached(attempts, rule?.threshold)

  /**
   * Target port: the alert record has no port column, so it is derived from the
   * raw events of this source IP (preferring events of the alert's service).
   * An empty list means no related event supplied one - shown as `—`, never
   * guessed.
   */
  const targetPorts = useMemo(() => {
    const group = related.data
    if (!group) return []

    const service = alert.service?.toLowerCase()
    const candidates = service
      ? group.events.filter(
          (event) => (event.service ?? '').toLowerCase() === service,
        )
      : group.events

    const ports = new Set<number>()
    for (const event of candidates) {
      if (event.port !== null && event.port !== undefined) ports.add(event.port)
    }

    return [...ports].sort((left, right) => left - right)
  }, [related.data, alert.service])

  const recorded = useMemo(() => recordedEvidence(alert), [alert])
  const historyAlerts = history.data?.alerts ?? []
  const reputation = history.data?.reputation ?? null
  const alreadyBlocked = Boolean(blacklist.data)
  const busy = pending || blockStage === 'saving'

  /** Block the alert's source IP (persisted by `POST /api/v1/blacklist/`). */
  const handleBlock = async () => {
    if (!sourceIp) return

    setError(null)
    setNotice(null)
    setBlockStage('saving')

    try {
      await blockIpAddress(sourceIp, `Blocked from alert #${alert.id}`)
      setNotice(`${sourceIp} is now blacklisted by the API.`)
      setBlockStage('idle')
      setBlockedTick((tick) => tick + 1)
    } catch (err) {
      setError(
        `Could not block ${sourceIp}: ${
          err instanceof Error ? err.message : 'unknown error'
        }`,
      )
      setBlockStage('idle')
    }
  }

  return (
    <div
      className="alert-panel"
      role="dialog"
      aria-modal="true"
      aria-label={`Alert ${alert.id} details`}
    >
      <button
        className="alert-panel__backdrop"
        type="button"
        aria-hidden="true"
        tabIndex={-1}
        onClick={onClose}
      />

      <div className="alert-panel__sheet">
        <header className="alert-panel__header">
          <div>
            <p className="alert-panel__eyebrow mono">Alert #{alert.id}</p>
            <h2 className="alert-panel__heading">{alert.title}</h2>
            <div className="alert-panel__badges">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <span className="badge badge-muted">
                {detectionLabel(alert.alert_type)}
              </span>
            </div>
          </div>
          <button
            ref={closeRef}
            type="button"
            className="neo-button neo-button--sm"
            aria-label="Close alert details"
            onClick={onClose}
          >
            <X size={14} aria-hidden="true" />
          </button>
        </header>

        <div className="alert-panel__body">
          <Section title="Alert">
            <dl className="detail-grid">
              <dt>Alert ID</dt>
              <dd className="mono">#{alert.id}</dd>

              <dt>Timestamp</dt>
              <dd className="mono" title={alert.created_at}>
                {formatDateTime(alert.created_at)}
              </dd>

              <dt>Severity</dt>
              <dd>
                <SeverityBadge severity={alert.severity} />
              </dd>

              <dt>Detection type</dt>
              <dd>{detectionLabel(alert.alert_type)}</dd>

              <dt>Status</dt>
              <dd>
                <StatusBadge status={alert.status} />
              </dd>

              <dt>Confidence</dt>
              <dd className="mono">{alert.confidence}%</dd>
            </dl>
          </Section>

          <Section title="Source">
            <dl className="detail-grid">
              <dt>Source IP</dt>
              <dd className="mono">{alert.source_ip ?? '—'}</dd>

              <dt>Username</dt>
              <dd className="mono">{alert.username ?? '—'}</dd>

              <dt>Target service</dt>
              <dd>{alert.service ? alert.service.toUpperCase() : '—'}</dd>

              <dt>Target port</dt>
              <dd className="mono">
                {targetPorts.length ? targetPorts.join(', ') : '—'}
              </dd>
            </dl>

            {targetPorts.length === 0 && (
              <p className="text-muted alert-panel__note">
                {related.loading
                  ? 'Resolving the target port from the raw events for this source IP...'
                  : 'The alert record stores no port, and none of the related raw events supplied one.'}
              </p>
            )}
          </Section>

          <Section title="Detection explanation">
            {rule ? (
              <p className="alert-panel__requirement">{rule.requirement}</p>
            ) : (
              <p className="text-muted alert-panel__note">
                The engine has no rule description for this detection type, so
                only the recorded evidence below is authoritative.
              </p>
            )}

            <dl className="detail-grid">
              <dt>Failed attempts</dt>
              <dd className="mono">{attempts ?? '—'}</dd>

              <dt>Detection threshold</dt>
              <dd>
                {rule ? (
                  <>
                    <span className="mono">{rule.threshold}</span>{' '}
                    <span className="text-muted">{rule.threshold_label}</span>
                    {reached !== null && (
                      <span
                        className={`badge alert-panel__chip ${
                          reached ? 'badge--high' : 'badge-muted'
                        }`}
                      >
                        {reached ? 'Threshold reached' : 'Below threshold'}
                      </span>
                    )}
                  </>
                ) : (
                  <span className="text-muted">Unavailable</span>
                )}
              </dd>

              {rule?.secondary_label && (
                <>
                  <dt>{rule.secondary_label}</dt>
                  <dd className="mono">{rule.secondary_threshold ?? '—'}</dd>
                </>
              )}

              <dt>Time window</dt>
              <dd className="mono">
                {formatDuration(windowSeconds)}
                {windowSeconds !== null ? ` (${windowSeconds} s)` : ''}
              </dd>

              <dt>Why the rule triggered</dt>
              <dd>{alert.description}</dd>
            </dl>

            {recorded.length > 0 && (
              <>
                <h4 className="alert-panel__subtitle">Recorded evidence</h4>
                <dl className="detail-grid">
                  {recorded.map(([label, value]) => (
                    <Fragment key={label}>
                      <dt>{label}</dt>
                      <dd className="mono">{value}</dd>
                    </Fragment>
                  ))}
                </dl>
              </>
            )}

            <p className="text-muted alert-panel__note">
              Only non-sensitive engine fields are shown. Raw collector payloads
              - which may contain credentials - are never rendered.
            </p>
          </Section>

          <Section title="Related events">
            {!sourceIp && (
              <p className="text-muted alert-panel__note">
                The alert records no source IP, so no events can be related.
              </p>
            )}

            {sourceIp && related.loading && !related.data && (
              <LoadingState label="Loading related events..." />
            )}

            {sourceIp && related.error && (
              <p className="text-muted alert-panel__note">
                Could not load the related events: {related.error}
              </p>
            )}

            {sourceIp && related.data && related.data.events.length === 0 && (
              <p className="text-muted alert-panel__note">
                No raw authentication events are stored for this source IP.
              </p>
            )}

            {sourceIp && related.data && related.data.events.length > 0 && (
              <>
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr>
                        <th scope="col">Timestamp</th>
                        <th scope="col">Service</th>
                        <th scope="col">Port</th>
                        <th scope="col">Username</th>
                        <th scope="col">Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {related.data.events.map((event) => (
                        <tr key={event.id}>
                          <td className="mono">
                            {formatDateTime(event.timestamp)}
                          </td>
                          <td>{(event.service ?? '—').toUpperCase()}</td>
                          <td className="mono">{event.port ?? '—'}</td>
                          <td className="mono">{event.username ?? '—'}</td>
                          <td>
                            <ResultBadge result={event.result} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <p className="text-muted alert-panel__note">
                  {related.data.events.length < related.data.event_count
                    ? `Showing the ${related.data.events.length} most recent of ${related.data.event_count} recorded events for this IP.`
                    : `${related.data.event_count} recorded event${
                        related.data.event_count === 1 ? '' : 's'
                      } for this IP.`}
                </p>
              </>
            )}
          </Section>

          <Section title="IP history">
            {!sourceIp && (
              <p className="text-muted alert-panel__note">
                The alert records no source IP, so no history is available.
              </p>
            )}

            {sourceIp && history.loading && !history.data && (
              <LoadingState label="Loading IP history..." />
            )}

            {sourceIp && history.error && (
              <p className="text-muted alert-panel__note">
                Could not load the IP history: {history.error}
              </p>
            )}

            {sourceIp && history.data && (
              <>
                <ReputationPanel reputation={reputation} />

                <h4 className="alert-panel__subtitle">
                  Previous alerts from this IP
                  {reputation ? ` (${reputation.alert_count})` : ''}
                </h4>

                {historyAlerts.length === 0 ? (
                  <p className="text-muted alert-panel__note">
                    {reputation && reputation.alert_count > 0
                      ? 'The alerts for this IP are outside the bounded window that was fetched.'
                      : 'No alerts recorded from this IP yet.'}
                  </p>
                ) : (
                  <ul className="alert-panel__history">
                    {historyAlerts.map((item) => (
                      <li key={item.id}>
                        <Link className="mono" to={`/alerts/${item.id}`}>
                          #{item.id}
                        </Link>
                        <span className="mono">
                          {formatDateTime(item.created_at)}
                        </span>
                        <SeverityBadge severity={item.severity} />
                        <span>{detectionLabel(item.alert_type)}</span>
                        <span className="badge badge-muted">
                          {alertStatusLabel(item.status)}
                        </span>
                        {item.id === alert.id && (
                          <span className="text-muted">(this alert)</span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </Section>

        </div>

        <footer className="alert-panel__footer">
          {error && (
            <div className="alert-banner alert-banner--error" role="alert">
              <span>{error}</span>
              <button
                type="button"
                className="neo-button neo-button--sm"
                onClick={() => setError(null)}
              >
                Dismiss
              </button>
            </div>
          )}

          {notice && (
            <div className="alert-banner alert-banner--ok" role="status">
              <span>{notice}</span>
              <button
                type="button"
                className="neo-button neo-button--sm"
                onClick={() => setNotice(null)}
              >
                Dismiss
              </button>
            </div>
          )}

          {blockStage === 'confirm' && (
            <div className="alert-banner alert-banner--warn" role="alert">
              <span>
                Block {sourceIp}? The API will reject requests from this address
                until the blacklist entry is removed.
              </span>
              <div className="row-actions">
                <button
                  type="button"
                  className="neo-button neo-button--sm neo-button--danger"
                  onClick={() => void handleBlock()}
                >
                  Confirm block
                </button>
                <button
                  type="button"
                  className="neo-button neo-button--sm"
                  onClick={() => setBlockStage('idle')}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          <div className="alert-panel__actions">
            <button
              type="button"
              className="neo-button"
              disabled={busy || !canAcknowledge(alert.status)}
              aria-busy={busy}
              onClick={() => void onStatusChange(alert, 'acknowledged')}
            >
              Acknowledge
            </button>

            <button
              type="button"
              className="neo-button"
              disabled={busy || !canResolve(alert.status)}
              aria-busy={busy}
              onClick={() => void onStatusChange(alert, 'resolved')}
            >
              Resolve
            </button>

            <button
              type="button"
              className="neo-button"
              disabled={busy || !canMarkFalsePositive(alert.status)}
              aria-busy={busy}
              onClick={() => void onStatusChange(alert, 'false_positive')}
            >
              Mark False Positive
            </button>

            <button
              type="button"
              className="neo-button neo-button--danger"
              disabled={busy || !sourceIp || alreadyBlocked}
              aria-busy={busy}
              onClick={() => setBlockStage('confirm')}
            >
              <Ban size={14} aria-hidden="true" />
              {alreadyBlocked ? 'Source IP blocked' : 'Block Source IP'}
            </button>
          </div>
        </footer>
      </div>
    </div>
  )
}

