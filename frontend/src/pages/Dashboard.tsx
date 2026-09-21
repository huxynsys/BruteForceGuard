import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Database,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'
import type {
  ActivityBucket,
  Alert,
  DashboardAnalytics,
  DashboardSummary,
  HealthStatus,
  ReadinessStatus,
} from '../types'
import { detectionLabel } from '../types'
import type { ApiState } from '../hooks/useApi'
import { SeverityBadge, StatCard } from '../components/ui/Cards'
import { EmptyState, LoadingState } from '../components/ui/States'
import { formatTime, timeAgo } from '../lib/format'

/**
 * High-level security overview.
 *
 * Answers one question - "is my security monitoring system healthy right
 * now?" - by showing posture KPIs, the newest detections, the critical
 * session count, the 24-hour attack trend and the health of the monitoring
 * stack. Every panel is derived from an existing API; the full alerts and
 * sessions tables live on /alerts and /sessions.
 */
export interface DashboardProps {
  summary: ApiState<DashboardSummary>
  analytics: ApiState<DashboardAnalytics>
  alerts: ApiState<Alert[]>
  health: ApiState<HealthStatus>
  readiness: ApiState<ReadinessStatus>
  onRefresh: () => void
}

/** The overview only highlights the newest detections. */
const RECENT_ALERTS = 3

type HealthLevel = 'ok' | 'error' | 'unknown'

const HEALTH_LEVEL_LABEL: Record<HealthLevel, string> = {
  ok: 'OK',
  error: 'FAILED',
  unknown: 'UNKNOWN',
}

interface TrendPoint extends ActivityBucket {
  label: string
}

function HealthIcon({ level }: { level: HealthLevel }) {
  if (level === 'ok') {
    return <CheckCircle2 size={16} aria-hidden="true" className="text-success" />
  }
  if (level === 'error') {
    return <XCircle size={16} aria-hidden="true" className="text-danger" />
  }
  return <AlertTriangle size={16} aria-hidden="true" className="text-muted" />
}

/** Inline failure state for a single panel (the rest of the page keeps working). */
function PanelError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="panel-state" role="alert">
      <AlertTriangle size={16} aria-hidden="true" className="text-danger" />
      <span>{message}</span>
      <button type="button" className="neo-button" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

/* ------------------------- Overview panels ------------------------- */

function KpiRow({ summary }: { summary: DashboardSummary }) {
  return (
    <div className="kpi-grid">
      <StatCard
        label="Total Events"
        value={summary.total_events.toLocaleString()}
        sub="Authentication events ingested"
      />
      <StatCard
        label="Active Alerts"
        value={summary.total_alerts.toLocaleString()}
        sub="Detections raised by the engine"
      />
      <StatCard
        label="Active Sessions"
        value={summary.active_sessions}
        sub="Correlated attacks in progress"
      />
      <StatCard
        label="Unique Source IPs"
        value={summary.unique_source_ips}
        sub="Distinct sources observed"
      />
    </div>
  )
}

function CriticalSessions({ summary }: { summary: DashboardSummary }) {
  const atRisk = summary.high_risk_sessions

  return (
    <div className="neo-card">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Correlated attacks</span>
          <h3 className="panel-title">Critical sessions</h3>
        </div>
        <ShieldAlert size={18} aria-hidden="true" />
      </div>

      <div className="critical-sessions__value mono">
        {atRisk.toLocaleString()}
      </div>
      <p className="critical-sessions__hint">
        {atRisk === 0
          ? 'No active session is currently rated high or critical risk.'
          : `${atRisk} active ${
              atRisk === 1 ? 'session is' : 'sessions are'
            } rated high or critical risk.`}
      </p>

      <Link className="panel-link" to="/sessions">
        Open attack sessions
        <ArrowUpRight size={14} aria-hidden="true" />
      </Link>
    </div>
  )
}

/* --------------------------- Attack trend -------------------------- */

function AttackTrend({
  analytics,
  onRetry,
}: {
  analytics: ApiState<DashboardAnalytics>
  onRetry: () => void
}) {
  const data: TrendPoint[] = (analytics.data?.activity ?? []).map((bucket) => ({
    ...bucket,
    label: bucket.time.slice(11, 16),
  }))
  const failures = data.reduce((total, point) => total + point.failure, 0)
  const successes = data.reduce((total, point) => total + point.success, 0)
  const peak = data.reduce<TrendPoint | null>(
    (best, point) =>
      best === null || point.failure > best.failure ? point : best,
    null,
  )

  return (
    <div className="neo-card activity-panel">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Last 24 hours</span>
          <h3 className="panel-title">Attack trend</h3>
        </div>
        <Activity size={18} aria-hidden="true" />
      </div>

      {analytics.loading && !analytics.data ? (
        <LoadingState label="Loading 24-hour trend..." />
      ) : analytics.error && !analytics.data ? (
        <PanelError message={analytics.error} onRetry={onRetry} />
      ) : failures + successes === 0 ? (
        <EmptyState
          title="No authentication activity in the last 24 hours"
          hint="Failed and successful authentications are charted here once events are ingested."
        />
      ) : (
        <>
          <div className="trend-summary">
            <div className="trend-summary__item">
              <span className="trend-summary__label">Failures</span>
              <strong className="mono trend-summary__value trend-summary__value--failure">
                {failures.toLocaleString()}
              </strong>
            </div>
            <div className="trend-summary__item">
              <span className="trend-summary__label">Successes</span>
              <strong className="mono trend-summary__value">
                {successes.toLocaleString()}
              </strong>
            </div>
            {peak && peak.failure > 0 && (
              <div className="trend-summary__item">
                <span className="trend-summary__label">Peak failure hour</span>
                <strong className="mono trend-summary__value">
                  {peak.label} &middot; {peak.failure}
                </strong>
              </div>
            )}
          </div>
          <p className="trend-note">
            Failed authentications show attack pressure; successes show
            legitimate logins.
          </p>
          <div
            className="trend-chart"
            role="img"
            aria-label={`Hourly authentication activity over the last 24 hours: ${failures} failures and ${successes} successes.`}
          >
            <ResponsiveContainer>
              <AreaChart
                data={data}
                margin={{ top: 8, right: 8, left: -18, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="failGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f87171" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#f87171" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="okGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#34d399" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#34d399" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(148,163,184,0.08)" vertical={false} />
                <XAxis
                  dataKey="label"
                  tick={{ fill: '#64748b', fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  minTickGap={28}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <Tooltip />
                <Area
                  type="monotone"
                  dataKey="failure"
                  name="Failures"
                  stroke="#f87171"
                  strokeWidth={2}
                  fill="url(#failGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="success"
                  name="Successes"
                  stroke="#34d399"
                  strokeWidth={2}
                  fill="url(#okGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </div>
  )
}

/* ---------------------------- Recent alerts ------------------------ */

function RecentAlerts({
  alerts,
  onRetry,
}: {
  alerts: ApiState<Alert[]>
  onRetry: () => void
}) {
  const recent = (alerts.data ?? []).slice(0, RECENT_ALERTS)

  return (
    <div className="neo-card incident-feed">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Latest detections</span>
          <h3 className="panel-title">Recent alerts</h3>
        </div>
        <Link className="panel-link" to="/alerts">
          View all
        </Link>
      </div>

      {alerts.loading && !alerts.data ? (
        <LoadingState label="Loading recent alerts..." />
      ) : alerts.error && !alerts.data ? (
        <PanelError message={alerts.error} onRetry={onRetry} />
      ) : recent.length === 0 ? (
        <EmptyState
          title="No alerts yet"
          hint="Detections will appear here as the engine flags attacks."
        />
      ) : (
        <ul className="alert-feed">
          {recent.map((alert) => (
            <li key={alert.id} className="alert-feed__item">
              <SeverityBadge severity={alert.severity} />
              <div className="alert-feed__body">
                <span className="strong">
                  {detectionLabel(alert.alert_type)}
                </span>
                <span className="alert-feed__meta mono">
                  {alert.source_ip ?? 'no source IP'} &middot;{' '}
                  {formatTime(alert.created_at)} ({timeAgo(alert.created_at)} ago)
                </span>
              </div>
              <Link
                className="alert-feed__link"
                to={`/alerts/${alert.id}`}
                aria-label={`View details for alert ${alert.id}`}
              >
                View details
                <ArrowUpRight size={13} aria-hidden="true" />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/* ------------------------ Monitoring stack ------------------------- */

function SystemHealth({
  health,
  readiness,
  onRetry,
}: {
  health: ApiState<HealthStatus>
  readiness: ApiState<ReadinessStatus>
  onRetry: () => void
}) {
  const checks = readiness.data?.checks
  const probing =
    (health.loading && !health.data) || (readiness.loading && !readiness.data)

  const backend: HealthLevel = health.data
    ? health.data.status === 'healthy'
      ? 'ok'
      : 'error'
    : health.error
      ? 'error'
      : 'unknown'

  // A 503 readiness answer still carries `checks`, so a failing dependency is
  // reported precisely; only an unreachable probe stays "unknown".
  const database: HealthLevel = checks
    ? checks.database === 'ok'
      ? 'ok'
      : 'error'
    : 'unknown'
  const detection: HealthLevel = checks
    ? checks.configuration === 'ok'
      ? 'ok'
      : 'error'
    : 'unknown'

  const overall: HealthLevel =
    backend === 'error' || database === 'error' || detection === 'error'
      ? 'error'
      : backend === 'ok' && database === 'ok' && detection === 'ok'
        ? 'ok'
        : 'unknown'

  const headline =
    overall === 'ok'
      ? 'All monitoring components are healthy'
      : overall === 'error'
        ? 'Degraded: a monitoring component is failing'
        : probing
          ? 'Checking monitoring components...'
          : 'Component status unknown'

  const rows: { name: string; icon: ReactNode; detail: string; level: HealthLevel }[] = [
    {
      name: 'Backend API',
      icon: <Activity size={15} aria-hidden="true" />,
      detail: health.data
        ? `${health.data.service} v${health.data.version}`
        : (health.error ?? 'Probing /health...'),
      level: backend,
    },
    {
      name: 'Database',
      icon: <Database size={15} aria-hidden="true" />,
      detail: checks
        ? checks.database === 'ok'
          ? 'PostgreSQL reachable'
          : 'Unavailable - see server logs'
        : 'Readiness probe unreachable',
      level: database,
    },
    {
      name: 'Detection engine',
      icon: <ShieldCheck size={15} aria-hidden="true" />,
      detail: checks
        ? checks.configuration === 'ok'
          ? 'Detection and risk configuration valid'
          : 'Invalid detection configuration'
        : 'Readiness probe unreachable',
      level: detection,
    },
  ]

  return (
    <div className="neo-card">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Monitoring stack</span>
          <h3 className="panel-title">System health</h3>
        </div>
        <Server size={18} aria-hidden="true" />
      </div>

      <p
        className={`system-health__summary system-health__summary--${overall}`}
        role="status"
        aria-live="polite"
      >
        <HealthIcon level={overall} />
        {headline}
      </p>

      <ul className="status-list">
        {rows.map((row) => (
          <li key={row.name} className="status-row">
            <span className="status-row__icon" aria-hidden="true">
              {row.icon}
            </span>
            <div className="status-row__body">
              <span className="status-row__name">{row.name}</span>
              <span className="status-row__detail">{row.detail}</span>
            </div>
            <span className={`status-pill status-pill--${row.level}`}>
              {HEALTH_LEVEL_LABEL[row.level]}
            </span>
          </li>
        ))}
      </ul>

      <div className="system-health__footer">
        <span>
          {readiness.lastUpdated
            ? `Checked ${formatTime(readiness.lastUpdated.toISOString())}`
            : 'Awaiting first probe'}
        </span>
        <button type="button" className="neo-button" onClick={onRetry}>
          <RefreshCw size={12} aria-hidden="true" /> Re-check
        </button>
      </div>
    </div>
  )
}

/* ---------------------- Security overview page --------------------- */

export default function Dashboard({
  summary,
  analytics,
  alerts,
  health,
  readiness,
  onRefresh,
}: DashboardProps) {
  return (
    <>
      <div className="dashboard-heading">
        <div>
          <span className="eyebrow">BruteForceGuard / Operations</span>
          <h2 className="dashboard-title">Security overview</h2>
          <p className="dashboard-subtitle">
            Posture, latest detections and the live health of the monitoring
            stack - details live on the alerts and sessions pages.
          </p>
        </div>
        <div className="dashboard-actions">
          <button className="toolbar-button" type="button" onClick={onRefresh}>
            <RefreshCw size={14} aria-hidden="true" /> Refresh
          </button>
        </div>
      </div>

      {summary.data && <KpiRow summary={summary.data} />}

      <div className="dashboard-grid dashboard-grid--overview">
        <AttackTrend analytics={analytics} onRetry={onRefresh} />
        {summary.data && <CriticalSessions summary={summary.data} />}
      </div>

      <div className="dashboard-grid dashboard-grid--overview">
        <RecentAlerts alerts={alerts} onRetry={onRefresh} />
        <SystemHealth
          health={health}
          readiness={readiness}
          onRetry={onRefresh}
        />
      </div>
    </>
  )
}
