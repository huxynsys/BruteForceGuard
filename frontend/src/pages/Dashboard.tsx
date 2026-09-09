import { useNavigate } from 'react-router-dom'
import { ArrowUpRight, Download, RefreshCw, ShieldAlert, Activity, Radio, Terminal, Crosshair } from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import type {
  Alert, AttackSession, DashboardAnalytics, DashboardSummary,
} from '../types'
import { detectionLabel, type Severity } from '../types'
import { SeverityBadge, StatCard } from '../components/ui/Cards'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import { formatTime } from '../lib/format'
import { sessionTypeLabel } from '../lib/labels'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#fb7185',
  high: '#fbbf24',
  medium: '#60a5fa',
  low: '#64748b',
}

function SeverityPanel({ summary }: { summary: DashboardSummary }) {
  const rows: Severity[] = ['critical', 'high', 'medium', 'low']
  const max = Math.max(1, ...rows.map((key) => summary.severity[key]))

  return (
    <div className="neo-card severity-panel">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Risk posture</span>
          <h3 className="panel-title">Severity distribution</h3>
        </div>
        <ShieldAlert size={18} aria-hidden="true" />
      </div>
      <div className="severity-list">
        {rows.map((key) => (
          <div key={key} className="severity-row">
            <span className="name">{key}</span>
            <span className="dot" style={{ background: SEVERITY_COLORS[key] }} />
            <div className="bar" role="presentation">
              <div
                style={{
                  width: `${(summary.severity[key] / max) * 100}%`,
                  background: SEVERITY_COLORS[key],
                }}
              />
            </div>
            <strong className="mono">{summary.severity[key]}</strong>
          </div>
        ))}
      </div>
    </div>
  )
}

function ActivityPanel({ analytics }: { analytics: DashboardAnalytics }) {
  const data = analytics.activity.map((bucket) => ({
    ...bucket,
    label: bucket.time.slice(11, 16),
  }))

  return (
    <div className="neo-card activity-panel">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Last 24 hours</span>
          <h3 className="panel-title">Authentication activity</h3>
        </div>
        <Activity size={18} aria-hidden="true" />
      </div>
      <div style={{ width: '100%', height: 240 }}>
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
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
            <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} minTickGap={28} />
            <YAxis tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip />
            <Area type="monotone" dataKey="failure" name="Failures" stroke="#f87171" strokeWidth={2} fill="url(#failGrad)" />
            <Area type="monotone" dataKey="success" name="Successes" stroke="#34d399" strokeWidth={2} fill="url(#okGrad)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

function ActiveAttacks({ sessions }: { sessions: AttackSession[] }) {
  const navigate = useNavigate()

  if (sessions.length === 0) {
    return (
      <div className="neo-card">
        <div className="section-heading"><h3 className="panel-title">Live attack sessions</h3><span className="live-pill">Monitoring</span></div>
        <EmptyState />
      </div>
    )
  }

  return (
    <div className="neo-card live-sessions">
      <div className="section-heading">
        <div><span className="eyebrow">Correlated activity</span><h3 className="panel-title">Live attack sessions <span className="count-badge">{sessions.length}</span></h3></div>
        <span className="live-pill">Monitoring</span>
      </div>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col">Attack</th>
              <th scope="col">Source</th>
              <th scope="col">Events</th>
              <th scope="col">Last Seen</th>
              <th scope="col" aria-label="Open" />
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
                className="clickable"
              >
                <td><SeverityBadge severity={session.severity} /></td>
                <td className="strong">{sessionTypeLabel(session.session_type)}</td>
                <td className="mono">{session.source_ips?.[0] ?? '—'}</td>
                <td className="mono">{session.event_count}</td>
                <td className="mono">{formatTime(session.last_seen_at)}</td>
                <td><ArrowUpRight size={14} aria-hidden /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RecentAlerts({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="neo-card incident-feed">
      <div className="section-heading"><div><span className="eyebrow">Detection engine</span><h3 className="panel-title">Incident feed</h3></div><span className="feed-dot" aria-label="Live feed" /></div>
      {alerts.length === 0 ? (
        <EmptyState
          title="No alerts yet"
          hint="Detections will appear here as the engine flags attacks."
        />
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Detection</th>
                <th scope="col">Source IP</th>
                <th scope="col">Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td><SeverityBadge severity={alert.severity} /></td>
                  <td className="strong">{detectionLabel(alert.alert_type)}</td>
                  <td className="mono">{alert.source_ip ?? '—'}</td>
                  <td className="mono">{formatTime(alert.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function AnalystSignal({ summary }: { summary: DashboardSummary }) {
  const threatLevel = summary.severity.critical > 0
    ? 'Critical attention'
    : summary.severity.high > 0
      ? 'Elevated monitoring'
      : 'Baseline watch'

  return (
    <div className="analyst-signal" aria-label="SOC analyst status">
      <div className="signal-command"><Terminal size={14} aria-hidden="true" /><span>soc@bruteforceguard</span><b>:</b><span>~/monitor</span><i>_</i></div>
      <div className="signal-items">
        <span><Radio size={13} aria-hidden="true" /><b>TELEMETRY</b> streaming</span>
        <span><Crosshair size={13} aria-hidden="true" /><b>SCOPE</b> {summary.unique_source_ips} source nodes</span>
        <span className="signal-threat"><span className="signal-threat-dot" />{threatLevel}</span>
      </div>
    </div>
  )
}

export default function Dashboard({
  summary,
  analytics,
  activeSessions,
  recentAlerts,
  loading,
  error,
  onRetry,
}: {
  summary: DashboardSummary | null
  analytics: DashboardAnalytics | null
  activeSessions: AttackSession[]
  recentAlerts: Alert[]
  loading: boolean
  error: string | null
  onRetry: () => void
}) {
  if (loading) return <LoadingState label="Loading security overview..." />
  if (error || !summary) {
    return <ErrorState message={error ?? 'Unknown error'} onRetry={onRetry} />
  }

  return (
    <>
      <div className="dashboard-heading">
        <div>
          <span className="eyebrow">BruteForceGuard / Operations</span>
          <h2 className="dashboard-title">Security overview</h2>
          <p className="dashboard-subtitle">A live view of authentication pressure across your protected services.</p>
        </div>
        <div className="dashboard-actions">
          <button className="toolbar-button" type="button" onClick={onRetry}><RefreshCw size={14} aria-hidden="true" /> Refresh</button>
          <button className="toolbar-button toolbar-button--primary" type="button"><Download size={14} aria-hidden="true" /> Export data</button>
        </div>
      </div>

      <AnalystSignal summary={summary} />

      <div className="kpi-grid">
        <StatCard label="Authentication events" value={summary.total_events} sub="All observed activity" />
        <StatCard label="Open incidents" value={summary.total_alerts} sub="Requires investigation" />
        <StatCard label="Active sessions" value={summary.active_sessions} sub="Correlated right now" />
        <StatCard label="Unique source IPs" value={summary.unique_source_ips} sub="Across protected services" />
      </div>

      <div className="dashboard-grid dashboard-grid--overview">
        {analytics && <ActivityPanel analytics={analytics} />}
        <SeverityPanel summary={summary} />
      </div>

      <div style={{ display: 'grid', gap: 20 }}>
        <ActiveAttacks sessions={activeSessions} />
        <RecentAlerts alerts={recentAlerts} />
      </div>
    </>
  )
}
