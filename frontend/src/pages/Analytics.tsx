import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { fetchAnalytics, fetchSummary } from '../api/dashboard'
import { LoadingState, ErrorState } from '../components/ui/States'
import {
  detectionLabel,
  type DashboardAnalytics,
  type DashboardSummary,
  type Severity,
  type TopItem,
} from '../types'

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#fb7185',
  high: '#fbbf24',
  medium: '#60a5fa',
  low: '#64748b',
}

const DETECTION_COLOR = '#60a5fa'
const IP_COLOR = '#f87171'
const USER_COLOR = '#34d399'
const SERVICE_COLOR = '#a78bfa'

function BarList({
  title,
  items,
  color,
  emptyHint,
}: {
  title: string
  items: TopItem[]
  color: string
  emptyHint: string
}) {
  const max = Math.max(1, ...items.map((item) => item.count))

  return (
    <div className="neo-card">
      <h3 className="panel-title">{title}</h3>
      {items.length === 0 ? (
        <p className="state-hint">{emptyHint}</p>
      ) : (
        <div className="severity-list">
          {items.map((item) => (
            <div key={item.value} className="severity-row">
              <span className="name mono">{item.value}</span>
              <div className="bar" role="presentation">
                <div
                  style={{
                    width: `${(item.count / max) * 100}%`,
                    background: color,
                  }}
                />
              </div>
              <strong className="mono">{item.count}</strong>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function SeverityPanel({ summary }: { summary: DashboardSummary }) {
  const rows: Severity[] = ['critical', 'high', 'medium', 'low']
  const max = Math.max(1, ...rows.map((key) => summary.severity[key]))

  return (
    <div className="neo-card">
      <h3 className="panel-title">Alerts by Severity</h3>
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

function DetectionPanel({ summary }: { summary: DashboardSummary }) {
  const entries = Object.entries(summary.detections)
  const max = Math.max(1, ...entries.map(([, count]) => count))

  return (
    <div className="neo-card">
      <h3 className="panel-title">Detections by Type</h3>
      {entries.length === 0 ? (
        <p className="state-hint">No detections recorded yet.</p>
      ) : (
        <div className="severity-list">
          {entries.map(([key, count]) => (
            <div key={key} className="severity-row">
              <span className="name">{detectionLabel(key)}</span>
              <div className="bar" role="presentation">
                <div
                  style={{
                    width: `${(count / max) * 100}%`,
                    background: DETECTION_COLOR,
                  }}
                />
              </div>
              <strong className="mono">{count}</strong>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ActivityPanel({ analytics }: { analytics: DashboardAnalytics }) {
  const data = analytics.activity.map((bucket) => ({
    ...bucket,
    label: bucket.time.slice(11, 16),
  }))

  return (
    <div className="neo-card">
      <h3 className="panel-title">Authentication Activity (24h)</h3>
      <div style={{ width: '100%', height: 260 }}>
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="anFailGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f87171" stopOpacity={0.45} />
                <stop offset="100%" stopColor="#f87171" stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="anOkGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#34d399" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#34d399" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(148,163,184,0.08)" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} minTickGap={28} />
            <YAxis tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip />
            <Area type="monotone" dataKey="failure" name="Failures" stroke="#f87171" strokeWidth={2} fill="url(#anFailGrad)" />
            <Area type="monotone" dataKey="success" name="Successes" stroke="#34d399" strokeWidth={2} fill="url(#anOkGrad)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default function Analytics() {
  const summary = useApi(fetchSummary, POLL_INTERVAL)
  const analytics = useApi(fetchAnalytics, POLL_INTERVAL)

  const loading = summary.loading || analytics.loading
  const error = summary.error ?? analytics.error

  if (loading && !summary.data && !analytics.data) {
    return <LoadingState label="Loading analytics..." />
  }

  if (error && !summary.data && !analytics.data) {
    return (
      <ErrorState
        message={error ?? 'Unknown error'}
        onRetry={() => {
          summary.refresh()
          analytics.refresh()
        }}
      />
    )
  }

  return (
    <>
      <h2 className="page-title">Threat Analytics</h2>

      {analytics.data && <ActivityPanel analytics={analytics.data} />}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: 20,
        }}
      >
        {summary.data && <SeverityPanel summary={summary.data} />}
        {summary.data && <DetectionPanel summary={summary.data} />}
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 20,
        }}
      >
        {analytics.data && (
          <BarList
            title="Top Attacking IPs (24h)"
            items={analytics.data.top_ips}
            color={IP_COLOR}
            emptyHint="No failed authentications in the last 24 hours."
          />
        )}
        {analytics.data && (
          <BarList
            title="Most Targeted Usernames (24h)"
            items={analytics.data.top_users}
            color={USER_COLOR}
            emptyHint="No targeted accounts in the last 24 hours."
          />
        )}
        {analytics.data && (
          <BarList
            title="Most Targeted Services (24h)"
            items={analytics.data.top_services}
            color={SERVICE_COLOR}
            emptyHint="No service activity in the last 24 hours."
          />
        )}
      </div>
    </>
  )
}