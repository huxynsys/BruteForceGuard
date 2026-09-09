import { useApi } from '../hooks/useApi'
import { fetchHealth } from '../api/dashboard'
import { fetchSessionStats } from '../api/sessions'
import { API_BASE_URL } from '../api/client'
import { POLL_INTERVAL } from '../hooks/useApi'

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="row spread" style={{ padding: '8px 0' }}>
      <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <span className="mono">{value}</span>
    </div>
  )
}

export default function Settings() {
  const health = useApi(fetchHealth, undefined)
  const stats = useApi(fetchSessionStats, undefined)

  return (
    <>
      <div className="neo-card" style={{ maxWidth: 640 }}>
        <h3 className="panel-title">Connection</h3>
        <Row label="API base URL" value={API_BASE_URL} />
        <Row
          label="Backend version"
          value={health.data?.version ?? health.error ? 'unavailable' : '...'}
        />
        <Row label="Backend status" value={health.data?.status ?? (health.error ? 'disconnected' : '...')} />
        <Row label="Polling interval" value={`${POLL_INTERVAL / 1000}s`} />
      </div>

      <div className="neo-card" style={{ maxWidth: 640, marginTop: 20 }}>
        <h3 className="panel-title">Live Session Statistics</h3>
        {stats.data ? (
          <>
            <Row label="Active sessions" value={String(stats.data.active_sessions)} />
            <Row label="Events in active sessions" value={String(stats.data.total_events)} />
            <Row label="Unique source IPs" value={String(stats.data.unique_source_ips)} />
            <Row label="Unique usernames" value={String(stats.data.unique_usernames)} />
          </>
        ) : (
          <p style={{ color: 'var(--text-muted)' }}>
            {stats.error ? 'Statistics unavailable.' : 'Loading...'}
          </p>
        )}
      </div>

      <div className="neo-card" style={{ maxWidth: 640, marginTop: 20 }}>
        <h3 className="panel-title">About</h3>
        <p style={{ color: 'var(--text-secondary)', margin: 0 }}>
          BruteForceGuard monitors authentication events, detects brute-force
          patterns, and correlates related detections into attack sessions.
          Configure collectors to feed authentication events into
          <span className="mono"> POST /api/v1/events/</span>.
        </p>
      </div>
    </>
  )
}
