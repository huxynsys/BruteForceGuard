import { useLocation } from 'react-router-dom'
import { useApi, POLL_INTERVAL } from '../../hooks/useApi'
import { fetchHealth } from '../../api/dashboard'

const PAGE_TITLES: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'Security Overview', subtitle: 'Real-time authentication threat monitoring' },
  '/events': { title: 'Authentication Events', subtitle: 'Raw authentication activity' },
  '/alerts': { title: 'Alerts', subtitle: 'Detection engine output' },
  '/sessions': { title: 'Attack Sessions', subtitle: 'Correlated attack activity' },
  '/analytics': { title: 'Analytics', subtitle: 'Visual threat analysis' },
  '/settings': { title: 'Settings', subtitle: 'Dashboard configuration' },
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export default function Topbar() {
  const location = useLocation()
  const { data, error, lastUpdated } = useApi(
    fetchHealth,
    POLL_INTERVAL,
  )

  const page = PAGE_TITLES[location.pathname] ?? {
    title: 'Session Details',
    subtitle: 'Attack session forensics',
  }

  const healthy = !error && data?.status === 'healthy'

  return (
    <header className="topbar">
      <div>
        <h1>{page.title}</h1>
        <div className="topbar-sub">{page.subtitle}</div>
      </div>

      <div
        className={`health ${healthy ? 'ok' : 'down'}`}
        role="status"
        aria-live="polite"
      >
        <span className="dot" aria-hidden="true" />
        {healthy ? 'SYSTEM HEALTHY' : 'DISCONNECTED'}
        {lastUpdated && (
          <span className="updated">Last updated: {formatTime(lastUpdated)}</span>
        )}
      </div>
    </header>
  )
}
