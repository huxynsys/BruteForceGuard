import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import {
  fetchAnalytics,
  fetchHealth,
  fetchReadiness,
  fetchSummary,
} from '../api/dashboard'
import { fetchAlerts } from '../api/alerts'
import Dashboard from './Dashboard'
import { ErrorState, LoadingState } from '../components/ui/States'

/**
 * Number of recent alerts the overview highlights. The full, filterable
 * alert list is the /alerts page's job.
 */
const RECENT_ALERT_LIMIT = 3

/**
 * Data-fetching wrapper for the security overview.
 *
 * Owns every request the overview needs so the presentational Dashboard stays
 * pure: posture KPIs (summary), the 24-hour trend (analytics), the newest
 * detections (alerts) and the two health probes (/health, /health/ready).
 */
export default function DashboardPage() {
  const summary = useApi(fetchSummary, POLL_INTERVAL)
  const analytics = useApi(fetchAnalytics, POLL_INTERVAL)
  const alerts = useApi(() => fetchAlerts(RECENT_ALERT_LIMIT), POLL_INTERVAL)
  const health = useApi(fetchHealth, POLL_INTERVAL)
  const readiness = useApi(fetchReadiness, POLL_INTERVAL)

  const refreshAll = () => {
    summary.refresh()
    analytics.refresh()
    alerts.refresh()
    health.refresh()
    readiness.refresh()
  }

  // The KPIs are the backbone of the page: block on the first load, then keep
  // the last good data when a later poll fails so an analyst is never left
  // blind. Panel-level failures render inside their own panel.
  if (summary.loading && !summary.data) {
    return <LoadingState label="Loading security overview..." />
  }

  if (summary.error && !summary.data) {
    return <ErrorState message={summary.error} onRetry={refreshAll} />
  }

  return (
    <Dashboard
      summary={summary}
      analytics={analytics}
      alerts={alerts}
      health={health}
      readiness={readiness}
      onRefresh={refreshAll}
    />
  )
}
