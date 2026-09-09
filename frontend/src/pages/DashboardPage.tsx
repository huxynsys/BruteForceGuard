import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { fetchSummary, fetchAnalytics } from '../api/dashboard'
import { fetchSessions } from '../api/sessions'
import { fetchAlerts } from '../api/alerts'
import Dashboard from './Dashboard'
import { ErrorState } from '../components/ui/States'

/**
 * Data-fetching wrapper around the presentational Dashboard.
 * Polls the four dashboard data sources on the shared interval.
 */
export default function DashboardPage() {
  const summary = useApi(fetchSummary, POLL_INTERVAL)
  const analytics = useApi(fetchAnalytics, POLL_INTERVAL)
  const sessions = useApi(() => fetchSessions('active'), POLL_INTERVAL)
  const alerts = useApi(() => fetchAlerts(100), POLL_INTERVAL)

  const loading =
    summary.loading || analytics.loading || sessions.loading || alerts.loading
  const error =
    summary.error ?? analytics.error ?? sessions.error ?? alerts.error

  if (loading && !summary.data) {
    return null // Topbar already shows connection state; avoid layout flash
  }

  if (error && !summary.data) {
    return <ErrorState message={error} onRetry={summary.refresh} />
  }

  return (
    <Dashboard
      summary={summary.data}
      analytics={analytics.data}
      activeSessions={sessions.data ?? []}
      recentAlerts={alerts.data ?? []}
      loading={loading}
      error={error}
      onRetry={() => {
        summary.refresh()
        analytics.refresh()
        sessions.refresh()
        alerts.refresh()
      }}
    />
  )
}
