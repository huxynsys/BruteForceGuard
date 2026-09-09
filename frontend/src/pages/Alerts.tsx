import { useMemo, useState } from 'react'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { fetchAlerts } from '../api/alerts'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/States'
import { StatCard } from '../components/ui/Cards'
import AlertTable from '../components/alerts/AlertTable'
import { detectionLabel, type Severity } from '../types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']

export default function Alerts() {
  const { data, loading, error, lastUpdated, refresh } = useApi(
    () => fetchAlerts(200),
    POLL_INTERVAL,
  )

  const [severityFilter, setSeverityFilter] = useState('all')
  const [detectionFilter, setDetectionFilter] = useState('all')
  const [search, setSearch] = useState('')

  const detectionTypes = useMemo(() => {
    const set = new Set((data ?? []).map((alert) => alert.alert_type))
    return [...set].sort()
  }, [data])

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const alert of data ?? []) {
      counts[alert.severity] = (counts[alert.severity] ?? 0) + 1
    }
    return counts
  }, [data])

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return (data ?? []).filter((alert) => {
      if (severityFilter !== 'all' && alert.severity !== severityFilter)
        return false
      if (detectionFilter !== 'all' && alert.alert_type !== detectionFilter)
        return false
      if (!query) return true
      return (
        (alert.source_ip ?? '').toLowerCase().includes(query) ||
        (alert.username ?? '').toLowerCase().includes(query)
      )
    })
  }, [data, severityFilter, detectionFilter, search])

  if (loading && !data) return <LoadingState label="Loading alerts..." />
  if (error && !data) return <ErrorState message={error} onRetry={refresh} />

  return (
    <>
      <div className="kpi-grid">
        <StatCard label="Total Alerts" value={data?.length ?? 0} />
        <StatCard label="Critical" value={severityCounts['critical'] ?? 0} />
        <StatCard label="High" value={severityCounts['high'] ?? 0} />
        <StatCard label="Medium" value={severityCounts['medium'] ?? 0} />
        <StatCard label="Low" value={severityCounts['low'] ?? 0} />
      </div>

      <div className="toolbar">
        <input
          className="neo-input"
          placeholder="Search IP or username..."
          aria-label="Search alerts"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="neo-input"
          aria-label="Filter by severity"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="all">All severities</option>
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severity.toUpperCase()}
            </option>
          ))}
        </select>
        <select
          className="neo-input"
          aria-label="Filter by detection type"
          value={detectionFilter}
          onChange={(e) => setDetectionFilter(e.target.value)}
        >
          <option value="all">All detections</option>
          {detectionTypes.map((type) => (
            <option key={type} value={type}>
              {detectionLabel(type)}
            </option>
          ))}
        </select>
        <span className="toolbar-meta mono">
          {filtered.length} alerts
          {lastUpdated ? ` · updated ${lastUpdated.toLocaleTimeString()}` : ''}
        </span>
      </div>

      <div className="neo-card">
        {filtered.length === 0 ? (
          <EmptyState
            title="No alerts match your filters"
            hint="Detections will appear here as the engine flags attacks."
          />
        ) : (
          <AlertTable alerts={filtered} />
        )}
      </div>
    </>
  )
}
