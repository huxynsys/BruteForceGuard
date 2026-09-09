import { useMemo, useState } from 'react'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { fetchSessions } from '../api/sessions'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/States'
import { StatCard } from '../components/ui/Cards'
import SessionTable from '../components/sessions/SessionTable'

type StatusTab = 'all' | 'active' | 'closed'

export default function Sessions() {
  const { data, loading, error, lastUpdated, refresh } = useApi(
    () => fetchSessions(),
    POLL_INTERVAL,
  )

  const [tab, setTab] = useState<StatusTab>('all')

  const filtered = useMemo(() => {
    const sessions = data ?? []
    if (tab === 'all') return sessions
    return sessions.filter((session) => session.status === tab)
  }, [data, tab])

  const activeCount = useMemo(
    () => (data ?? []).filter((session) => session.status === 'active').length,
    [data],
  )

  if (loading && !data) return <LoadingState label="Loading attack sessions..." />
  if (error && !data) return <ErrorState message={error} onRetry={refresh} />

  return (
    <>
      <div className="kpi-grid">
        <StatCard label="Total Sessions" value={data?.length ?? 0} />
        <StatCard label="Active" value={activeCount} />
        <StatCard
          label="Closed"
          value={(data?.length ?? 0) - activeCount}
        />
        <StatCard
          label="Total Events In Sessions"
          value={
            (data ?? []).reduce((sum, session) => sum + session.event_count, 0)
          }
        />
      </div>

      <div className="toolbar" role="tablist" aria-label="Session status filter">
        {(['all', 'active', 'closed'] as StatusTab[]).map((value) => (
          <button
            key={value}
            role="tab"
            aria-selected={tab === value}
            className={`neo-button${tab === value ? ' selected' : ''}`}
            onClick={() => setTab(value)}
          >
            {value.toUpperCase()}
          </button>
        ))}
        <span className="toolbar-meta mono">
          {filtered.length} sessions
          {lastUpdated ? ` · updated ${lastUpdated.toLocaleTimeString()}` : ''}
        </span>
      </div>

      <div className="neo-card">
        {filtered.length === 0 ? (
          <EmptyState
            title="No attack sessions"
            hint="Correlated attack activity will appear here as detections occur."
          />
        ) : (
          <SessionTable sessions={filtered} />
        )}
      </div>
    </>
  )
}
