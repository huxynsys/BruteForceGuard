import { useMemo, useState } from 'react'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { fetchEvents } from '../api/events'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/States'
import { ResultBadge } from '../components/ui/Cards'
import { formatDateTime } from '../lib/format'

export default function Events() {
  const { data, loading, error, lastUpdated, refresh } = useApi(
    () => fetchEvents(200),
    POLL_INTERVAL,
  )

  const [search, setSearch] = useState('')
  const [resultFilter, setResultFilter] = useState('all')
  const [serviceFilter, setServiceFilter] = useState('all')

  const services = useMemo(() => {
    const set = new Set(
      (data ?? [])
        .map((event) => event.service)
        .filter((service): service is string => Boolean(service)),
    )
    return [...set].sort()
  }, [data])

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return (data ?? []).filter((event) => {
      if (resultFilter !== 'all' && event.result !== resultFilter) return false
      if (serviceFilter !== 'all' && event.service !== serviceFilter) return false
      if (!query) return true
      return (
        (event.source_ip ?? '').toLowerCase().includes(query) ||
        (event.username ?? '').toLowerCase().includes(query)
      )
    })
  }, [data, search, resultFilter, serviceFilter])

  if (loading && !data) return <LoadingState label="Loading events..." />
  if (error && !data) return <ErrorState message={error} onRetry={refresh} />

  return (
    <>
      <div className="toolbar">
        <input
          className="neo-input"
          placeholder="Search IP or username..."
          aria-label="Search events"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="neo-input"
          aria-label="Filter by result"
          value={resultFilter}
          onChange={(e) => setResultFilter(e.target.value)}
        >
          <option value="all">All results</option>
          <option value="failure">Failure</option>
          <option value="success">Success</option>
        </select>
        <select
          className="neo-input"
          aria-label="Filter by service"
          value={serviceFilter}
          onChange={(e) => setServiceFilter(e.target.value)}
        >
          <option value="all">All services</option>
          {services.map((service) => (
            <option key={service} value={service}>
              {service.toUpperCase()}
            </option>
          ))}
        </select>
        <span className="toolbar-meta mono">
          {filtered.length} events
          {lastUpdated ? ` · updated ${lastUpdated.toLocaleTimeString()}` : ''}
        </span>
      </div>

      <div className="neo-card">
        {filtered.length === 0 ? (
          <EmptyState
            title="No events match your filters"
            hint="Adjust the search or filters, or send authentication events to the API."
          />
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Username</th>
                  <th scope="col">Service</th>
                  <th scope="col">Port</th>
                  <th scope="col">Result</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => (
                  <tr key={event.id}>
                    <td className="mono">{formatDateTime(event.timestamp)}</td>
                    <td className="mono">{event.source_ip ?? '—'}</td>
                    <td className="mono">{event.username ?? '—'}</td>
                    <td>{(event.service ?? '—').toUpperCase()}</td>
                    <td className="mono">{event.port ?? '—'}</td>
                    <td>
                      <ResultBadge result={event.result} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
