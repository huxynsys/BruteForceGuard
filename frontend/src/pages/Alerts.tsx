import { useMemo, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { fetchAlertsPage, updateAlertStatus } from '../api/alerts'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import { StatusBadge } from '../components/ui/Cards'
import AlertTable from '../components/alerts/AlertTable'
import AlertDetailPanel from '../components/alerts/AlertDetailPanel'
import { ALERT_STATUSES, alertStatusLabel } from '../lib/labels'
import { detectionLabel } from '../lib/detectionLabels'
import type { Alert, AlertStatus, Severity } from '../types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']

/** Alerts per page; paging is server-side (`skip`/`limit`). */
const PAGE_SIZE = 25

type SeverityFilter = 'all' | Severity
type StatusFilter = 'all' | AlertStatus

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

/**
 * Alerts work queue - the authoritative detailed view of detections.
 *
 * Filtering, search and pagination are performed by the backend
 * (`GET /api/v1/alerts/` + `/stats`) and Acknowledge/Resolve persist a triage
 * transition through `PATCH /api/v1/alerts/{id}` before the table is
 * refreshed from the server.
 *
 * Selecting a row opens the alert details side panel for that alert.
 */
export default function Alerts() {
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<SeverityFilter>('all')
  const [status, setStatus] = useState<StatusFilter>('all')
  const [detectionType, setDetectionType] = useState('all')
  const [page, setPage] = useState(0)

  const [pendingId, setPendingId] = useState<number | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  /** Alert whose details side panel is open. */
  const [selectedId, setSelectedId] = useState<number | null>(null)

  const filters = useMemo(
    () => ({
      severity: severity === 'all' ? undefined : severity,
      status: status === 'all' ? undefined : status,
      alertType: detectionType === 'all' ? undefined : detectionType,
      search: search === '' ? undefined : search,
    }),
    [severity, status, detectionType, search],
  )

  // Any filter or page change produces a new key, which refetches at once.
  const refetchKey = JSON.stringify({ ...filters, page })

  const { data, loading, error, lastUpdated, refresh } = useApi(
    () =>
      fetchAlertsPage({
        ...filters,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      }),
    POLL_INTERVAL,
    refetchKey,
  )

  const items = data?.items ?? []
  const total = data?.total ?? 0
  // The selected alert is always read from the latest server page, so the side
  // panel shows persisted values and closes itself once the alert no longer
  // matches the active filters or page.
  const selectedAlert = items.find((item) => item.id === selectedId) ?? null
  const statusCounts = data?.stats.by_status ?? {}
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const firstRow = total === 0 ? 0 : page * PAGE_SIZE + 1
  const lastRow = total === 0 ? 0 : page * PAGE_SIZE + items.length
  const hasFilters = Boolean(
    filters.severity || filters.status || filters.alertType || filters.search,
  )

  // Detection-type options come from real data; the selected value is kept
  // even when the current facet counts no longer include it.
  const detectionTypeOptions = useMemo(() => {
    const options = new Set(Object.keys(data?.stats.by_alert_type ?? {}))
    if (detectionType !== 'all') options.add(detectionType)
    return [...options].sort((left, right) =>
      detectionLabel(left).localeCompare(detectionLabel(right)),
    )
  }, [data, detectionType])

  const clearFeedbacks = () => {
    setActionError(null)
    setNotice(null)
  }

  /** Every filter change resets paging (the result set changed). */
  const applyFilter = (apply: () => void) => {
    apply()
    setPage(0)
    clearFeedbacks()
  }

  const clearFilters = () => {
    setSearchInput('')
    setSearch('')
    setSeverity('all')
    setStatus('all')
    setDetectionType('all')
    setPage(0)
    clearFeedbacks()
  }

  /** Selecting a row opens the alert details side panel for that alert. */
  const handleSelect = (alert: Alert) => {
    setSelectedId(alert.id)
    clearFeedbacks()
  }

  const closePanel = () => setSelectedId(null)

  const handleStatusChange = async (alert: Alert, next: AlertStatus) => {
    setPendingId(alert.id)
    clearFeedbacks()

    try {
      await updateAlertStatus(alert.id, next)
      setNotice(
        `Alert #${alert.id} marked as ${alertStatusLabel(next).toLowerCase()}.`,
      )
      // Reload from the backend: the row must show the persisted value.
      refresh()
    } catch (err) {
      setActionError(
        `Could not update alert #${alert.id}: ${
          err instanceof Error ? err.message : 'unknown error'
        }`,
      )
    } finally {
      setPendingId(null)
    }
  }

  if (loading && !data) {
    return <LoadingState label="Loading alerts..." />
  }

  if (error && !data) {
    return <ErrorState message={error} onRetry={refresh} />
  }

  return (
    <>
      <form
        className="toolbar filter-bar"
        role="search"
        aria-label="Filter alerts"
        onSubmit={(event) => {
          event.preventDefault()
          applyFilter(() => setSearch(searchInput.trim()))
        }}
      >
        <input
          className="neo-input"
          type="search"
          value={searchInput}
          placeholder="Search source IP or username..."
          aria-label="Search alerts by source IP or username"
          onChange={(event) => setSearchInput(event.target.value)}
        />
        <button className="neo-button" type="submit">
          Search
        </button>
        <select
          className="neo-input"
          value={severity}
          aria-label="Filter by severity"
          onChange={(event) =>
            applyFilter(() => setSeverity(event.target.value as SeverityFilter))
          }
        >
          <option value="all">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {value.toUpperCase()}
            </option>
          ))}
        </select>

        <select
          className="neo-input"
          value={detectionType}
          aria-label="Filter by detection type"
          onChange={(event) =>
            applyFilter(() => setDetectionType(event.target.value))
          }
        >
          <option value="all">All detection types</option>
          {detectionTypeOptions.map((value) => (
            <option key={value} value={value}>
              {detectionLabel(value)}
            </option>
          ))}
        </select>

        <select
          className="neo-input"
          value={status}
          aria-label="Filter by status"
          onChange={(event) =>
            applyFilter(() => setStatus(event.target.value as StatusFilter))
          }
        >
          <option value="all">All statuses</option>
          {ALERT_STATUSES.map((value) => (
            <option key={value} value={value}>
              {alertStatusLabel(value)}
            </option>
          ))}
        </select>

        {hasFilters && (
          <button className="neo-button" type="button" onClick={clearFilters}>
            Clear filters
          </button>
        )}

        <button
          className="neo-button"
          type="button"
          aria-label="Refresh alerts"
          onClick={refresh}
        >
          <RefreshCw size={14} aria-hidden="true" />
        </button>

        <span className="toolbar-meta mono">
          {loading
            ? 'Refreshing...'
            : hasFilters
              ? `${plural(total, 'alert')} match`
              : plural(total, 'alert')}
          {lastUpdated ? ` · updated ${lastUpdated.toLocaleTimeString()}` : ''}
        </span>
      </form>

      {actionError && (
        <div className="alert-banner alert-banner--error" role="alert">
          <span>{actionError}</span>
          <button
            type="button"
            className="neo-button neo-button--sm"
            onClick={() => setActionError(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {notice && (
        <div className="alert-banner alert-banner--ok" role="status">
          <span>{notice}</span>
          <button
            type="button"
            className="neo-button neo-button--sm"
            onClick={() => setNotice(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {error && data && (
        <div className="alert-banner alert-banner--warn" role="alert">
          <span>Refresh failed: {error}. Showing the last loaded alerts.</span>
          <button
            type="button"
            className="neo-button neo-button--sm"
            onClick={refresh}
          >
            Retry
          </button>
        </div>
      )}

      {Object.keys(statusCounts).length > 0 && (
        <div className="status-summary" aria-label="Alert status breakdown">
          {ALERT_STATUSES.filter((value) => statusCounts[value]).map((value) => (
            <span key={value} className="status-summary__item">
              <StatusBadge status={value} />
              <strong className="mono">{statusCounts[value]}</strong>
            </span>
          ))}
        </div>
      )}

      <div className="neo-card">
        {items.length === 0 ? (
          total > 0 ? (
            <>
              <EmptyState
                title="No alerts on this page"
                hint="The filtered result set changed while you were paging."
              />
              <div className="state-action">
                <button
                  className="neo-button"
                  type="button"
                  onClick={() => setPage(0)}
                >
                  Back to the first page
                </button>
              </div>
            </>
          ) : hasFilters ? (
            <>
              <EmptyState
                title="No alerts match your filters"
                hint="Broaden the search or clear the filters to see more alerts."
              />
              <div className="state-action">
                <button
                  className="neo-button"
                  type="button"
                  onClick={clearFilters}
                >
                  Clear filters
                </button>
              </div>
            </>
          ) : (
            <EmptyState
              title="No alerts recorded yet"
              hint="Detections will appear here as the engine flags attacks."
            />
          )
        ) : (
          <AlertTable
            alerts={items}
            onStatusChange={handleStatusChange}
            pendingId={pendingId}
            selectedId={selectedId}
            onSelect={handleSelect}
          />
        )}
      </div>

      {total > 0 && (
        <nav className="pager" aria-label="Alert pagination">
          <button
            className="neo-button"
            type="button"
            disabled={page === 0}
            onClick={() => setPage(0)}
          >
            First
          </button>
          <button
            className="neo-button"
            type="button"
            disabled={page === 0}
            onClick={() => setPage((value) => Math.max(0, value - 1))}
          >
            Previous
          </button>
          <span className="pager__info mono">
            Page {Math.min(page + 1, pageCount)} of {pageCount} &middot; showing{' '}
            {firstRow}&ndash;{lastRow} of {total}
          </span>
          <button
            className="neo-button"
            type="button"
            disabled={page + 1 >= pageCount}
            onClick={() => setPage((value) => value + 1)}
          >
            Next
          </button>
          <button
            className="neo-button"
            type="button"
            disabled={page + 1 >= pageCount}
            onClick={() => setPage(pageCount - 1)}
          >
            Last
          </button>
        </nav>
      )}

      {selectedAlert && (
        <AlertDetailPanel
          alert={selectedAlert}
          pending={pendingId === selectedAlert.id}
          onStatusChange={handleStatusChange}
          onClose={closePanel}
        />
      )}
    </>
  )
}
