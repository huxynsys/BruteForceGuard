import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight, RefreshCw } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { fetchEventGroups, type EventGroupSort } from '../api/events'
import { LoadingState, ErrorState, EmptyState } from '../components/ui/States'
import { ResultBadge } from '../components/ui/Cards'
import { formatDateTime } from '../lib/format'
import { detectionLabel } from '../lib/detectionLabels'
import type { EventGroup } from '../types'

/** Groups per page; paging is server-side (`skip`/`limit`). */
const PAGE_SIZE = 20
/**
 * Events embedded per group for the expanded view. The backend clamps this
 * to 100 and returns only the most recent events, so the browser never
 * receives an unbounded raw event list.
 */
const EVENTS_PER_GROUP = 50

type ResultFilter = 'all' | 'success' | 'failure'

const SORTS: { value: EventGroupSort; label: string }[] = [
  { value: 'recent', label: 'Most recent' },
  { value: 'events', label: 'Most events' },
  { value: 'ip', label: 'Source IP (A–Z)' },
]

function detectionSummary(group: EventGroup): string {
  if (group.alert_types.length === 0) return '—'
  return group.alert_types.map(detectionLabel).join(', ')
}

function usernameSummary(usernames: string[]): string {
  if (usernames.length === 0) return '—'
  if (usernames.length <= 3) return usernames.join(', ')
  return `${usernames.slice(0, 3).join(', ')} +${usernames.length - 3} more`
}

/**
 * Expanded accordion content: one row per raw event (most recent first,
 * capped server-side). `AuthEvent` has no per-event session foreign key, so
 * the Session ID column shows the sessions correlated to this group's source
 * IP via alerts — real data, never synthesized. Likewise the Event type
 * column falls back to the collector `source` because the model has no
 * dedicated event-type column.
 */
function GroupEvents({ group }: { group: EventGroup }) {
  const truncated = group.events.length < group.event_count

  return (
    <tr id={`group-detail-${group.group_key}`}>
      <td colSpan={8} className="event-detail-cell">
        <div className="event-detail">
          <div className="group-context">
            <span>
              <b>Services</b>
              <span className="mono">
                {group.services.length ? group.services.join(', ') : '—'}
              </span>
            </span>
            <span>
              <b>Sessions</b>
              <span className="mono">
                {group.session_ids.length
                  ? group.session_ids.map((id) => (
                      <Link key={id} to={`/sessions/${id}`}>{`#${id}`}</Link>
                    ))
                  : '—'}
              </span>
            </span>
            <span>
              <b>Window</b>
              <span className="mono">
                {formatDateTime(group.first_seen)} &rarr;{' '}
                {formatDateTime(group.last_seen)}
              </span>
            </span>
            {truncated && (
              <span className="group-truncated">
                Showing the {group.events.length} most recent of{' '}
                {group.event_count} events
              </span>
            )}
          </div>

          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Timestamp</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Username</th>
                  <th scope="col">Service</th>
                  <th scope="col">Port</th>
                  <th scope="col">Result</th>
                  <th scope="col">Event type</th>
                  <th scope="col">Session ID</th>
                  <th scope="col">Raw event details</th>
                </tr>
              </thead>
              <tbody>
                {group.events.map((event) => (
                  <tr key={event.id}>
                    <td className="mono">{formatDateTime(event.timestamp)}</td>
                    <td className="mono">{event.source_ip}</td>
                    <td className="mono">{event.username ?? '—'}</td>
                    <td>{(event.service ?? '—').toUpperCase()}</td>
                    <td className="mono">{event.port ?? '—'}</td>
                    <td>
                      <ResultBadge result={event.result} />
                    </td>
                    <td>{event.source}</td>
                    <td className="mono">
                      {group.session_ids.length
                        ? group.session_ids.map((id) => `#${id}`).join(', ')
                        : '—'}
                    </td>
                    <td>
                      {event.raw_event ? (
                        <details className="raw-details">
                          <summary>JSON</summary>
                          <pre>{JSON.stringify(event.raw_event, null, 2)}</pre>
                        </details>
                      ) : (
                        '—'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </td>
    </tr>
  )
}

/**
 * Authentication events, grouped server-side by their strongest correlation
 * identifier (source IP — `AuthEvent` carries no session foreign key).
 *
 * Search, result filtering, sorting and pagination all run on the backend
 * (`GET /api/v1/events/groups`), so the browser never loads an unbounded raw
 * event list. Collapsed rows show group aggregates; expanding a row reveals
 * the capped per-event detail table that ships with the group payload.
 */
export default function Events() {
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [result, setResult] = useState<ResultFilter>('all')
  const [sort, setSort] = useState<EventGroupSort>('recent')
  const [page, setPage] = useState(0)
  const [expandedKey, setExpandedKey] = useState<string | null>(null)

  // Any filter or page change produces a new key, which refetches at once.
  const refetchKey = JSON.stringify({ search, result, sort, page })

  const { data, loading, error, lastUpdated, refresh } = useApi(
    () =>
      fetchEventGroups({
        search: search === '' ? undefined : search,
        result: result === 'all' ? undefined : result,
        sort,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
        events_limit: EVENTS_PER_GROUP,
      }),
    POLL_INTERVAL,
    refetchKey,
  )

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const firstRow = total === 0 ? 0 : page * PAGE_SIZE + 1
  const lastRow = total === 0 ? 0 : page * PAGE_SIZE + items.length
  const hasFilters = Boolean(search) || result !== 'all'

  /** Apply a filter change and jump back to the first page. */
  const applyFilter = (update: () => void) => {
    update()
    setPage(0)
    setExpandedKey(null)
  }

  const clearFilters = () => {
    setSearchInput('')
    applyFilter(() => {
      setSearch('')
      setResult('all')
    })
  }

  const gotoPage = (next: number) => {
    setPage(next)
    setExpandedKey(null)
  }

  const toggleGroup = (key: string) => {
    setExpandedKey((current) => (current === key ? null : key))
  }

  if (loading && !data) return <LoadingState label="Loading event groups..." />
  if (error && !data) return <ErrorState message={error} onRetry={refresh} />

  return (
    <>
      <form
        className="toolbar filter-bar"
        role="search"
        aria-label="Search and filter event groups"
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
          aria-label="Search events by source IP or username"
          onChange={(event) => setSearchInput(event.target.value)}
        />
        <button className="neo-button" type="submit">
          Search
        </button>
        <select
          className="neo-input"
          aria-label="Filter by result"
          value={result}
          onChange={(event) =>
            applyFilter(() => setResult(event.target.value as ResultFilter))
          }
        >
          <option value="all">All results</option>
          <option value="failure">Failure</option>
          <option value="success">Success</option>
        </select>
        <select
          className="neo-input"
          aria-label="Sort groups"
          value={sort}
          onChange={(event) =>
            applyFilter(() => setSort(event.target.value as EventGroupSort))
          }
        >
          {SORTS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <button
          className="neo-button"
          type="button"
          onClick={refresh}
          disabled={loading}
        >
          <RefreshCw size={14} aria-hidden="true" /> Refresh
        </button>
        <span className="toolbar-meta mono">
          {loading && data
            ? 'Refreshing...'
            : `${total} group${total === 1 ? '' : 's'}`}
          {lastUpdated ? ` · updated ${lastUpdated.toLocaleTimeString()}` : ''}
        </span>
      </form>

      {error && data && (
        <div className="alert-banner alert-banner--warn" role="alert">
          <span>
            Refresh failed: {error}. Showing the last loaded event groups.
          </span>
          <button
            className="neo-button neo-button--sm"
            type="button"
            onClick={refresh}
          >
            Retry
          </button>
        </div>
      )}

      <div className="neo-card">
        {items.length === 0 ? (
          total > 0 ? (
            <>
              <EmptyState
                title="No event groups on this page"
                hint="The filtered result set changed while you were paging."
              />
              <div className="state-action">
                <button
                  className="neo-button"
                  type="button"
                  onClick={() => gotoPage(0)}
                >
                  Back to the first page
                </button>
              </div>
            </>
          ) : hasFilters ? (
            <>
              <EmptyState
                title="No event groups match your filters"
                hint="Broaden the search or clear the filters to see more events."
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
              title="No authentication events yet"
              hint="Correlated event groups will appear here once collectors send events."
            />
          )
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Source IP</th>
                  <th scope="col">Target username(s)</th>
                  <th scope="col">Start</th>
                  <th scope="col">End</th>
                  <th scope="col">Total events</th>
                  <th scope="col">Success</th>
                  <th scope="col">Failure</th>
                  <th scope="col">Detection type</th>
                </tr>
              </thead>
              <tbody>
                {items.map((group) => {
                  const expanded = expandedKey === group.group_key
                  return (
                    <Fragment key={group.group_key}>
                      <tr>
                        <td>
                          <button
                            className="event-group__toggle"
                            type="button"
                            aria-expanded={expanded}
                            aria-controls={`group-detail-${group.group_key}`}
                            onClick={() => toggleGroup(group.group_key)}
                          >
                            {expanded ? (
                              <ChevronDown size={15} aria-hidden="true" />
                            ) : (
                              <ChevronRight size={15} aria-hidden="true" />
                            )}
                            <span className="mono">{group.group_key}</span>
                          </button>
                        </td>
                        <td>{usernameSummary(group.usernames)}</td>
                        <td className="mono">
                          {formatDateTime(group.first_seen)}
                        </td>
                        <td className="mono">
                          {formatDateTime(group.last_seen)}
                        </td>
                        <td className="mono">{group.event_count}</td>
                        <td className="mono metric-ok">{group.success_count}</td>
                        <td className="mono metric-fail">
                          {group.failure_count}
                        </td>
                        <td>{detectionSummary(group)}</td>
                      </tr>
                      {expanded && <GroupEvents group={group} />}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {total > 0 && (
        <nav className="pager" aria-label="Event group pagination">
          <button
            className="neo-button"
            type="button"
            disabled={page === 0}
            onClick={() => gotoPage(0)}
          >
            First
          </button>
          <button
            className="neo-button"
            type="button"
            disabled={page === 0}
            onClick={() => gotoPage(Math.max(0, page - 1))}
          >
            Previous
          </button>
          <span className="pager__info mono">
            Page {Math.min(page + 1, pageCount)} of {pageCount} &middot;
            showing {firstRow}&ndash;{lastRow} of {total}
          </span>
          <button
            className="neo-button"
            type="button"
            disabled={page + 1 >= pageCount}
            onClick={() => gotoPage(page + 1)}
          >
            Next
          </button>
          <button
            className="neo-button"
            type="button"
            disabled={page + 1 >= pageCount}
            onClick={() => gotoPage(pageCount - 1)}
          >
            Last
          </button>
        </nav>
      )}
    </>
  )
}
