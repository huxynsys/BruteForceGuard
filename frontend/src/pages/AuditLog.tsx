import { useState } from 'react'
import { RefreshCw, ShieldCheck } from 'lucide-react'

import { fetchAuditLog } from '../api/audit'
import AuditLogTable from '../components/audit/AuditLogTable'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import { AUDIT_ACTIONS, AUDIT_RESULTS, auditActionLabel, auditResultLabel } from '../lib/audit'
import type { AuditResult } from '../types'

/** Entries per page; paging is server-side (`skip`/`limit`). */
const PAGE_SIZE = 25

/**
 * Convert a `<input type="datetime-local">` value into an absolute instant.
 *
 * The control yields a wall-clock string with no zone (`2026-10-03T12:00`).
 * `new Date` reads it in the operator's local timezone and `toISOString`
 * emits the equivalent UTC instant, so the server never has to guess which
 * timezone the filter meant. Unparseable input is dropped rather than sent.
 */
function toInstantOrUndefined(value: string): string | undefined {
  if (!value) return undefined
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return undefined
  return parsed.toISOString()
}

/**
 * Security audit log.
 *
 * Read-only view of the append-only `security_audit_logs` table: entries are
 * written by server-side hooks (no API can create, edit or delete them) and
 * every field rendered here is the stored evidence, including server-side
 * `[REDACTED]` markers. Filtering and pagination run on the backend
 * (`GET /api/v1/audit/`, newest first); reading requires the admin role.
 */
export default function AuditLog() {
  const [action, setAction] = useState('all')
  const [result, setResult] = useState('all')
  const [userInput, setUserInput] = useState('')
  const [user, setUser] = useState('')
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const [page, setPage] = useState(0)

  const since = toInstantOrUndefined(sinceInput)
  const until = toInstantOrUndefined(untilInput)

  // Any filter or page change produces a new key, which refetches at once.
  const refetchKey = JSON.stringify({ action, result, user, since, until, page })

  const { data, loading, error, lastUpdated, refresh } = useApi(
    () =>
      fetchAuditLog({
        action: action === 'all' ? undefined : action,
        result: result === 'all' ? undefined : (result as AuditResult),
        user: user === '' ? undefined : user,
        since,
        until,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      }),
    POLL_INTERVAL,
    refetchKey,
  )

  const entries = data?.items ?? []
  const total = data?.total ?? 0
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const firstRow = total === 0 ? 0 : page * PAGE_SIZE + 1
  const lastRow = total === 0 ? 0 : page * PAGE_SIZE + entries.length
  const deniedOnPage = entries.filter((entry) => entry.result !== 'success').length
  const hasFilters =
    action !== 'all' ||
    result !== 'all' ||
    user !== '' ||
    sinceInput !== '' ||
    untilInput !== ''

  const applyFilter = (update: () => void) => {
    update()
    setPage(0)
  }

  const clearFilters = () => {
    setUserInput('')
    setSinceInput('')
    setUntilInput('')
    applyFilter(() => {
      setAction('all')
      setResult('all')
      setUser('')
    })
  }

  if (loading && !data) {
    return <LoadingState label="Loading audit log..." />
  }
  if (error && !data) {
    return <ErrorState message={error} onRetry={refresh} />
  }

  return (
    <div className="page-shell">
      <header className="page-header">
        <div>
          <p className="eyebrow">Security evidence</p>
          <h1>Audit Log</h1>
          <p className="page-header-copy">
            Append-only record of security-sensitive actions. Entries are written
            server-side alongside the change they describe and can never be
            edited or deleted; secrets are redacted before they are stored.
          </p>
        </div>
        <div className="page-header-kpis">
          <div className="mini-stat">
            <span>Matching entries</span>
            <strong>{total}</strong>
          </div>
          <div className="mini-stat">
            <span>Non-success on page</span>
            <strong>{deniedOnPage}</strong>
          </div>
          <div className="mini-stat">
            <span>Page</span>
            <strong>
              {Math.min(page + 1, pageCount)} / {pageCount}
            </strong>
          </div>
        </div>
      </header>
      <form
        className="toolbar filter-bar"
        role="search"
        aria-label="Filter audit log entries"
        onSubmit={(event) => {
          event.preventDefault()
          applyFilter(() => setUser(userInput.trim()))
        }}
      >
        <select
          className="neo-input"
          aria-label="Filter by action"
          value={action}
          onChange={(event) => applyFilter(() => setAction(event.target.value))}
        >
          <option value="all">All actions</option>
          {AUDIT_ACTIONS.map((value) => (
            <option key={value} value={value}>
              {auditActionLabel(value)}
            </option>
          ))}
        </select>

        <select
          className="neo-input"
          aria-label="Filter by result"
          value={result}
          onChange={(event) => applyFilter(() => setResult(event.target.value))}
        >
          <option value="all">All results</option>
          {AUDIT_RESULTS.map((value) => (
            <option key={value} value={value}>
              {auditResultLabel(value)}
            </option>
          ))}
        </select>

        <input
          className="neo-input"
          type="search"
          value={userInput}
          placeholder="Actor..."
          aria-label="Filter by actor"
          onChange={(event) => setUserInput(event.target.value)}
        />
        <button className="neo-button" type="submit">
          Filter
        </button>

        <input
          className="neo-input"
          type="datetime-local"
          value={sinceInput}
          aria-label="Recorded at or after"
          onChange={(event) =>
            applyFilter(() => setSinceInput(event.target.value))
          }
        />
        <input
          className="neo-input"
          type="datetime-local"
          value={untilInput}
          aria-label="Recorded at or before"
          onChange={(event) =>
            applyFilter(() => setUntilInput(event.target.value))
          }
        />

        {hasFilters && (
          <button className="neo-button" type="button" onClick={clearFilters}>
            Clear filters
          </button>
        )}

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
            : `${total} entr${total === 1 ? 'y' : 'ies'}`}
          {lastUpdated ? ` · updated ${lastUpdated.toLocaleTimeString()}` : ''}
        </span>
      </form>

      {error && data && (
        <div className="alert-banner alert-banner--warn" role="alert">
          <span>Refresh failed: {error}. Showing the last loaded entries.</span>
          <button className="neo-button neo-button--sm" type="button" onClick={refresh}>
            Retry
          </button>
        </div>
      )}

      <section className="neo-card" aria-labelledby="audit-log-title">
        <div className="section-header">
          <div>
            <p className="eyebrow">Append-only</p>
            <h2 className="panel-title" id="audit-log-title">
              Recorded actions
            </h2>
          </div>
          <ShieldCheck size={18} className="section-icon" aria-hidden="true" />
        </div>

        {entries.length === 0 ? (
          total > 0 ? (
            <>
              <EmptyState
                title="No entries on this page"
                hint="The filtered result set changed while you were paging."
              />
              <div className="state-action">
                <button className="neo-button" type="button" onClick={() => setPage(0)}>
                  Back to first page
                </button>
              </div>
            </>
          ) : hasFilters ? (
            <>
              <EmptyState
                title="No entries match these filters"
                hint="Widen the action, actor or time range to see more of the audit trail."
              />
              <div className="state-action">
                <button className="neo-button" type="button" onClick={clearFilters}>
                  Show all entries
                </button>
              </div>
            </>
          ) : (
            <EmptyState
              title="No audited actions yet"
              hint="Security-sensitive actions (alert triage, IP list changes, failed authorizations) appear here as they happen."
            />
          )
        ) : (
          <AuditLogTable entries={entries} />
        )}
      </section>

      {total > 0 && (
        <nav className="pager" aria-label="Audit log pagination">
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
            onClick={() => setPage(Math.max(0, page - 1))}
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
            onClick={() => setPage(page + 1)}
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
    </div>
  )
}
