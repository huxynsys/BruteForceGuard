import { useMemo, useState, type FormEvent } from 'react'
import { ShieldAlert, ShieldCheck, Trash2, Plus } from 'lucide-react'

import { blockIpAddress, deleteBlacklistEntry, fetchBlacklistEntries } from '../api/blacklist'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import type { BlacklistEntry } from '../types'

type ListType = 'BLOCKLIST' | 'WHITELIST'

const EMPTY_FORM = {
  ipAddress: '',
  description: '',
  listType: 'BLOCKLIST' as ListType,
}

function entryLabel(entry: BlacklistEntry): string {
  if (entry.entry_type === 'SINGLE') return entry.ip_address ?? 'Unknown IP'
  if (entry.entry_type === 'RANGE') return `${entry.ip_range_start ?? 'start'}-${entry.ip_range_end ?? 'end'}`
  return entry.region_code ?? 'Unknown region'
}

export default function IPManagementPage() {
  const [form, setForm] = useState(EMPTY_FORM)
  const [pendingAction, setPendingAction] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const blocklist = useApi(() => fetchBlacklistEntries(100, 'BLOCKLIST'), POLL_INTERVAL)
  const whitelist = useApi(() => fetchBlacklistEntries(100, 'WHITELIST'), POLL_INTERVAL)

  const refreshLists = () => {
    blocklist.refresh()
    whitelist.refresh()
  }

  const blockEntries = blocklist.data ?? []
  const whiteEntries = whitelist.data ?? []

  const totalManaged = useMemo(
    () => blockEntries.length + whiteEntries.length,
    [blockEntries.length, whiteEntries.length],
  )

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const ipAddress = form.ipAddress.trim()
    if (!ipAddress) {
      setError('Enter an IPv4 or IPv6 address before saving.')
      return
    }

    const actionLabel = form.listType === 'BLOCKLIST' ? 'Block IP' : 'Whitelist IP'
    const confirmed = window.confirm(
      `${actionLabel} ${ipAddress}? This action will persist a management entry on the server.`,
    )

    if (!confirmed) return

    setPendingAction(actionLabel)
    setError(null)

    try {
      await blockIpAddress(ipAddress, form.description, {
        listType: form.listType,
        addedBy: 'analyst',
      })
      setForm(EMPTY_FORM)
      refreshLists()
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'The IP could not be saved for management.',
      )
    } finally {
      setPendingAction(null)
    }
  }

  const handleDelete = async (entry: BlacklistEntry) => {
    const action = entry.list_type === 'BLOCKLIST' ? 'unblock' : 'remove from whitelist'
    const confirmed = window.confirm(
      `Confirm removing ${entryLabel(entry)} from the ${entry.list_type.toLowerCase()}?`,
    )

    if (!confirmed) return

    setPendingAction(action)
    setError(null)

    try {
      await deleteBlacklistEntry(entry.id)
      refreshLists()
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'The management entry could not be removed.',
      )
    } finally {
      setPendingAction(null)
    }
  }

  if (blocklist.loading && !blocklist.data) {
    return <LoadingState label="Loading IP management entries..." />
  }

  if (blocklist.error && !blocklist.data) {
    return <ErrorState message={blocklist.error} onRetry={refreshLists} />
  }

  return (
    <div className="page-shell">
      <header className="page-header">
        <div>
          <p className="eyebrow">Threat Operations</p>
          <h1>IP Management</h1>
        </div>
        <div className="page-header-kpis">
          <div className="mini-stat">
            <span>Total managed</span>
            <strong>{totalManaged}</strong>
          </div>
          <div className="mini-stat">
            <span>Blocked</span>
            <strong>{blockEntries.length}</strong>
          </div>
          <div className="mini-stat">
            <span>Whitelisted</span>
            <strong>{whiteEntries.length}</strong>
          </div>
        </div>
      </header>

      <section className="neo-card ip-form-panel">
        <h2 className="panel-title">Add IP</h2>
        <form className="ip-form" onSubmit={handleSubmit}>
          <div className="field-row">
            <label>
              <span>IP address</span>
              <input
                className="neo-input"
                value={form.ipAddress}
                onChange={(event) => setForm((current) => ({ ...current, ipAddress: event.target.value }))}
                placeholder="203.0.113.10"
              />
            </label>

            <label>
              <span>List</span>
              <select
                className="neo-input"
                value={form.listType}
                onChange={(event) =>
                  setForm((current) => ({
                    ...current,
                    listType: event.target.value as ListType,
                  }))
                }
              >
                <option value="BLOCKLIST">BLOCKLIST</option>
                <option value="WHITELIST">WHITELIST</option>
              </select>
            </label>
          </div>

          <label>
            <span>Reason</span>
            <input
              className="neo-input"
              value={form.description}
              onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
              placeholder="Repeated brute-force traffic"
            />
          </label>

          <div className="action-row">
            <button className="neo-button" type="submit" disabled={pendingAction !== null}>
              <Plus size={16} />
              {pendingAction === 'Block IP' || pendingAction === 'Whitelist IP'
                ? 'Saving...'
                : form.listType === 'BLOCKLIST'
                  ? 'Block IP'
                  : 'Whitelist IP'}
            </button>
          </div>
        </form>

        {error && <div className="inline-error">{error}</div>}
      </section>

      <div className="list-grid">
        <section className="neo-card">
          <div className="section-header">
            <h2 className="panel-title">BLOCKLIST</h2>
            <ShieldAlert size={18} className="section-icon danger" />
          </div>
          {blockEntries.length === 0 ? (
            <EmptyState title="No blocked IPs" hint="No source IPs are currently blocked." />
          ) : (
            <div className="entries-table">
              {blockEntries.map((entry) => (
                <div key={entry.id} className="entry-row">
                  <div>
                    <div className="entry-ip">{entryLabel(entry)}</div>
                    <div className="entry-meta">
                      {entry.description || 'No note provided'}
                    </div>
                    <div className="entry-meta muted">
                      Added by {entry.added_by ?? 'unknown'} · {new Date(entry.created_at).toLocaleString()}
                    </div>
                  </div>
                  <button
                    className="neo-button neo-button--danger"
                    onClick={() => handleDelete(entry)}
                    disabled={pendingAction !== null}
                  >
                    <Trash2 size={16} />
                    Unblock
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="neo-card">
          <div className="section-header">
            <h2 className="panel-title">WHITELIST</h2>
            <ShieldCheck size={18} className="section-icon success" />
          </div>
          {whiteEntries.length === 0 ? (
            <EmptyState title="No whitelisted IPs" hint="No trusted source IPs are currently exempted." />
          ) : (
            <div className="entries-table">
              {whiteEntries.map((entry) => (
                <div key={entry.id} className="entry-row">
                  <div>
                    <div className="entry-ip">{entryLabel(entry)}</div>
                    <div className="entry-meta">
                      {entry.description || 'No note provided'}
                    </div>
                    <div className="entry-meta muted">
                      Added by {entry.added_by ?? 'unknown'} · {new Date(entry.created_at).toLocaleString()}
                    </div>
                  </div>
                  <button
                    className="neo-button neo-button--danger"
                    onClick={() => handleDelete(entry)}
                    disabled={pendingAction !== null}
                  >
                    <Trash2 size={16} />
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}