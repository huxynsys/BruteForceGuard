import { useMemo, useState, type FormEvent } from 'react'
import { AlertTriangle, Check, Plus, ShieldAlert, ShieldCheck, Trash2, X } from 'lucide-react'

import { blockIpAddress, deleteBlacklistEntry, fetchBlacklistEntries } from '../api/blacklist'
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States'
import { useApi, POLL_INTERVAL } from '../hooks/useApi'
import type { BlacklistEntry } from '../types'

type ListType = 'BLOCKLIST' | 'WHITELIST'
type ConfirmationTarget = BlacklistEntry | null

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
  const [notice, setNotice] = useState<string | null>(null)
  const [confirmationTarget, setConfirmationTarget] = useState<ConfirmationTarget>(null)

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

    setPendingAction(form.listType === 'BLOCKLIST' ? 'block' : 'whitelist')
    setError(null)
    setNotice(null)

    try {
      await blockIpAddress(ipAddress, form.description, {
        listType: form.listType,
      })
      setForm(EMPTY_FORM)
      refreshLists()
      setNotice(`${ipAddress} added to the ${form.listType.toLowerCase()}.`)
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
    setPendingAction(action)
    setError(null)
    setNotice(null)

    try {
      await deleteBlacklistEntry(entry.id)
      refreshLists()
      setNotice(`${entryLabel(entry)} removed from the ${entry.list_type.toLowerCase()}.`)
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'The management entry could not be removed.',
      )
    } finally {
      setPendingAction(null)
    }
  }

  const requestDelete = (entry: BlacklistEntry) => setConfirmationTarget(entry)

  if (blocklist.loading && !blocklist.data) {
    return <LoadingState label="Loading IP management entries..." />
  }

  if (blocklist.error && !blocklist.data) {
    return <ErrorState message={blocklist.error} onRetry={refreshLists} />
  }

  return (
    <div className="page-shell">
      <header className="page-header ip-page-header">
        <div>
          <p className="eyebrow">Threat Operations</p>
          <h1>IP Management</h1>
          <p className="page-header-copy">
            Control which sources can reach protected services. Changes are audited and enforced server-side.
          </p>
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

      <section className="neo-card ip-form-panel" aria-labelledby="add-ip-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">New control</p>
            <h2 className="panel-title" id="add-ip-title">Add an IP rule</h2>
          </div>
          <span className="form-hint">IPv4 and IPv6 supported</span>
        </div>
        <form className="ip-form" onSubmit={handleSubmit}>
          <div className="field-row">
            <label>
              <span>IP address <b aria-hidden="true">*</b></span>
              <input
                id="managed-ip-address"
                className="neo-input"
                name="ipAddress"
                autoComplete="off"
                required
                value={form.ipAddress}
                onChange={(event) => setForm((current) => ({ ...current, ipAddress: event.target.value }))}
                placeholder="203.0.113.10"
              />
            </label>

            <label>
              <span>List</span>
              <select
                id="managed-ip-list"
                className="neo-input"
                name="listType"
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
              id="managed-ip-reason"
              className="neo-input"
              name="description"
              maxLength={500}
              value={form.description}
              onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
              placeholder="Repeated brute-force traffic"
            />
          </label>

          <div className="action-row">
            <button className="toolbar-button toolbar-button--primary" type="submit" disabled={pendingAction !== null}>
              <Plus size={16} />
              {pendingAction === 'block' || pendingAction === 'whitelist'
                ? 'Saving...'
                : form.listType === 'BLOCKLIST'
                  ? 'Block IP'
                  : 'Whitelist IP'}
            </button>
          </div>
        </form>

        {error && <div className="inline-feedback inline-feedback--error" role="alert"><AlertTriangle size={15} />{error}</div>}
        {notice && <div className="inline-feedback inline-feedback--success" role="status"><Check size={15} />{notice}</div>}
      </section>

      <div className="list-grid">
        <section className="neo-card managed-list" aria-labelledby="blocklist-title">
          <div className="section-header">
            <div>
              <p className="eyebrow">Access control</p>
              <h2 className="panel-title" id="blocklist-title">Blocklist</h2>
            </div>
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
                    onClick={() => requestDelete(entry)}
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

        <section className="neo-card managed-list" aria-labelledby="whitelist-title">
          <div className="section-header">
            <div>
              <p className="eyebrow">Trusted sources</p>
              <h2 className="panel-title" id="whitelist-title">Whitelist</h2>
            </div>
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
                    onClick={() => requestDelete(entry)}
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

      {confirmationTarget && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setConfirmationTarget(null)}>
          <section
            className="confirmation-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <button className="modal-close" type="button" aria-label="Close confirmation" onClick={() => setConfirmationTarget(null)}>
              <X size={17} />
            </button>
            <div className="modal-icon"><AlertTriangle size={20} /></div>
            <p className="eyebrow">Destructive action</p>
            <h2 id="confirm-title">
              {confirmationTarget.list_type === 'BLOCKLIST' ? 'Unblock this IP?' : 'Remove this trusted IP?'}
            </h2>
            <p>
              <span className="mono">{entryLabel(confirmationTarget)}</span> will be removed from the {confirmationTarget.list_type.toLowerCase()}.
              This takes effect after the server confirms the change.
            </p>
            <div className="modal-actions">
              <button className="toolbar-button" type="button" onClick={() => setConfirmationTarget(null)}>Cancel</button>
              <button
                className="toolbar-button toolbar-button--danger"
                type="button"
                onClick={() => {
                  const entry = confirmationTarget
                  setConfirmationTarget(null)
                  void handleDelete(entry)
                }}
              >
                <Trash2 size={15} />
                {confirmationTarget.list_type === 'BLOCKLIST' ? 'Unblock IP' : 'Remove from whitelist'}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}