import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Link } from 'react-router-dom'

import {
  auditActionLabel,
  auditDetailSummary,
  auditResultClass,
  auditResultLabel,
  auditTargetLabel,
} from '../../lib/audit'
import { formatDateTime } from '../../lib/format'
import type { AuditLogEntry } from '../../types'

/** Number of columns in the collapsed row (the expanded row spans them all). */
const COLUMN_COUNT = 8

/**
 * Security audit log table.
 *
 * One collapsed row per entry (time, action, actor, role, target, result,
 * source IP, detail summary) plus an expandable panel showing the sanitized
 * `detail` payload verbatim and the recorded note. Alert targets link through
 * to the investigation page; nothing is inferred — every cell renders the
 * stored evidence, including `[REDACTED]` markers left by the server.
 */
export default function AuditLogTable({
  entries,
}: {
  entries: AuditLogEntry[]
}) {
  const [expandedId, setExpandedId] = useState<number | null>(null)

  const toggleRow = (id: number) => {
    setExpandedId((current) => (current === id ? null : id))
  }

  return (
    <div className="table-wrap">
      <table className="data" aria-label="Security audit log entries">
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Action</th>
            <th scope="col">Actor</th>
            <th scope="col">Role</th>
            <th scope="col">Target</th>
            <th scope="col">Result</th>
            <th scope="col">Source IP</th>
            <th scope="col">Details</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => {
            const expanded = expandedId === entry.id

            return (
              <Fragment key={entry.id}>
                <tr>
                  <td className="mono">{formatDateTime(entry.created_at)}</td>
                  <td>
                    <button
                      type="button"
                      className="event-group__toggle"
                      aria-expanded={expanded}
                      aria-controls={`audit-detail-${entry.id}`}
                      onClick={() => toggleRow(entry.id)}
                    >
                      {expanded ? (
                        <ChevronDown size={15} aria-hidden="true" />
                      ) : (
                        <ChevronRight size={15} aria-hidden="true" />
                      )}
                      <span>{auditActionLabel(entry.action)}</span>
                    </button>
                    <div className="entry-meta muted mono">{entry.action}</div>
                  </td>
                  <td>{entry.actor}</td>
                  <td>
                    {entry.actor_role ? (
                      <span className="badge badge-muted">
                        {entry.actor_role}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td>
                    {entry.target_type === 'alert' && entry.target_id ? (
                      <Link to={`/alerts/${entry.target_id}`}>
                        {auditTargetLabel(entry)}
                      </Link>
                    ) : (
                      <span className="mono">{auditTargetLabel(entry)}</span>
                    )}
                  </td>
                  <td>
                    <span
                      className={`badge ${auditResultClass(entry.result)}`}
                      data-result={entry.result}
                    >
                      {auditResultLabel(entry.result)}
                    </span>
                  </td>
                  <td className="mono">{entry.source_ip ?? '—'}</td>
                  <td>
                    <span className="mono">{auditDetailSummary(entry)}</span>
                  </td>
                </tr>

                {expanded && (
                  <tr id={`audit-detail-${entry.id}`}>
                    <td colSpan={COLUMN_COUNT} className="event-detail-cell">
                      <div className="event-detail">
                        <div className="group-context">
                          <span>
                            <b>Entry</b>
                            <span className="mono">#{entry.id}</span>
                          </span>
                          <span>
                            <b>Recorded</b>
                            <span className="mono">
                              {formatDateTime(entry.created_at)}
                            </span>
                          </span>
                          <span>
                            <b>Target</b>
                            <span className="mono">
                              {entry.target_type ?? '—'}
                              {entry.target_id ? ` / ${entry.target_id}` : ''}
                            </span>
                          </span>
                          <span>
                            <b>Result</b>
                            <span className="mono">
                              {auditResultLabel(entry.result)}
                            </span>
                          </span>
                          <span>
                            <b>Actor</b>
                            <span className="mono">
                              {entry.actor}
                              {entry.actor_role ? ` (${entry.actor_role})` : ''}
                            </span>
                          </span>
                        </div>

                        {entry.note && (
                          <div className="group-context">
                            <span>
                              <b>Note</b>
                              <span>{entry.note}</span>
                            </span>
                          </div>
                        )}

                        <details className="raw-details" open>
                          <summary>Recorded detail (sanitized server-side)</summary>
                          <pre>
                            {entry.detail && Object.keys(entry.detail).length > 0
                              ? JSON.stringify(entry.detail, null, 2)
                              : 'No structured detail was recorded for this entry.'}
                          </pre>
                        </details>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
