/**
 * Security audit log domain helpers.
 *
 * Mirrors the backend vocabulary in `app/models/audit_log.py` (keep both in
 * sync): the action/result enums, their human labels and a renderer for the
 * sanitized `detail` payload. Nothing here interprets or re-derives the
 * evidence - it only presents what the server recorded.
 */

import type { AuditAction, AuditLogEntry, AuditResult } from '../types'

/** Canonical actions, in the order they appear in the filter dropdown. */
export const AUDIT_ACTIONS: AuditAction[] = [
  'alert.status_change',
  'ip.blocklist.add',
  'ip.blocklist.remove',
  'ip.whitelist.add',
  'ip.whitelist.remove',
  'auth.failed',
  'auth.login',
  'auth.logout',
  'settings.change',
  'role.change',
]

const AUDIT_ACTION_LABELS: Record<string, string> = {
  'alert.status_change': 'Alert status change',
  'ip.blocklist.add': 'IP blocked',
  'ip.blocklist.remove': 'IP unblocked',
  'ip.whitelist.add': 'IP whitelisted',
  'ip.whitelist.remove': 'IP removed from whitelist',
  'auth.failed': 'Authentication failed',
  'auth.login': 'Login',
  'auth.logout': 'Logout',
  'settings.change': 'Settings change',
  'role.change': 'Role change',
}

/** Human label for an action code (falls back to the raw code). */
export function auditActionLabel(action: string): string {
  return AUDIT_ACTION_LABELS[action] ?? action
}

/** Canonical results, in the order they appear in the filter dropdown. */
export const AUDIT_RESULTS: AuditResult[] = ['success', 'failure', 'denied']

/** Human label for a result code. */
export function auditResultLabel(result: string): string {
  if (result === 'success') return 'Success'
  if (result === 'failure') return 'Failure'
  if (result === 'denied') return 'Denied'
  return result
}

/**
 * Badge CSS modifier for a result. Success reads as healthy, a failure as a
 * problem and a denial as a policy decision (warning colour) - the result is
 * always rendered as text too, so colour is never the only signal.
 */
export function auditResultClass(result: string): string {
  if (result === 'success') return 'badge-success'
  if (result === 'denied') return 'badge-medium'
  return 'badge-high'
}

/**
 * One-line description of the target an entry acted upon.
 *
 * Uses the recorded `target_type` / `target_id` (and `detail.value` for IP
 * list entries) - never invented data.
 */
export function auditTargetLabel(entry: AuditLogEntry): string {
  if (!entry.target_type && !entry.target_id) return '—'

  const type = entry.target_type ?? 'target'
  const id = entry.target_id ?? '—'

  if (entry.target_type === 'alert') return `Alert #${id}`
  if (entry.target_type === 'blacklist_entry') {
    const value = typeof entry.detail?.value === 'string' ? entry.detail.value : null
    return value ? `${type} ${value}` : `${type} #${id}`
  }
  if (entry.target_type === 'endpoint') return String(id)

  return `${type} #${id}`
}

/**
 * Flatten the sanitized `detail` payload for display.
 *
 * Values are stringified, not re-interpreted, so `[REDACTED]` markers and any
 * other server-side sanitization stay visible to the reader. `null`/empty
 * payloads render as an em dash.
 */
export function auditDetailSummary(entry: AuditLogEntry): string {
  const detail = entry.detail
  if (!detail || Object.keys(detail).length === 0) return '—'

  return Object.entries(detail)
    .filter(([, value]) => value !== null && value !== undefined && value !== '')
    .map(([key, value]) => {
      const rendered =
        typeof value === 'object' ? JSON.stringify(value) : String(value)
      return `${key}=${rendered}`
    })
    .join(' · ')
}
