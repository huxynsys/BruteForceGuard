import type { Alert, AlertStatus } from '../types'

/**
 * Number of failed authentication attempts recorded as detection evidence.
 *
 * Detectors store this as `failure_count`; the failed-then-success detector
 * uses `failed_attempts`. Missing or unparseable evidence returns null so the
 * table can show a placeholder instead of a fabricated zero.
 */
export function failedAttempts(alert: Alert): number | null {
  const evidence = alert.evidence ?? {}
  const raw = evidence.failure_count ?? evidence.failed_attempts

  if (typeof raw === 'number' && Number.isFinite(raw)) return raw

  if (typeof raw === 'string' && raw.trim() !== '') {
    const parsed = Number(raw)
    if (Number.isFinite(parsed)) return parsed
  }

  return null
}

/**
 * Alert triage lifecycle - a mirror of the backend state machine in
 * `backend/app/services/alert_lifecycle.py` (keep both in sync).
 *
 * The browser only *offers* what the server will accept; the backend still
 * validates every PATCH, so a stale or hand-crafted request can never apply
 * an arbitrary state change.
 */
export type TriageRole = 'analyst' | 'admin'

/** Closed (terminal, but reclassifiable) statuses. */
export const CLOSED_STATUSES: readonly string[] = ['resolved', 'false_positive']

/** Active statuses an alert can be reopened into. */
export const ACTIVE_STATUSES: readonly string[] = [
  'open',
  'acknowledged',
  'investigating',
]

/** Canonical lifecycle order (drives stable action lists and legends). */
export const LIFECYCLE_ORDER: readonly AlertStatus[] = [
  'open',
  'acknowledged',
  'investigating',
  'resolved',
  'false_positive',
]

/**
 * Allowed targets for each status. A status is never its own successor, so
 * a no-op "transition" is rejected instead of silently recorded.
 */
export const VALID_TRANSITIONS: Record<AlertStatus, readonly AlertStatus[]> = {
  open: ['acknowledged', 'investigating', 'resolved', 'false_positive'],
  acknowledged: ['open', 'investigating', 'resolved', 'false_positive'],
  investigating: ['open', 'acknowledged', 'resolved', 'false_positive'],
  resolved: ['open', 'acknowledged', 'investigating', 'false_positive'],
  false_positive: ['open', 'acknowledged', 'investigating', 'resolved'],
}

/** Reopening a closed alert back into an active state is admin-only. */
export function requiresAdminTransition(from: string, to: string): boolean {
  return CLOSED_STATUSES.includes(from) && ACTIVE_STATUSES.includes(to)
}

/** Whether `status` is a closed (terminal, reclassifiable) lifecycle state. */
export function isClosedStatus(status: string): boolean {
  return CLOSED_STATUSES.includes(status)
}

/** Statuses `from` may move to (empty for unknown statuses). */
export function availableTransitions(from: string): AlertStatus[] {
  return [...(VALID_TRANSITIONS[from as AlertStatus] ?? [])]
}

/**
 * Whether `role` may perform `from -> to`.
 *
 * Unknown statuses and self-transitions are never allowed; reopens are
 * allowed for admins only.
 */
export function canTransition(
  from: string,
  to: string,
  role: TriageRole = 'analyst',
): boolean {
  if (!availableTransitions(from).includes(to as AlertStatus)) return false
  if (requiresAdminTransition(from, to)) return role === 'admin'
  return true
}

/**
 * Button label for a transition. Distinct per target so every action in the
 * panel is uniquely addressable; closed alerts "Reopen" while active ones
 * step "Back to Open".
 */
export function transitionLabel(from: string, to: AlertStatus): string {
  if (to === 'acknowledged') return 'Acknowledge'
  if (to === 'investigating') return 'Investigate'
  if (to === 'resolved') return 'Resolve'
  if (to === 'false_positive') return 'Mark False Positive'
  // to === 'open'
  return CLOSED_STATUSES.includes(from) ? 'Reopen' : 'Back to Open'
}

/**
 * Whether the recorded detection evidence reached the rule's threshold.
 *
 * Returns `null` when either number is unknown so the UI states "unknown"
 * rather than claiming a threshold was met (or missed) it cannot prove.
 */
export function thresholdReached(
  observed: number | null,
  threshold: number | null | undefined,
): boolean | null {
  if (observed === null || threshold === null || threshold === undefined) {
    return null
  }
  return observed >= threshold
}

