import type { Alert } from '../types'

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

/** Triage transitions offered by the alerts work queue. */
export function canAcknowledge(status: string): boolean {
  return status === 'open' || status === 'investigating'
}

export function canResolve(status: string): boolean {
  return status !== 'resolved' && status !== 'false_positive'
}

/**
 * Marking an alert as a false positive is always a legitimate correction
 * (including on an already-resolved alert), but re-marking it is not.
 */
export function canMarkFalsePositive(status: string): boolean {
  return status !== 'false_positive'
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

