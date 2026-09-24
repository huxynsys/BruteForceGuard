/**
 * Label helpers. Canonical detection labels live in `types/index.ts`;
 * this module adds severity, session-type and alert-status labels.
 */

import type { AlertStatus } from '../types'

export { detectionLabel, DETECTION_LABELS } from './detectionLabels'

export const SEVERITY_LABELS: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
}

const SESSION_TYPE_LABELS: Record<string, string> = {
  single_account: 'Single Account',
  password_spray: 'Password Spray',
  distributed: 'Distributed Brute Force',
  failed_success: 'Failed -> Success',
  credential_stuffing: 'Credential Stuffing',
  low_and_slow: 'Low & Slow',
}

export function sessionTypeLabel(key: string): string {
  return SESSION_TYPE_LABELS[key] ?? key
}

/** Canonical alert triage statuses, in workflow order. */
export const ALERT_STATUSES: AlertStatus[] = [
  'open',
  'acknowledged',
  'investigating',
  'resolved',
  'false_positive',
]

const ALERT_STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

export function alertStatusLabel(status: string): string {
  return ALERT_STATUS_LABELS[status] ?? status
}

