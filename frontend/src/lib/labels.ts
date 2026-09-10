/**
 * Label helpers. Canonical detection labels live in `types/index.ts`;
 * this module adds severity and session-type labels.
 */

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

