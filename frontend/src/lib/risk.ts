/**
 * Phase 7 - Risk level helpers.
 *
 * Maps numeric scores to levels and provides display utilities.
 */

import type { RiskLevel, ReputationLevel } from '../types/intelligence'

/** Map a 0-100 risk score to a normalized risk level. */
export function riskLevelForScore(score: number): RiskLevel {
  const clamped = Math.max(0, Math.min(100, score))
  if (clamped >= 85) return 'critical'
  if (clamped >= 70) return 'high'
  if (clamped >= 50) return 'medium'
  if (clamped >= 25) return 'low'
  return 'informational'
}

/** Map a 0-100 reputation score to a reputation level. */
export function reputationLevelForScore(score: number): ReputationLevel {
  const clamped = Math.max(0, Math.min(100, score))
  if (clamped >= 80) return 'hostile'
  if (clamped >= 60) return 'high'
  if (clamped >= 40) return 'suspicious'
  if (clamped >= 20) return 'low'
  return 'unknown'
}

/** CSS class suffix for a risk level. */
export function riskLevelClass(level: RiskLevel | string): string {
  const known: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'informational']
  return known.includes(level as RiskLevel) ? level : 'informational'
}

/** CSS class suffix for a reputation level. */
export function reputationLevelClass(level: ReputationLevel | string): string {
  const known: ReputationLevel[] = ['hostile', 'high', 'suspicious', 'low', 'unknown']
  return known.includes(level as ReputationLevel) ? level : 'unknown'
}

/** Display label for a risk level. */
export function riskLevelLabel(level: RiskLevel | string): string {
  return level.toUpperCase()
}

/** Display label for a reputation level. */
export function reputationLevelLabel(level: ReputationLevel | string): string {
  return level.toUpperCase()
}

/** Build a visual bar string for a score (e.g., "████████░░ 80/100"). */
export function scoreBar(score: number, max = 100, length = 20): string {
  const clamped = Math.max(0, Math.min(max, score))
  const filled = Math.round((clamped / max) * length)
  const empty = length - filled
  return `${'█'.repeat(filled)}${'░'.repeat(empty)} ${clamped}/${max}`
}