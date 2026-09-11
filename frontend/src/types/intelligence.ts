/**
 * Phase 7 - Security Intelligence types.
 *
 * Mirrors the backend Pydantic schemas for the frontend.
 */

export interface RiskFactor {
  factor: string
  value: number
  reason: string
}

export interface RiskResult {
  risk_score: number
  risk_level: string
  risk_factors: RiskFactor[]
}

export interface ThreatIntelLookup {
  indicator: string
  indicator_type: string
  known: boolean
  confidence: number | null
  categories: string[]
  threat_type: string | null
  source: string | null
}

export interface ReputationResult {
  source_ip: string
  internal_reputation_score: number
  internal_reputation_level: string
  failure_rate: number | null
  unique_usernames: number
  unique_services: number
  attack_sessions: number
  alert_count: number
  first_seen: string | null
  last_seen: string | null
}

export interface MitreContext {
  detection_type: string
  technique_id: string
  technique_name: string
  tactic: string
  description: string
  is_mapped: boolean
}

export interface ThreatIndicator {
  id: number
  indicator: string
  indicator_type: string
  confidence: number
  threat_type: string | null
  source: string
  tags: string[] | null
  active: boolean
  created_at: string
  updated_at: string
}

export interface ThreatIndicatorCreate {
  indicator: string
  indicator_type: 'ipv4' | 'ipv6' | 'domain' | 'username'
  confidence: number
  threat_type?: string
  source?: string
  tags?: string[]
  active?: boolean
}

/** Risk level from the backend (matches RISK_LEVELS). */
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational'

/** Reputation level from the backend (matches REPUTATION_LEVELS). */
export type ReputationLevel = 'hostile' | 'high' | 'suspicious' | 'low' | 'unknown'