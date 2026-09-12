export interface AuthEvent {
  id: number
  timestamp: string
  source: string
  source_ip: string | null
  username: string | null
  result: 'success' | 'failure' | string
  service: string | null
  port: number | null
  created_at: string
}

export interface AlertRiskFactor {
  factor: string
  value: number
  reason: string
}

/** Phase 7 threat-intelligence payload persisted on an alert. */
export interface AlertThreatIntel {
  known: boolean
  confidence: number | null
  categories: string[] | null
  threat_type: string | null
  source: string | null
}

/** Phase 7 source-reputation payload persisted on an alert. */
export interface AlertReputation {
  internal_reputation_score: number
  internal_reputation_level: string
  failure_rate: number | null
  unique_usernames: number
  unique_services: number
  attack_sessions: number
  alert_count: number
  first_seen?: string | null
  last_seen?: string | null
}

/** Phase 7 MITRE ATT&CK context persisted on an alert. */
export interface AlertMitreContext {
  technique_id: string
  technique_name: string
  tactic: string
  description: string
  is_mapped: boolean
}

export interface Alert {
  id: number
  alert_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | string
  confidence: number
  title: string
  description: string
  source_ip: string | null
  username: string | null
  service: string | null
  mitre_technique: string | null
  status: string
  evidence: Record<string, unknown>
  created_at: string
  // Phase 7 intelligence enrichment
  risk_score: number
  risk_level: string
  risk_factors: AlertRiskFactor[] | null
  threat_intelligence: AlertThreatIntel | null
  source_reputation: AlertReputation | null
  mitre_context: AlertMitreContext | null
}

/** Phase 7 behavioral profile persisted on an attack session. */
export interface BehavioralProfile {
  unique_source_ips: number
  unique_usernames: number
  unique_services: number
  detection_types: string[]
  source_reputation_levels: string[]
}

export interface AttackSession {
  id: number
  session_type: string
  severity: string
  status: 'active' | 'closed' | string
  event_count: number
  source_ips: string[]
  usernames: string[]
  services: string[]
  detection_types: string[]
  started_at: string
  last_seen_at: string
  created_at: string
  // Phase 7 intelligence enrichment
  risk_score: number
  risk_level: string
  risk_factors: AlertRiskFactor[] | null
  behavioral_profile: BehavioralProfile | null
}

export interface DashboardSummary {
  total_events: number
  total_alerts: number
  active_sessions: number
  unique_source_ips: number
  unique_usernames: number
  severity: {
    critical: number
    high: number
    medium: number
    low: number
  }
  detections: Record<string, number>
  // Phase 7 intelligence KPIs (backend-computed)
  critical_risk: number
  high_risk_alerts: number
  high_risk_sessions: number
  known_malicious_indicators: number
  threat_indicators: number
}

export interface ActivityBucket {
  time: string
  failure: number
  success: number
}

export interface TopItem {
  value: string
  count: number
}

export interface DashboardAnalytics {
  activity: ActivityBucket[]
  top_ips: TopItem[]
  top_users: TopItem[]
  top_services: TopItem[]
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export { detectionLabel, DETECTION_LABELS } from '../lib/detectionLabels'
