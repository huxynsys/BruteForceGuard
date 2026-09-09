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

export const DETECTION_LABELS: Record<string, string> = {
  single_account_bruteforce: 'Single Account Brute Force',
  password_spray: 'Password Spray',
  distributed: 'Distributed Brute Force',
  failed_success: 'Failed -> Success',
  credential_stuffing: 'Credential Stuffing',
  low_and_slow: 'Low & Slow Attack',
}

export function detectionLabel(key: string): string {
  return DETECTION_LABELS[key] ?? key
}
