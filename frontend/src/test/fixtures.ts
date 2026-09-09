import type { Alert, AttackSession, AuthEvent, DashboardAnalytics, DashboardSummary } from '../types'

/** Shared API fixtures for component and flow tests. */

export const alertFixture: Alert = {
  id: 1,
  alert_type: 'single_account_bruteforce',
  severity: 'high',
  confidence: 65,
  title: 'Possible Single-Account Brute Force',
  description: '10 failed authentication attempts.',
  source_ip: '192.168.1.44',
  username: 'admin',
  service: 'ssh',
  mitre_technique: 'T1110.001',
  status: 'open',
  evidence: { failure_count: 10 },
  created_at: '2026-09-08T10:42:00Z',
}

export const criticalAlertFixture: Alert = {
  ...alertFixture,
  id: 2,
  alert_type: 'failed_then_success',
  severity: 'critical',
  confidence: 90,
  source_ip: '10.0.0.8',
  username: 'administrator',
}

export const sessionFixture: AttackSession = {
  id: 41,
  session_type: 'single_account',
  severity: 'high',
  status: 'active',
  event_count: 6,
  source_ips: ['192.168.1.44'],
  usernames: ['admin'],
  services: ['ssh'],
  detection_types: ['single_account', 'failed_success'],
  started_at: '2026-09-08T10:31:22Z',
  last_seen_at: '2026-09-08T10:34:18Z',
  created_at: '2026-09-08T10:31:22Z',
}

export const closedSessionFixture: AttackSession = {
  ...sessionFixture,
  id: 39,
  status: 'closed',
  session_type: 'password_spray',
}

export const eventFixture: AuthEvent = {
  id: 7,
  timestamp: '2026-09-08T10:42:01Z',
  source: 'linux',
  source_ip: '10.0.0.10',
  username: 'admin',
  result: 'failure',
  service: 'ssh',
  port: 22,
  created_at: '2026-09-08T10:42:01Z',
}

export const summaryFixture: DashboardSummary = {
  total_events: 1247,
  total_alerts: 42,
  active_sessions: 4,
  unique_source_ips: 37,
  unique_usernames: 18,
  severity: { critical: 2, high: 8, medium: 15, low: 17 },
  detections: {
    single_account: 14,
    password_spray: 9,
    distributed: 7,
    failed_success: 4,
    credential_stuffing: 5,
    low_and_slow: 3,
  },
}

export const analyticsFixture: DashboardAnalytics = {
  activity: [{ time: '2026-09-08T10:00', failure: 12, success: 4 }],
  top_ips: [{ value: '192.168.1.44', count: 25 }],
  top_users: [{ value: 'admin', count: 18 }],
  top_services: [{ value: 'ssh', count: 30 }],
}
