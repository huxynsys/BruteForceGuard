import type {
  Alert,
  AlertDetectionRule,
  AttackSession,
  AuthEvent,
  BlacklistEntry,
  DashboardAnalytics,
  DashboardSummary,
  EventGroup,
  EventGroupsPage,
  HealthStatus,
  ReadinessStatus,
} from '../types'
import type { ReputationResult } from '../types/intelligence'

/** Shared API fixtures for component and flow tests. */

/**
 * Detection-rule context returned with every alert (`detection_rule`).
 *
 * Mirrors `get_detection_rule("single_account_bruteforce", "ssh")` in the
 * backend, so the panel never has to carry its own threshold copy.
 */
export const detectionRuleFixture: AlertDetectionRule = {
  alert_type: 'single_account_bruteforce',
  label: 'Single Account Brute Force',
  threshold_label: 'Failed attempts against the same account',
  threshold: 5,
  secondary_label: null,
  secondary_threshold: null,
  window_seconds: 300,
  requirement:
    '5 failed authentication attempts against the same account from the same source IP within 300 seconds.',
}

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
  evidence: { failure_count: 10, window_seconds: 300 },
  created_at: '2026-09-08T10:42:00Z',
  detection_rule: detectionRuleFixture,
  // Phase 7 intelligence
  risk_score: 72,
  risk_level: 'high',
  risk_factors: [
    { factor: 'detection_severity', value: 24, reason: 'High severity detection' },
    { factor: 'confidence', value: 13, reason: 'Detection confidence 65%' },
    {
      factor: 'threat_intelligence',
      value: 15,
      reason: 'Known indicator from local (confidence 90%)',
    },
  ],
  threat_intelligence: {
    known: true,
    confidence: 90,
    categories: ['brute_force'],
    threat_type: 'brute_force',
    source: 'local',
  },
  source_reputation: {
    internal_reputation_score: 78,
    internal_reputation_level: 'high',
    failure_rate: 1.0,
    unique_usernames: 2,
    unique_services: 1,
    attack_sessions: 3,
    alert_count: 4,
    first_seen: '2026-09-08T10:31:22Z',
    last_seen: '2026-09-08T10:42:00Z',
  },
  mitre_context: {
    technique_id: 'T1110.001',
    technique_name: 'Password Guessing',
    tactic: 'Credential Access',
    description: 'Password guessing against a single account.',
    is_mapped: true,
  },
}

/** Alert where threat intelligence enrichment is entirely unavailable. */
export const noIntelAlertFixture: Alert = {
  ...alertFixture,
  id: 3,
  risk_score: 0,
  risk_level: 'informational',
  risk_factors: null,
  threat_intelligence: null,
  source_reputation: null,
  mitre_context: null,
}

/** Alert with a known-malicious indicator match. */
export const maliciousAlertFixture: Alert = {
  ...alertFixture,
  id: 4,
  risk_score: 88,
  risk_level: 'critical',
  threat_intelligence: {
    known: true,
    confidence: 95,
    categories: ['brute_force', 'scanner'],
    threat_type: 'brute_force',
    source: 'local',
  },
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
  // Phase 7 intelligence
  risk_score: 64,
  risk_level: 'medium',
  risk_factors: [
    { factor: 'detection_severity', value: 24, reason: 'High severity session' },
    { factor: 'attack_frequency', value: 8, reason: '6 failed attempts against 1 account' },
  ],
  behavioral_profile: {
    unique_source_ips: 1,
    unique_usernames: 1,
    unique_services: 1,
    detection_types: ['single_account', 'failed_success'],
    source_reputation_levels: ['high'],
  },
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
  destination_ip: '192.168.1.10',
  username: 'admin',
  result: 'failure',
  service: 'ssh',
  port: 22,
  hostname: null,
  user_agent: null,
  event_id: null,
  raw_event: { message: 'Failed password for admin from 10.0.0.10' },
  created_at: '2026-09-08T10:42:01Z',
}

/** Second event in the same source-IP group (different user + result). */
export const secondEventFixture: AuthEvent = {
  ...eventFixture,
  id: 8,
  timestamp: '2026-09-08T10:43:05Z',
  created_at: '2026-09-08T10:43:05Z',
  username: 'root',
  result: 'success',
  raw_event: { message: 'Accepted password for root from 10.0.0.10' },
}

/** Server-side grouped events payload (`GET /api/v1/events/groups`). */
export const eventGroupsFixture: EventGroupsPage = {
  items: [
    {
      group_key: '10.0.0.10',
      group_field: 'source_ip',
      event_count: 2,
      success_count: 1,
      failure_count: 1,
      usernames: ['admin', 'root'],
      services: ['ssh'],
      first_seen: '2026-09-08T10:42:01Z',
      last_seen: '2026-09-08T10:43:05Z',
      alert_types: ['single_account_bruteforce'],
      session_ids: [41],
      events: [secondEventFixture, eventFixture],
    },
  ],
  total: 1,
}

/** Empty grouped-events payload — exercises the empty state. */
export const emptyEventGroupsFixture: EventGroupsPage = {
  items: [],
  total: 0,
}

/**
 * Grouped events for `alertFixture`'s source IP, as returned by
 * `GET /api/v1/events/groups?search=192.168.1.44`.  `event_count` is the true
 * total while `events` holds the capped most-recent page, exactly like the
 * backend, so the panel's truncation note can be verified.
 */
export const alertEventGroupFixture: EventGroup = {
  group_key: '192.168.1.44',
  group_field: 'source_ip',
  event_count: 3,
  success_count: 1,
  failure_count: 2,
  usernames: ['admin'],
  services: ['ssh'],
  first_seen: '2026-09-08T10:40:00Z',
  last_seen: '2026-09-08T10:43:05Z',
  alert_types: ['single_account_bruteforce'],
  session_ids: [41],
  events: [
    { ...secondEventFixture, id: 8, source_ip: '192.168.1.44' },
    { ...eventFixture, id: 7, source_ip: '192.168.1.44' },
  ],
}

/** `GET /api/v1/intelligence/reputation/{ip}` payload. */
export const reputationFixture: ReputationResult = {
  source_ip: '192.168.1.44',
  internal_reputation_score: 78,
  internal_reputation_level: 'high',
  failure_rate: 1,
  unique_usernames: 2,
  unique_services: 1,
  attack_sessions: 3,
  alert_count: 4,
  first_seen: '2026-09-08T10:31:22Z',
  last_seen: '2026-09-08T10:42:00Z',
}

/** `POST/GET /api/v1/blacklist/` entry created by "Block Source IP". */
export const blacklistEntryFixture: BlacklistEntry = {
  id: 9,
  entry_type: 'SINGLE',
  ip_address: '192.168.1.44',
  ip_range_start: null,
  ip_range_end: null,
  region_code: null,
  description: 'Blocked from alert #1',
  created_at: '2026-09-08T11:00:00Z',
  updated_at: '2026-09-08T11:00:00Z',
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
  // Phase 7 intelligence KPIs
  critical_risk: 3,
  high_risk_alerts: 10,
  high_risk_sessions: 2,
  known_malicious_indicators: 5,
  threat_indicators: 12,
}

/** `GET /health` liveness payload. */
export const healthFixture: HealthStatus = {
  status: 'healthy',
  service: 'bruteforceguard-api',
  version: '0.5.0',
}

/** `GET /health/ready` payload when every check passes. */
export const readinessFixture: ReadinessStatus = {
  status: 'ready',
  service: 'bruteforceguard-api',
  version: '0.5.0',
  environment: 'development',
  checks: { configuration: 'ok', database: 'ok' },
}

/** `GET /health/ready` payload served with HTTP 503 when a check fails. */
export const notReadyFixture: ReadinessStatus = {
  status: 'not_ready',
  service: 'bruteforceguard-api',
  checks: { configuration: 'ok', database: 'error' },
  detail: 'database unavailable',
}

export const analyticsFixture: DashboardAnalytics = {
  activity: [
    { time: '2026-09-08T09:00', failure: 12, success: 4 },
    { time: '2026-09-08T10:00', failure: 31, success: 2 },
  ],
  top_ips: [{ value: '192.168.1.44', count: 25 }],
  top_users: [{ value: 'admin', count: 18 }],
  top_services: [{ value: 'ssh', count: 30 }],
}
