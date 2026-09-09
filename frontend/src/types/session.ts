export interface AttackSession {
  id: number;
  session_type: string;
  severity: string;
  status: "active" | "closed" | string;
  event_count: number;
  started_at: string;
  last_seen_at: string | null;
  source_ips: string[];
  usernames: string[];
  services: string[];
  detection_types: string[];
  created_at?: string;
}

export interface SessionStats {
  active_sessions: number;
  total_events: number;
  unique_source_ips: number;
  unique_usernames: number;
}
