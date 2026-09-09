export interface DashboardSummary {
  total_events: number;
  total_alerts: number;
  active_sessions: number;
  unique_source_ips: number;
  unique_usernames: number;
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  detections: Record<string, number>;
}

export interface ActivityPoint {
  time: string;
  failure: number;
  success: number;
}

export interface TopItem {
  value: string;
  count: number;
}

export interface DashboardAnalytics {
  activity: ActivityPoint[];
  top_ips: TopItem[];
  top_users: TopItem[];
  top_services: TopItem[];
}
