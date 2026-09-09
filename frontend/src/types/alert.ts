export type Severity = "critical" | "high" | "medium" | "low";

export interface Alert {
  id: number;
  alert_type: string;
  severity: Severity | string;
  confidence: number;
  title: string;
  description: string;
  source_ip: string | null;
  username: string | null;
  service: string | null;
  mitre_technique?: string | null;
  evidence?: Record<string, unknown>;
  status: string;
  created_at?: string;
}
