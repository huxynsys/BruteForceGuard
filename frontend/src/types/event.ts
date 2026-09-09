export interface AuthEvent {
  id: number;
  timestamp: string;
  source: string;
  source_ip: string | null;
  username: string | null;
  result: string;
  service: string | null;
  port: number | null;
  created_at?: string;
}

export interface EventListResponse {
  events?: AuthEvent[];
  total?: number;
  [key: string]: unknown;
}
