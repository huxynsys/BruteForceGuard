import { api } from './client'
import type { AttackSession } from '../types'

export async function fetchSessions(
  status?: 'active' | 'closed',
): Promise<AttackSession[]> {
  const response = await api.get<AttackSession[]>('/api/v1/attack-sessions/', {
    params: status ? { status } : undefined,
  })
  return response.data
}

export async function fetchSession(id: number | string): Promise<AttackSession> {
  const response = await api.get<AttackSession>(
    `/api/v1/attack-sessions/${id}`,
  )
  return response.data
}

export async function closeSession(
  id: number | string,
): Promise<AttackSession> {
  const response = await api.post<AttackSession>(
    `/api/v1/attack-sessions/${id}/close`,
  )
  return response.data
}

export interface SessionStats {
  active_sessions: number
  total_events: number
  unique_source_ips: number
  unique_usernames: number
}

export async function fetchSessionStats(): Promise<SessionStats> {
  const response = await api.get<SessionStats>(
    '/api/v1/attack-sessions/stats/active',
  )
  return response.data
}
