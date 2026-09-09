import { api } from './client'
import type { AuthEvent } from '../types'

export async function fetchEvents(limit = 100): Promise<AuthEvent[]> {
  const response = await api.get<AuthEvent[]>('/api/v1/events/', {
    params: { limit },
  })
  return response.data
}
