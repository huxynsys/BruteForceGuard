import { api } from './client'
import type { Alert } from '../types'

export async function fetchAlerts(limit = 100): Promise<Alert[]> {
  const response = await api.get<Alert[]>('/api/v1/alerts/', {
    params: { limit },
  })
  return response.data
}
