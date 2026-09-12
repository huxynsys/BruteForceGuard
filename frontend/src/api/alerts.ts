import { api } from './client'
import type { Alert } from '../types'

export async function fetchAlerts(limit = 100): Promise<Alert[]> {
  const response = await api.get<Alert[]>('/api/v1/alerts/', {
    params: { limit },
  })
  return response.data
}

/** Fetch a single alert (with Phase 7 intelligence enrichment) by ID. */
export async function fetchAlert(alertId: number | string): Promise<Alert> {
  try {
    const response = await api.get<Alert>(`/api/v1/alerts/${alertId}`)
    return response.data
  } catch (err) {
    if (
      err &&
      typeof err === 'object' &&
      'response' in err &&
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (err as any).response?.status === 404
    ) {
      throw new Error('Alert not found')
    }
    throw err
  }
}
