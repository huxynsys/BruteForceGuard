import axios from 'axios'
import { api } from './client'
import type {
  DashboardAnalytics,
  DashboardSummary,
  HealthStatus,
  ReadinessStatus,
} from '../types'

export async function fetchSummary(): Promise<DashboardSummary> {
  const response = await api.get<DashboardSummary>('/api/v1/dashboard/summary')
  return response.data
}

export async function fetchAnalytics(): Promise<DashboardAnalytics> {
  const response = await api.get<DashboardAnalytics>(
    '/api/v1/dashboard/analytics',
  )
  return response.data
}

/** Liveness probe: the API process is up (no database access). */
export async function fetchHealth(): Promise<HealthStatus> {
  const response = await api.get<HealthStatus>('/health')
  return response.data
}

/**
 * Readiness probe: configuration + database.
 *
 * A 503 is a real answer (`not_ready`) rather than a transport failure, so
 * the body is returned instead of thrown away - the System health panel has
 * to show *which* check failed. Only genuine transport/parse errors throw.
 */
export async function fetchReadiness(): Promise<ReadinessStatus> {
  try {
    const response = await api.get<ReadinessStatus>('/health/ready')
    return response.data
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.data) {
      return err.response.data as ReadinessStatus
    }
    throw err
  }
}
