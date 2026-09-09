import { api } from './client'
import type { DashboardAnalytics, DashboardSummary } from '../types'

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

export interface HealthStatus {
  status: string
  service: string
  version: string
}

export async function fetchHealth(): Promise<HealthStatus> {
  const response = await api.get<HealthStatus>('/health')
  return response.data
}
