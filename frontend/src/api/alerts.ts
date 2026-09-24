import { api } from './client'
import type { Alert, AlertStats, AlertStatus } from '../types'

/**
 * Alerts API client.
 *
 * The alerts page is the authoritative detailed view, so it uses:
 *   GET   /api/v1/alerts/       filtered + paginated rows
 *   GET   /api/v1/alerts/stats  matching total + facet counts
 *   PATCH /api/v1/alerts/{id}   persisted triage transition
 */

/** Filters accepted by the alerts API (combined with AND). */
export interface AlertFilters {
  severity?: string
  status?: AlertStatus | string
  alertType?: string
  search?: string
}

export interface AlertQuery extends AlertFilters {
  skip?: number
  limit?: number
}

/** One page of alerts plus the facet counts for the same filters. */
export interface AlertPage {
  items: Alert[]
  total: number
  stats: AlertStats
}

function filterParams(filters: AlertFilters): Record<string, string> {
  const params: Record<string, string> = {}

  if (filters.severity) params.severity = filters.severity
  if (filters.status) params.status = String(filters.status)
  if (filters.alertType) params.alert_type = filters.alertType

  const search = filters.search?.trim()
  if (search) params.search = search

  return params
}

function pageParams(query: AlertQuery): Record<string, string | number> {
  const params: Record<string, string | number> = filterParams(query)

  if (query.skip !== undefined) params.skip = query.skip
  if (query.limit !== undefined) params.limit = query.limit

  return params
}

/** Recent alerts as a plain list (used by the dashboard overview). */
export async function fetchAlerts(limit = 100): Promise<Alert[]> {
  const response = await api.get<Alert[]>('/api/v1/alerts/', {
    params: { limit },
  })
  return response.data
}

/**
 * Filtered, paginated alerts for the work queue.
 *
 * The list endpoint supplies the rows while `/stats` supplies the matching
 * total (pagination) and the facet counts used for the filter options; both
 * are queried in parallel with the same filters.
 */
export async function fetchAlertsPage(
  query: AlertQuery = {},
): Promise<AlertPage> {
  const [list, stats] = await Promise.all([
    api.get<Alert[]>('/api/v1/alerts/', { params: pageParams(query) }),
    api.get<AlertStats>('/api/v1/alerts/stats', {
      params: filterParams(query),
    }),
  ])

  return { items: list.data, total: stats.data.total, stats: stats.data }
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
      throw new Error('Alert not found', { cause: err })
    }
    throw err
  }
}

/**
 * Persist an analyst triage transition.
 *
 * The backend validates the status, stores it and returns the updated alert,
 * so callers can refresh from the server instead of faking local state.
 */
export async function updateAlertStatus(
  alertId: number | string,
  status: AlertStatus,
): Promise<Alert> {
  const response = await api.patch<Alert>(`/api/v1/alerts/${alertId}`, {
    status,
  })
  return response.data
}
