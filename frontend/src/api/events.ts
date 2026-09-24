import { api } from './client'
import type { AuthEvent, EventGroupsPage } from '../types'

export async function fetchEvents(limit = 100): Promise<AuthEvent[]> {
  const response = await api.get<AuthEvent[]>('/api/v1/events/', {
    params: { limit },
  })
  return response.data
}

export type EventGroupSort = 'recent' | 'events' | 'ip'

export interface EventGroupsParams {
  search?: string
  result?: 'all' | 'success' | 'failure'
  sort?: EventGroupSort
  skip?: number
  limit?: number
  events_limit?: number
}

/**
 * Server-side grouped events (grouped by source IP on the backend, with
 * real alert-derived detection/session context).  Pagination, search and
 * sorting all happen server-side so the browser never loads an unbounded
 * raw event list.
 */
export async function fetchEventGroups(
  params: EventGroupsParams = {},
): Promise<EventGroupsPage> {
  const response = await api.get<EventGroupsPage>(
    '/api/v1/events/groups',
    { params },
  )
  return response.data
}
