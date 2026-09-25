import { api } from './client'
import type { BlacklistEntry, BlacklistEntryCreate } from '../types'

/**
 * Blacklist API client (existing endpoints):
 *
 *   GET  /api/v1/blacklist/   list stored entries
 *   POST /api/v1/blacklist/   block an entry (used for "Block Source IP")
 *
 * The backend validates and persists the entry, so callers refresh from the
 * server instead of keeping local state.
 */

/** List blacklist entries (newest bounded by `limit`, max 100 server-side). */
export async function fetchBlacklistEntries(
  limit = 100,
): Promise<BlacklistEntry[]> {
  const response = await api.get<BlacklistEntry[]>('/api/v1/blacklist/', {
    params: { limit },
  })
  return response.data
}

/**
 * Block a single source IP address.
 *
 * The backend stores it as a `SINGLE` entry; its middleware then rejects
 * requests from that address, so the UI asks for confirmation first.
 */
export async function blockIpAddress(
  ipAddress: string,
  description?: string,
): Promise<BlacklistEntry> {
  const payload: BlacklistEntryCreate = {
    entry_type: 'SINGLE',
    ip_address: ipAddress,
  }

  const trimmed = description?.trim()
  if (trimmed) payload.description = trimmed

  const response = await api.post<BlacklistEntry>('/api/v1/blacklist/', payload)
  return response.data
}
