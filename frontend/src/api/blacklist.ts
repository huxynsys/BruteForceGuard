import { api } from './client'
import type { BlacklistEntry, BlacklistEntryCreate } from '../types'

export async function deleteBlacklistEntry(
  entryId: number,
): Promise<BlacklistEntry> {
  const response = await api.delete<BlacklistEntry>(`/api/v1/blacklist/${entryId}`)
  return response.data
}

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
  listType?: 'BLOCKLIST' | 'WHITELIST',
): Promise<BlacklistEntry[]> {
  const response = await api.get<BlacklistEntry[]>('/api/v1/blacklist/', {
    params: listType ? { limit, list_type: listType } : { limit },
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
  options?: { listType?: 'BLOCKLIST' | 'WHITELIST'; addedBy?: string },
): Promise<BlacklistEntry> {
  const payload: BlacklistEntryCreate = {
    entry_type: 'SINGLE',
    ip_address: ipAddress,
  }

  if (options?.listType) {
    payload.list_type = options.listType
  }

  const trimmed = description?.trim()
  if (trimmed) payload.description = trimmed

  if (options?.addedBy?.trim()) payload.added_by = options.addedBy.trim()

  const response = await api.post<BlacklistEntry>('/api/v1/blacklist/', payload)
  return response.data
}
