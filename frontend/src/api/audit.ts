import { api } from './client'
import type { AuditLogPage, AuditResult } from '../types'

/**
 * Security audit log API client (read-only).
 *
 *   GET /api/v1/audit/   newest-first, server-side filtered + paginated
 *
 * The table is append-only evidence: there is no create/update/delete
 * endpoint. Reads require an admin-role token from `ALERT_TRIAGE_API_TOKENS`
 * (the request interceptor in `client.ts` attaches it for `/api/v1/audit/`).
 */

/** Query accepted by `GET /api/v1/audit/`; empty values are omitted. */
export interface AuditQuery {
  skip?: number
  limit?: number
  /** Exact action, e.g. `alert.status_change` (see `AuditAction`). */
  action?: string
  /** Exact actor identity from the `X-User-Id` header. */
  user?: string
  result?: AuditResult | ''
  /** Inclusive ISO 8601 lower bound on `created_at`. */
  since?: string
  /** Inclusive ISO 8601 upper bound on `created_at`. */
  until?: string
}

function queryParams(query: AuditQuery): Record<string, string | number> {
  const params: Record<string, string | number> = {}

  if (query.skip !== undefined) params.skip = query.skip
  if (query.limit !== undefined) params.limit = query.limit

  const action = query.action?.trim()
  if (action) params.action = action

  const user = query.user?.trim()
  if (user) params.user = user

  if (query.result) params.result = query.result
  if (query.since) params.since = query.since
  if (query.until) params.until = query.until

  return params
}

/**
 * Fetch one page of the immutable audit log.
 *
 * Authentication failures are turned into actionable messages: the backend
 * answers 401/403 when the caller lacks (or the deployment has not
 * configured) the admin triage token, and 503 when no triage tokens exist at
 * all - states an operator can fix, unlike a generic request error.
 */
export async function fetchAuditLog(
  query: AuditQuery = {},
): Promise<AuditLogPage> {
  try {
    const response = await api.get<AuditLogPage>('/api/v1/audit/', {
      params: queryParams(query),
    })
    return response.data
  } catch (err) {
    const status =
      err && typeof err === 'object' && 'response' in err
        ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (err as any).response?.status
        : undefined

    if (status === 401 || status === 403) {
      throw new Error(
        'Reading the audit log requires the admin role. Configure VITE_ALERT_TRIAGE_TOKEN with an admin token (ALERT_TRIAGE_API_TOKENS on the server).',
        { cause: err },
      )
    }
    if (status === 503) {
      throw new Error(
        'The audit log API is not configured on the server (ALERT_TRIAGE_API_TOKENS is unset).',
        { cause: err },
      )
    }
    throw err
  }
}
