import axios from 'axios'

// API base URL resolution (Phase 9.3).
//
// The dashboard always calls paths that already include the API prefix
// (e.g. "/api/v1/events/"), so the base URL only decides which *origin*
// serves them:
//
//   * VITE_API_BASE_URL set (including empty) -> used verbatim
//       - empty  -> same origin: requests hit the reverse proxy, which
//         forwards /api/... to FastAPI
//       - origin -> absolute API origin, e.g. https://bfg.example.com
//   * VITE_API_BASE_URL unset:
//       - development -> http://localhost:8000 (the Vite dev server runs on
//         :5173 and talks to the backend directly)
//       - production  -> '' (same origin, served behind the reverse proxy)
export interface ApiEnv {
  VITE_API_BASE_URL?: string
  DEV?: boolean
}

export function resolveApiBaseUrl(env: ApiEnv): string {
  return env.VITE_API_BASE_URL ?? (env.DEV ? 'http://localhost:8000' : '')
}

export const API_BASE_URL: string = resolveApiBaseUrl(import.meta.env)

const IP_MANAGEMENT_TOKEN = import.meta.env.VITE_IP_MANAGEMENT_TOKEN
const IP_MANAGEMENT_USER = import.meta.env.VITE_IP_MANAGEMENT_USER ?? 'frontend'

// Alert triage writes (PATCH /api/v1/alerts/{id}) authenticate with their own
// token, which is bound to an analyst/admin role server-side via
// ALERT_TRIAGE_API_TOKENS. VITE_ALERT_TRIAGE_ROLE only drives which
// admin-only actions the UI offers - the backend never trusts it.
const TRIAGE_TOKEN = import.meta.env.VITE_ALERT_TRIAGE_TOKEN
const TRIAGE_USER = import.meta.env.VITE_ALERT_TRIAGE_USER ?? 'frontend'

/** Role the UI may offer admin-only lifecycle actions for (see above). */
export const TRIAGE_ROLE: 'analyst' | 'admin' =
  import.meta.env.VITE_ALERT_TRIAGE_ROLE === 'admin' ? 'admin' : 'analyst'

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10_000,
  headers: { 'Content-Type': 'application/json' },
})

/** Credentials attached to one request; `null` when no token is configured. */
export interface RequestCredentials {
  token: string
  user: string
}

/** Environment-backed credential pairs for the two endpoint groups. */
export interface AuthEnv {
  /** Guards IP-management writes (`VITE_IP_MANAGEMENT_TOKEN`). */
  ipManagementToken?: string
  ipManagementUser?: string
  /** Role-bound token for alert triage and audit reads (`VITE_ALERT_TRIAGE_TOKEN`). */
  triageToken?: string
  triageUser?: string
}

/**
 * Whether a request is served by the role-gated token
 * (`ALERT_TRIAGE_API_TOKENS` server-side).
 *
 * Triage writes (`PATCH /api/v1/alerts/{id}`) and audit reads
 * (`GET /api/v1/audit/`, admin-only) both resolve the caller's role from the
 * token itself, so they must not receive the IP-management credential.
 */
export function isRoleGatedRequest(method: string, url: string): boolean {
  const verb = method.toLowerCase()
  return (
    (verb === 'patch' && url.includes('/api/v1/alerts/')) ||
    (verb === 'get' && url.includes('/api/v1/audit/'))
  )
}

/**
 * Select the credentials for one request (pure - unit-tested below).
 *
 * Falls back to whichever single token is configured, so a deployment that
 * sets only one of the two tokens still authenticates both groups.
 */
export function selectAuthCredentials(
  method: string,
  url: string,
  env: AuthEnv,
): RequestCredentials | null {
  const roleGated = isRoleGatedRequest(method, url)

  const token = roleGated
    ? (env.triageToken ?? env.ipManagementToken)
    : (env.ipManagementToken ?? env.triageToken)
  if (!token) return null

  const user = roleGated
    ? (env.triageUser ?? env.ipManagementUser ?? 'frontend')
    : (env.ipManagementUser ?? env.triageUser ?? 'frontend')

  return { token, user }
}

if (IP_MANAGEMENT_TOKEN || TRIAGE_TOKEN) {
  api.interceptors.request.use((config) => {
    const credentials = selectAuthCredentials(
      config.method ?? 'get',
      config.url ?? '',
      {
        ipManagementToken: IP_MANAGEMENT_TOKEN,
        ipManagementUser: IP_MANAGEMENT_USER,
        triageToken: TRIAGE_TOKEN,
        triageUser: TRIAGE_USER,
      },
    )
    if (!credentials) return config

    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${credentials.token}`
    config.headers['X-User-Id'] = credentials.user
    return config
  })
}
