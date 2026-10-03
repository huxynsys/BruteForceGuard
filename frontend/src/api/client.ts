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

if (IP_MANAGEMENT_TOKEN || TRIAGE_TOKEN) {
  api.interceptors.request.use((config) => {
    // Each write endpoint expects its own token (roles are bound to tokens
    // server-side), so pick by target: triage PATCHes use the triage token,
    // everything else keeps using the IP-management token (falling back to
    // whichever single token is configured).
    const method = (config.method ?? 'get').toLowerCase()
    const isTriageWrite =
      method === 'patch' && (config.url ?? '').includes('/api/v1/alerts/')

    const token = isTriageWrite
      ? (TRIAGE_TOKEN ?? IP_MANAGEMENT_TOKEN)
      : (IP_MANAGEMENT_TOKEN ?? TRIAGE_TOKEN)
    const user = isTriageWrite ? TRIAGE_USER : IP_MANAGEMENT_USER

    if (!token) return config

    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${token}`
    config.headers['X-User-Id'] = user
    return config
  })
}
