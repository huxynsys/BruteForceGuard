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

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10_000,
  headers: { 'Content-Type': 'application/json' },
})
