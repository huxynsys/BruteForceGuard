import { describe, expect, it } from 'vitest'
import {
  resolveApiBaseUrl,
  selectAuthCredentials,
  isRoleGatedRequest,
} from './client'

// Phase 9.3: API base URL resolution for development and production builds.
// Paths already contain the API prefix (e.g. "/api/v1/events/"), so these
// values only decide which origin serves them.

describe('API base URL resolution', () => {
  it('uses the direct backend origin in development', () => {
    expect(resolveApiBaseUrl({ DEV: true })).toBe('http://localhost:8000')
  })

  it('falls back to same-origin for a production build', () => {
    expect(resolveApiBaseUrl({ DEV: false })).toBe('')
  })

  it('honours an explicit absolute API origin', () => {
    expect(
      resolveApiBaseUrl({
        VITE_API_BASE_URL: 'https://api.example.com',
        DEV: false,
      }),
    ).toBe('https://api.example.com')
  })

  it('treats an empty value as same-origin (reverse proxy deployment)', () => {
    expect(resolveApiBaseUrl({ VITE_API_BASE_URL: '', DEV: true })).toBe('')
  })

  it('uses the configured value verbatim even in development', () => {
    expect(
      resolveApiBaseUrl({
        VITE_API_BASE_URL: 'http://localhost:9000',
        DEV: true,
      }),
    ).toBe('http://localhost:9000')
  })
})

// Phase 10: credential routing. Roles are bound to tokens server-side
// (`ALERT_TRIAGE_API_TOKENS`), so the dashboard must send the role-gated
// triage token to triage writes and audit reads, and the IP-management token
// everywhere else.
const BOTH_TOKENS = {
  ipManagementToken: 'ip-token',
  ipManagementUser: 'ip-operator',
  triageToken: 'triage-token',
  triageUser: 'analyst-1',
}

describe('request credential selection', () => {
  it('routes audit reads to the role-gated triage token', () => {
    expect(isRoleGatedRequest('GET', '/api/v1/audit/')).toBe(true)
    expect(selectAuthCredentials('get', '/api/v1/audit/', BOTH_TOKENS)).toEqual({
      token: 'triage-token',
      user: 'analyst-1',
    })
  })

  it('routes alert triage writes to the role-gated triage token', () => {
    expect(selectAuthCredentials('patch', '/api/v1/alerts/7', BOTH_TOKENS)).toEqual({
      token: 'triage-token',
      user: 'analyst-1',
    })
  })

  it('keeps the IP-management token for every other request', () => {
    expect(selectAuthCredentials('post', '/api/v1/blacklist/', BOTH_TOKENS)).toEqual({
      token: 'ip-token',
      user: 'ip-operator',
    })
    // Reading alerts is not role-gated (only the triage PATCH is).
    expect(selectAuthCredentials('get', '/api/v1/alerts/1', BOTH_TOKENS)).toEqual({
      token: 'ip-token',
      user: 'ip-operator',
    })
  })

  it('falls back to the only configured token', () => {
    expect(
      selectAuthCredentials('get', '/api/v1/audit/', { triageToken: 'only' }),
    ).toEqual({ token: 'only', user: 'frontend' })
    expect(
      selectAuthCredentials('post', '/api/v1/blacklist/', { triageToken: 'only' }),
    ).toEqual({ token: 'only', user: 'frontend' })
    expect(
      selectAuthCredentials('get', '/api/v1/audit/', { ipManagementToken: 'only' }),
    ).toEqual({ token: 'only', user: 'frontend' })
  })

  it('returns null when no token is configured', () => {
    expect(selectAuthCredentials('get', '/api/v1/audit/', {})).toBeNull()
    expect(isRoleGatedRequest('get', '/api/v1/events/')).toBe(false)
  })
})