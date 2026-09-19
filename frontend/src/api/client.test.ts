import { describe, expect, it } from 'vitest'
import { resolveApiBaseUrl } from './client'

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