import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { fetchEvents } from './events'
import { fetchAlerts } from './alerts'
import { closeSession, fetchSession, fetchSessionStats, fetchSessions } from './sessions'
import { fetchAnalytics, fetchHealth, fetchSummary } from './dashboard'
import { api } from './client'
import {
  alertFixture,
  analyticsFixture,
  eventFixture,
  sessionFixture,
  summaryFixture,
} from '../test/fixtures'

// API-layer tests: verify each client function hits the right endpoint
// with the right parameters and unwraps response.data.

describe('api layer', () => {
  let get: ReturnType<typeof vi.spyOn>
  let post: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    get = vi.spyOn(api, 'get').mockResolvedValue({ data: [] })
    post = vi.spyOn(api, 'post').mockResolvedValue({ data: {} })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('fetchEvents requests /api/v1/events/ with limit param', async () => {
    get.mockResolvedValue({ data: [eventFixture] })

    const events = await fetchEvents(50)

    expect(get).toHaveBeenCalledWith('/api/v1/events/', { params: { limit: 50 } })
    expect(events).toEqual([eventFixture])
  })

  it('fetchAlerts defaults to limit 100', async () => {
    get.mockResolvedValue({ data: [alertFixture] })

    const alerts = await fetchAlerts()

    expect(get).toHaveBeenCalledWith('/api/v1/alerts/', { params: { limit: 100 } })
    expect(alerts).toHaveLength(1)
  })

  it('fetchSessions passes status filter only when provided', async () => {
    await fetchSessions('active')
    expect(get).toHaveBeenCalledWith('/api/v1/attack-sessions/', {
      params: { status: 'active' },
    })

    await fetchSessions()
    expect(get).toHaveBeenCalledWith('/api/v1/attack-sessions/', {
      params: undefined,
    })
  })

  it('fetchSession requests a single session by id', async () => {
    get.mockResolvedValue({ data: sessionFixture })

    const session = await fetchSession(41)

    expect(get).toHaveBeenCalledWith('/api/v1/attack-sessions/41')
    expect(session.id).toBe(41)
  })

  it('closeSession POSTs to the close endpoint', async () => {
    post.mockResolvedValue({ data: { ...sessionFixture, status: 'closed' } })

    const closed = await closeSession(41)

    expect(post).toHaveBeenCalledWith('/api/v1/attack-sessions/41/close')
    expect(closed.status).toBe('closed')
  })

  it('fetchSessionStats hits the stats endpoint', async () => {
    const stats = {
      active_sessions: 4,
      total_events: 30,
      unique_source_ips: 37,
      unique_usernames: 18,
    }
    get.mockResolvedValue({ data: stats })

    expect(await fetchSessionStats()).toEqual(stats)
    expect(get).toHaveBeenCalledWith('/api/v1/attack-sessions/stats/active')
  })

  it('fetchSummary hits the dashboard summary endpoint', async () => {
    get.mockResolvedValue({ data: summaryFixture })

    const summary = await fetchSummary()

    expect(get).toHaveBeenCalledWith('/api/v1/dashboard/summary')
    expect(summary.total_events).toBe(1247)
  })

  it('fetchAnalytics hits the dashboard analytics endpoint', async () => {
    get.mockResolvedValue({ data: analyticsFixture })

    const analytics = await fetchAnalytics()

    expect(get).toHaveBeenCalledWith('/api/v1/dashboard/analytics')
    expect(analytics.top_ips[0].value).toBe('192.168.1.44')
  })

  it('fetchHealth hits /health', async () => {
    get.mockResolvedValue({ data: { status: 'healthy', service: 'bruteforceguard-api', version: '0.5.0' } })

    const health = await fetchHealth()

    expect(get).toHaveBeenCalledWith('/health')
    expect(health.status).toBe('healthy')
  })

  it('propagates request failures so callers can render error states', async () => {
    get.mockRejectedValue(new Error('Network Error'))

    await expect(fetchEvents()).rejects.toThrow('Network Error')
  })
})
