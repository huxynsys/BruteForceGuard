import { useCallback, useEffect, useRef, useState } from 'react'

export interface ApiState<T> {
  data: T | null
  loading: boolean
  error: string | null
  lastUpdated: Date | null
  refresh: () => void
}

/**
 * Fetch helper with optional polling. Polling only re-runs while the
 * document is visible, so background tabs do not hammer the API.
 */
export function useApi<T>(
  fetcher: () => Promise<T>,
  intervalMs?: number,
): ApiState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [tick, setTick] = useState(0)

  const fetcherRef = useRef(fetcher)

  // Keep the ref current without touching it during render (react-hooks/refs).
  useEffect(() => {
    fetcherRef.current = fetcher
  })

  const refresh = useCallback(() => setTick((t) => t + 1), [])

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      try {
        const result = await fetcherRef.current()
        if (cancelled) return
        setData(result)
        setError(null)
        setLastUpdated(new Date())
      } catch (err) {
        if (cancelled) return
        setError(
          err instanceof Error ? err.message : 'Unknown error occurred',
        )
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void run()

    let timer: ReturnType<typeof setInterval> | undefined
    if (intervalMs && intervalMs > 0) {
      timer = setInterval(() => {
        if (document.visibilityState === 'visible') void run()
      }, intervalMs)
    }

    return () => {
      cancelled = true
      if (timer) clearInterval(timer)
    }
  }, [intervalMs, tick])

  return { data, loading, error, lastUpdated, refresh }
}

/** Polling interval used across dashboard pages (8 seconds). */
export const POLL_INTERVAL = 8000
