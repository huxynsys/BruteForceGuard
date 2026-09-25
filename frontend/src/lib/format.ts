/** Time formatting helpers for the SOC dashboard. */

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return `${date.toLocaleDateString()} ${formatTime(iso)}`
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return '—'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return iso
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000))

  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h`
  return `${Math.floor(hours / 24)}d`
}

/**
 * Compact human duration for detection windows (`300` -> `5 min`).
 *
 * The raw seconds value is always rendered next to it by the caller, so the
 * exact configured number stays visible.
 */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) {
    return '—'
  }
  if (seconds < 60) return `${seconds} s`

  const minutes = seconds / 60
  if (minutes < 60) {
    return `${Number.isInteger(minutes) ? minutes : minutes.toFixed(1)} min`
  }

  const hours = minutes / 60
  return `${Number.isInteger(hours) ? hours : hours.toFixed(1)} h`
}

