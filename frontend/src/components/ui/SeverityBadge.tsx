import { SEVERITY_LABELS } from '../../lib/labels'

interface SeverityBadgeProps {
  severity: string
  showDot?: boolean
}

/** Severity badge: color + text (never color alone — accessibility). */
export default function SeverityBadge({
  severity,
  showDot = true,
}: SeverityBadgeProps) {
  const key = severity?.toLowerCase() ?? 'low'
  const known = ['critical', 'high', 'medium', 'low'].includes(key)

  return (
    <span className={known ? `badge badge--${key}` : 'badge badge--low'}>
      {showDot && <span className="dot" aria-hidden />}
      {SEVERITY_LABELS[key] ?? key.toUpperCase()}
    </span>
  )
}
