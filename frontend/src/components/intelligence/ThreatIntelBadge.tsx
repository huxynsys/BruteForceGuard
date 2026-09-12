/**
 * Phase 7 - Threat Intelligence badge component.
 *
 * Shows whether an indicator is known to threat intelligence.
 */

import type { ThreatIntelLookup } from '../../types/intelligence'

interface ThreatIntelBadgeProps {
  intel: ThreatIntelLookup | null
  loading?: boolean
}

export default function ThreatIntelBadge({ intel, loading = false }: ThreatIntelBadgeProps) {
  if (loading) {
    return (
      <span className="badge badge-muted" aria-label="Checking threat intelligence">
        Checking...
      </span>
    )
  }

  if (!intel) {
    return (
      <span className="badge badge-muted" aria-label="Threat intelligence unavailable">
        TI unavailable
      </span>
    )
  }

  if (intel.known) {
    return (
      <span className="badge badge-critical" aria-label={`Known threat indicator from ${intel.source}`}>
        MATCH
        {intel.confidence != null && (
          <span className="badge-sub"> {intel.confidence}%</span>
        )}
      </span>
    )
  }

  return (
    <span className="badge badge-muted" aria-label="Indicator not present in threat intelligence">
      No match
    </span>
  )
}