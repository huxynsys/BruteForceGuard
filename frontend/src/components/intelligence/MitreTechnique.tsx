/**
 * Phase 7 - MITRE ATT&CK technique badge component.
 *
 * Displays structured MITRE context for a detection type.
 */

import type { MitreContext } from '../../types/intelligence'

interface MitreTechniqueProps {
  context: MitreContext | null
  loading?: boolean
}

export default function MitreTechnique({ context, loading = false }: MitreTechniqueProps) {
  if (loading) {
    return (
      <div className="mitre-technique">
        <span className="badge badge-muted">Loading...</span>
      </div>
    )
  }

  if (!context) {
    return (
      <div className="mitre-technique">
        <span className="badge badge-muted">No MITRE mapping</span>
      </div>
    )
  }

  if (!context.is_mapped) {
    return (
      <div className="mitre-technique">
        <span className="badge badge-muted">Unmapped</span>
      </div>
    )
  }

  return (
    <div className="mitre-technique">
      <div className="mitre-technique__header">
        <span className="badge badge-high mono">{context.technique_id}</span>
        <span className="mitre-technique__name">{context.technique_name}</span>
      </div>
      <div className="mitre-technique__tactic">{context.tactic}</div>
      {context.description && (
        <div className="mitre-technique__description">{context.description}</div>
      )}
    </div>
  )
}