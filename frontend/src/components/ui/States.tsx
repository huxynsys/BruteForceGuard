import type { ReactNode } from 'react'
import { Loader2, AlertTriangle, CheckCircle2 } from 'lucide-react'

export function LoadingState({ label = 'Loading data...' }: { label?: string }) {
  return (
    <div className="state" role="status">
      <div className="state-icon">
        <Loader2 className="spin" size={24} aria-hidden="true" />
      </div>
      <div className="state-title">{label}</div>
    </div>
  )
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="state" role="alert">
      <div className="state-icon">
        <AlertTriangle size={24} aria-hidden="true" className="text-danger" />
      </div>
      <div className="state-title">Unable to load data</div>
      <div className="state-hint">{message}</div>
      {onRetry && (
        <button className="neo-button" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  )
}

export function EmptyState({
  title = 'No active attacks',
  hint = 'BruteForceGuard is monitoring authentication activity.',
}: {
  title?: string
  hint?: string
}) {
  return (
    <div className="state">
      <div className="state-icon">
        <CheckCircle2 size={24} aria-hidden="true" className="text-success" />
      </div>
      <div className="state-title">{title}</div>
      <div className="state-hint">{hint}</div>
    </div>
  )
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title}>
      <h2 className="page-section-title">{title}</h2>
      {children}
    </section>
  )
}
