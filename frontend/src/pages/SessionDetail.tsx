import { useCallback, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useApi } from '../hooks/useApi'
import { fetchSession, closeSession } from '../api/sessions'
import { LoadingState, ErrorState } from '../components/ui/States'
import SessionDetails from '../components/sessions/SessionDetails'

export default function SessionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data, loading, error, refresh } = useApi(
    () => fetchSession(id ?? ''),
    undefined,
  )
  const [closing, setClosing] = useState(false)
  const [closeError, setCloseError] = useState<string | null>(null)

  const handleClose = useCallback(async () => {
    if (!id) return
    setClosing(true)
    setCloseError(null)
    try {
      await closeSession(id)
      refresh()
    } catch {
      setCloseError('Failed to close the session. Please try again.')
    } finally {
      setClosing(false)
    }
  }, [id, refresh])

  if (loading && !data) return <LoadingState label="Loading session..." />
  if (error && !data) return <ErrorState message={error} onRetry={refresh} />
  if (!data) return <ErrorState message="Session not found." onRetry={refresh} />

  return (
    <>
      {closeError && (
        <div className="state" role="alert">
          <div className="state-title">{closeError}</div>
        </div>
      )}
      <SessionDetails session={data} onClose={handleClose} closing={closing} />
    </>
  )
}
