import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from './Cards'

describe('SeverityBadge', () => {
  it.each(['critical', 'high', 'medium', 'low'])(
    'renders %s with text and severity class (color + text, never color alone)',
    (severity) => {
      render(<SeverityBadge severity={severity} />)

      const badge = screen.getByText(severity)
      expect(badge).toBeInTheDocument()
      expect(badge).toHaveClass(`badge-${severity}`)
    },
  )

  it('marks unknown severities as muted without a dot', () => {
    render(<SeverityBadge severity="unknown-level" />)

    const badge = screen.getByText('unknown-level')
    expect(badge).toHaveClass('badge-muted')
    expect(badge.querySelector('.sev-dot')).toBeNull()
  })
})
