'use client'

import { useState, useTransition } from 'react'
import { useRouter } from 'next/navigation'
import { mutate } from '@/lib/browser'
import { INCIDENT_TRANSITIONS } from '@/lib/types'
import type { IncidentStatus } from '@/lib/types'
import { humanizeEnum } from '@/lib/format'

// Incident status controls.
//
// The transitions mirror the server's state machine, so the UI cannot offer a
// change the server would reject as a skipped stage or a reopened terminal
// incident. A rejection from the server is still surfaced, because the server is
// the authority and a divergence should be visible rather than swallowed.
export function IncidentControls({ id, status }: { id: string; status: IncidentStatus }) {
  const router = useRouter()
  const [pending, startTransition] = useTransition()
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const transitions = INCIDENT_TRANSITIONS[status] ?? []

  async function apply(next: IncidentStatus) {
    setBusy(next)
    setError(null)
    const result = await mutate('incident.status', id, { status: next })
    setBusy(null)

    if (!result.ok) {
      setError(result.message)
      return
    }
    startTransition(() => router.refresh())
  }

  if (transitions.length === 0) {
    return (
      <span className="dim" style={{ fontSize: 12 }} title="A terminal incident is never reopened; new activity creates a new incident.">
        terminal — no further transitions
      </span>
    )
  }

  return (
    <div>
      <div className="button-row">
        {transitions.map((next) => (
          <button
            key={next}
            type="button"
            className={`small ${next === 'FALSE_POSITIVE' ? 'danger' : 'primary'}`}
            disabled={pending || busy !== null}
            onClick={() => apply(next)}
          >
            {busy === next ? '…' : humanizeEnum(next)}
          </button>
        ))}
      </div>
      {error ? (
        <div style={{ color: 'var(--danger)', fontSize: 12, marginTop: 6 }}>{error}</div>
      ) : null}
    </div>
  )
}
