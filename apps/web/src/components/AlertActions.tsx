'use client'

import { useState, useTransition } from 'react'
import { useRouter } from 'next/navigation'
import { mutate } from '@/lib/browser'
import { ALERT_TRANSITIONS } from '@/lib/types'
import type { AlertStatus } from '@/lib/types'

// Alert status controls.
//
// The available transitions come from the same table the server enforces, so the
// UI cannot offer an action the server would reject. The server is still the
// authority: a rejection is displayed rather than assumed away.
export function AlertActions({ id, status }: { id: string; status: AlertStatus }) {
  const router = useRouter()
  const [pending, startTransition] = useTransition()
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const transitions = ALERT_TRANSITIONS[status] ?? []

  if (transitions.length === 0) {
    return <span className="dim" style={{ fontSize: 12 }}>terminal</span>
  }

  async function apply(next: AlertStatus) {
    setBusy(next)
    setError(null)
    const result = await mutate('alert.status', id, { status: next })
    setBusy(null)

    if (!result.ok) {
      setError(result.message)
      return
    }
    startTransition(() => router.refresh())
  }

  return (
    <div>
      <div className="button-row">
        {transitions.map((next) => (
          <button
            key={next}
            type="button"
            className={`small ${next === 'DISMISSED' ? 'danger' : ''}`}
            disabled={pending || busy !== null}
            onClick={() => apply(next)}
          >
            {busy === next ? '…' : next.toLowerCase()}
          </button>
        ))}
      </div>
      {error ? (
        <div className="muted" style={{ color: 'var(--danger)', fontSize: 12, marginTop: 4 }}>
          {error}
        </div>
      ) : null}
    </div>
  )
}
