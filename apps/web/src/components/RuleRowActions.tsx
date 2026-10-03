'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { mutate } from '@/lib/browser'

// Per-rule admin actions: delete with an explicit confirmation step.
export function RuleRowActions({ id }: { id: string }) {
  const router = useRouter()
  const [confirming, setConfirming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function remove() {
    setBusy(true)
    setError(null)
    const result = await mutate('rules.delete', id)
    setBusy(false)
    if (!result.ok) {
      setError(result.message)
      return
    }
    setConfirming(false)
    router.refresh()
  }

  if (!confirming) {
    return (
      <div>
        <button type="button" className="small danger" disabled={busy} onClick={() => setConfirming(true)}>
          Delete
        </button>
        {error ? (
          <div className="muted" style={{ color: 'var(--danger)', fontSize: 12, marginTop: 4 }}>
            {error}
          </div>
        ) : null}
      </div>
    )
  }

  return (
    <div>
      <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>
        Delete this rule file? The engine keeps running it until reload.
      </div>
      <div className="button-row">
        <button type="button" className="small danger" disabled={busy} onClick={remove}>
          {busy ? '…' : 'Confirm delete'}
        </button>
        <button type="button" className="small" disabled={busy} onClick={() => setConfirming(false)}>
          Cancel
        </button>
      </div>
    </div>
  )
}
