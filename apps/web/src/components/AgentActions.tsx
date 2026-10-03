'use client'

import { useState, useTransition } from 'react'
import { useRouter } from 'next/navigation'
import { mutate } from '@/lib/browser'

// Agent credential management.
//
// Rotation and revocation are admin-only, and the server enforces that too. The
// UI hides the controls from a non-admin because showing an action that will always
// fail is bad UX, not because hiding is a control.
//
// A rotated token is displayed exactly once. The server stores only its hash, so
// this is the only chance to copy it; the panel says so.
export function AgentActions({ id, host, revoked }: { id: string; host: string; revoked: boolean }) {
  const router = useRouter()
  const [pending, startTransition] = useTransition()
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [confirmRevoke, setConfirmRevoke] = useState(false)

  async function rotate() {
    setBusy('rotate')
    setError(null)
    const result = await mutate<{ agent_token: string }>('agent.rotate', id)
    setBusy(null)

    if (!result.ok) {
      setError(result.message)
      return
    }
    setToken(result.data.agent_token)
    startTransition(() => router.refresh())
  }

  async function revoke() {
    setBusy('revoke')
    setError(null)
    const result = await mutate('agent.revoke', id)
    setBusy(null)

    if (!result.ok) {
      setError(result.message)
      return
    }
    setConfirmRevoke(false)
    startTransition(() => router.refresh())
  }

  return (
    <div>
      <div className="button-row">
        <button type="button" className="small" disabled={pending || busy !== null || revoked} onClick={rotate}>
          {busy === 'rotate' ? '…' : 'Rotate'}
        </button>
        {confirmRevoke ? (
          <>
            <button type="button" className="small danger" disabled={busy !== null} onClick={revoke}>
              {busy === 'revoke' ? '…' : `Confirm revoke ${host}`}
            </button>
            <button type="button" className="small" disabled={busy !== null} onClick={() => setConfirmRevoke(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button
            type="button"
            className="small danger"
            disabled={pending || revoked}
            onClick={() => setConfirmRevoke(true)}
          >
            Revoke
          </button>
        )}
      </div>

      {error ? (
        <div style={{ color: 'var(--danger)', fontSize: 12, marginTop: 4 }}>{error}</div>
      ) : null}

      {token ? (
        <div className="notice notice-warn" style={{ marginTop: 8, marginBottom: 0 }}>
          <div style={{ marginBottom: 6 }}>
            <strong>New token for {host}.</strong> This is shown once and cannot be recovered. The previous
            token is already invalid.
          </div>
          <code className="mono" style={{ wordBreak: 'break-all' }}>
            {token}
          </code>
          <div style={{ marginTop: 8 }}>
            <button type="button" className="small" onClick={() => setToken(null)}>
              Dismiss
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
