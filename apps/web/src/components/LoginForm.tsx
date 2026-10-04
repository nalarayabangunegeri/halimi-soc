'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { assertCredential, webauthnSupported } from '@/lib/webauthn'

// The login form.
//
// Failures are reported with the API's own message, which is deliberately generic,
// so the form cannot be used to discover whether an account exists. The submit
// button is disabled while a request is in flight so a double click cannot produce
// two sessions.
export function LoginForm() {
  const router = useRouter()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [needMfa, setNeedMfa] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // Rendered only after mount: the server has no window, so rendering it
  // during SSR would hydrate differently on the client (React error #418).
  const [canUsePasskey, setCanUsePasskey] = useState(false)
  useEffect(() => {
    setCanUsePasskey(webauthnSupported())
  }, [])

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          needMfa
            ? { username, password, totp_code: code, backup_code: code }
            : { username, password },
        ),
      })

      const text = await response.text()
      let parsed: unknown
      try {
        parsed = text ? JSON.parse(text) : undefined
      } catch {
        parsed = undefined
      }

      if (!response.ok) {
        const envelope = parsed as { error?: { code?: string; message?: string } } | undefined
        // Password was correct but the second factor is missing: prompt for it
        // instead of reporting a generic failure. The code is not echoed.
        if (envelope?.error?.code === 'MFA_REQUIRED' && !needMfa) {
          setNeedMfa(true)
          setError('Enter the 6-digit code from your authenticator app (or a backup code).')
          return
        }
        setError(envelope?.error?.message ?? 'Sign in failed.')
        return
      }

      // The session cookie is set by the response; a full navigation picks it up
      // and lets the server render the console with the new session.
      router.replace('/')
      router.refresh()
    } catch {
      setError('The console is unreachable. Check that the API is running.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={onSubmit} noValidate>
      {error ? (
        <div className="error-banner" role="alert">
          {error}
        </div>
      ) : null}

      <div className="login-field">
        <label htmlFor="username">Username</label>
        <input
          id="username"
          name="username"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
      </div>

      <div className="login-field">
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>

      {needMfa ? (
        <div className="login-field">
          <label htmlFor="mfa-code">Authenticator code or backup code</label>
          <input
            id="mfa-code"
            name="mfa-code"
            autoComplete="one-time-code"
            inputMode="text"
            value={code}
            onChange={(e) => setCode(e.target.value.trim())}
            required
          />
        </div>
      ) : null}

      <button type="submit" className="primary" disabled={busy || !username || !password || (needMfa && !code)}>
        {busy ? 'Signing in…' : needMfa ? 'Verify and sign in' : 'Sign in'}
      </button>

      {canUsePasskey ? (
        <button
          type="button"
          disabled={busy || !username}
          onClick={async () => {
            setBusy(true)
            setError(null)
            try {
              const beginRes = await fetch('/api/auth/webauthn/login/begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username }),
              })
              if (!beginRes.ok) {
                setError('Passkey sign-in is not available for this account.')
                return
              }
              const opts = (await beginRes.json()) as {
                challenge: string
                rpId: string
                allowCredentials: Array<{ type: string; id: string; transports?: string[] }>
              }
              const assertion = await assertCredential(opts)
              const completeRes = await fetch('/api/auth/webauthn/login/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  username,
                  challenge: opts.challenge,
                  id: assertion.id,
                  response: {
                    clientDataJSON: assertion.clientDataJSON,
                    authenticatorData: assertion.authenticatorData,
                    signature: assertion.signature,
                    userHandle: assertion.userHandle,
                  },
                }),
              })
              if (!completeRes.ok) {
                setError('Passkey sign-in failed.')
                return
              }
              router.replace('/')
              router.refresh()
            } catch {
              setError('Passkey sign-in was cancelled or failed.')
            } finally {
              setBusy(false)
            }
          }}
        >
          Sign in with passkey
        </button>
      ) : null}
    </form>
  )
}
