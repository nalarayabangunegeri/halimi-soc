'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

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
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      const text = await response.text()
      let parsed: unknown
      try {
        parsed = text ? JSON.parse(text) : undefined
      } catch {
        parsed = undefined
      }

      if (!response.ok) {
        const envelope = parsed as { error?: { message?: string } } | undefined
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

      <button type="submit" className="primary" disabled={busy || !username || !password}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  )
}
