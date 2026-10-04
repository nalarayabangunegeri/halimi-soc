import { NextResponse } from 'next/server'
import { config } from '@/lib/config'

// Passwordless login, step 1: fetch a challenge for the username.
// Unauthenticated by design (like /api/auth/login); the API throttles and
// returns a generic error for unknown users.
export async function POST(request: Request) {
  let payload: { username?: unknown }
  try {
    payload = (await request.json()) as typeof payload
  } catch {
    return NextResponse.json({ error: { code: 'BAD_REQUEST', message: 'Invalid request body.' } }, { status: 400 })
  }
  const username = typeof payload.username === 'string' ? payload.username.trim().toLowerCase() : ''
  if (!username) {
    return NextResponse.json(
      { error: { code: 'BAD_REQUEST', message: 'Username is required.' } },
      { status: 400 },
    )
  }

  const upstream = await fetch(`${config.apiUrl}/api/v1/auth/webauthn/login/begin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ username }),
    cache: 'no-store',
  })
  const text = await upstream.text()
  let parsed: unknown
  try {
    parsed = text ? JSON.parse(text) : undefined
  } catch {
    parsed = undefined
  }
  if (!upstream.ok) {
    const envelope = parsed as { error?: { code?: string; message?: string } } | undefined
    return NextResponse.json(
      { error: { code: envelope?.error?.code ?? 'LOGIN_FAILED', message: envelope?.error?.message ?? 'Login failed.' } },
      { status: upstream.status === 429 ? 429 : upstream.status },
    )
  }
  return NextResponse.json(parsed)
}
