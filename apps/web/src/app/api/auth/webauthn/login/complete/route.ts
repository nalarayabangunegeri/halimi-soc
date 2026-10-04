import { NextResponse } from 'next/server'
import { extractSessionCookie } from '@/lib/api'
import { config } from '@/lib/config'
import { issueCsrfToken } from '@/lib/csrf'
import { writeSession } from '@/lib/session'

// Passwordless login, step 2: verify the assertion. On success the API sets a
// session cookie, which is captured server-side like the password login.
export async function POST(request: Request) {
  let payload: {
    username?: unknown
    challenge?: unknown
    id?: unknown
    response?: unknown
  }
  try {
    payload = (await request.json()) as typeof payload
  } catch {
    return NextResponse.json({ error: { code: 'BAD_REQUEST', message: 'Invalid request body.' } }, { status: 400 })
  }
  const username = typeof payload.username === 'string' ? payload.username.trim().toLowerCase() : ''
  const challenge = typeof payload.challenge === 'string' ? payload.challenge : ''
  const id = typeof payload.id === 'string' ? payload.id : ''
  const response = payload.response as
    | { clientDataJSON?: unknown; authenticatorData?: unknown; signature?: unknown; userHandle?: unknown }
    | undefined
  if (!username || !challenge || !id || !response) {
    return NextResponse.json(
      { error: { code: 'BAD_REQUEST', message: 'Username, challenge and assertion are required.' } },
      { status: 400 },
    )
  }

  const upstream = await fetch(`${config.apiUrl}/api/v1/auth/webauthn/login/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ username, challenge, id, response }),
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

  const setCookie = upstream.headers.get('set-cookie') ?? ''
  const apiCookie = extractSessionCookie(setCookie)
  if (!apiCookie) {
    return NextResponse.json(
      { error: { code: 'NO_SESSION_COOKIE', message: 'The API did not return a session.' } },
      { status: 500 },
    )
  }
  const info = parsed as { user: { id: string; username: string; role: 'ADMIN' | 'ANALYST' | 'READONLY' }; csrf_token: string; expires_at: string }
  await writeSession({
    apiSession: apiCookie,
    apiCsrf: info.csrf_token,
    username: info.user.username,
    role: info.user.role,
    expiresAt: info.expires_at,
  })
  const csrf = await issueCsrfToken()
  return NextResponse.json({ user: info.user, expires_at: info.expires_at, csrf_token: csrf })
}
