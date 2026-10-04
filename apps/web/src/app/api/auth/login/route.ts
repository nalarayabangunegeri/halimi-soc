import { NextResponse } from 'next/server'
import { login, ApiError } from '@/lib/api'
import { issueCsrfToken } from '@/lib/csrf'
import { writeSession } from '@/lib/session'

// Login is the one endpoint that creates a session. It exchanges credentials for
// an API session, then stores that session in this app's own HttpOnly cookie.
//
// The API session value never reaches the browser. That is what keeps the API
// unreachable from the browser, removes the need for CORS, and means a stolen
// dashboard cookie cannot be replayed against the API directly.

export async function POST(request: Request) {
  let payload: { username?: unknown; password?: unknown; totp_code?: unknown; backup_code?: unknown }
  try {
    payload = (await request.json()) as typeof payload
  } catch {
    return NextResponse.json({ error: { code: 'BAD_REQUEST', message: 'Invalid request body.' } }, { status: 400 })
  }

  const username = typeof payload.username === 'string' ? payload.username.trim().toLowerCase() : ''
  const password = typeof payload.password === 'string' ? payload.password : ''
  const totpCode = typeof payload.totp_code === 'string' ? payload.totp_code.trim() : ''
  const backupCode = typeof payload.backup_code === 'string' ? payload.backup_code.trim() : ''

  if (!username || !password) {
    return NextResponse.json(
      { error: { code: 'BAD_REQUEST', message: 'Username and password are required.' } },
      { status: 400 },
    )
  }

  try {
    const result = await login(username, password, totpCode || undefined, backupCode || undefined)

    await writeSession({
      apiSession: result.apiCookie,
      apiCsrf: result.csrf_token,
      username: result.user.username,
      role: result.user.role,
      expiresAt: result.expires_at,
    })

    // The CSRF token is issued only after a successful login, so a failed attempt
    // cannot be used to plant a token.
    const csrf = await issueCsrfToken()

    // Only the non-secret parts are returned. The API session and its CSRF token
    // stay server-side.
    return NextResponse.json({
      user: result.user,
      expires_at: result.expires_at,
      csrf_token: csrf,
    })
  } catch (error) {
    if (error instanceof ApiError) {
      // The API's status is preserved so the UI can distinguish a rate limit from
      // bad credentials, and its message is deliberately not forwarded: it is
      // already generic, and forwarding an upstream message verbatim is how an
      // internal detail ends up in a browser.
      const status = error.status === 429 ? 429 : error.status === 401 ? 401 : 502
      return NextResponse.json({ error: { code: error.code, message: error.message } }, { status })
    }
    return NextResponse.json(
      { error: { code: 'INTERNAL_ERROR', message: 'Login is unavailable.' } },
      { status: 500 },
    )
  }
}
