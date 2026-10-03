import { NextResponse } from 'next/server'
import { logout, ApiError } from '@/lib/api'
import { clearCsrfToken, verifyCsrf } from '@/lib/csrf'
import { clearSession, readSession } from '@/lib/session'

// Logout revokes the API session and clears this app's cookies.
//
// It requires the CSRF token because it is a state-changing request authenticated
// by a cookie.

export async function POST(request: Request) {
  if (!(await verifyCsrf(request))) {
    return NextResponse.json({ error: { code: 'FORBIDDEN', message: 'Invalid CSRF token.' } }, { status: 403 })
  }

  const session = await readSession()
  if (session) {
    try {
      await logout(session)
    } catch (error) {
      // The API session may already be gone or the API may be unreachable. The
      // local session is cleared regardless: leaving a local cookie in place
      // because a remote revoke failed would keep the operator apparently logged
      // in to a session that no longer exists.
      if (!(error instanceof ApiError)) throw error
    }
  }

  await clearSession()
  await clearCsrfToken()

  return NextResponse.json({ status: 'logged_out' })
}
