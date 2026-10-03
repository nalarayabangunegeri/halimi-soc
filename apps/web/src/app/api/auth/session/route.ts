import { NextResponse } from 'next/server'
import { readSession } from '@/lib/session'

// Reports the current operator to the client UI.
//
// It returns only the non-secret parts of the session. The CSRF token is included
// because the page must echo it on mutations, and it is already readable by this
// origin.
export async function GET() {
  const session = await readSession()
  if (!session) {
    return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Not signed in.' } }, { status: 401 })
  }
  return NextResponse.json({
    user: { username: session.username, role: session.role },
    expires_at: session.expiresAt,
  })
}
