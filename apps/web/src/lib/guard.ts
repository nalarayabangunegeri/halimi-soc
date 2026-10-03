import 'server-only'

import { redirect } from 'next/navigation'
import { readSession } from './session'
import type { WebSession } from './session'

// Page-level authentication guard.
//
// Every page calls this before doing anything else. Redirecting here rather than
// in a middleware keeps the check next to the data fetch: a middleware-only guard
// is easy to bypass by adding a route that the matcher does not cover, and the
// failure would be a page that renders with no session and then errors obscurely.
export async function requireSession(): Promise<WebSession> {
  const session = await readSession()
  if (!session) redirect('/login')
  return session
}
