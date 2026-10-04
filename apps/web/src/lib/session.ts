import 'server-only'

import { cookies } from 'next/headers'
import { assertRuntimeConfig, config } from './config'

// Session handling for the dashboard's own cookie.
//
// Architecture note (see DESIGN.md §15 and ADR-003):
//
// The browser never holds the API session. The API's session cookie is captured by
// the login route handler and kept in this app's own HttpOnly cookie; every API
// call is made server-side with that value. Two consequences matter:
//
//  1. A stolen browser cookie cannot be replayed against the API, because it is not
//     the API's credential and the API is not reachable from the browser.
//  2. The API needs no CORS policy, because no browser request ever crosses to it.

export interface WebSession {
  /** The API's session cookie value, held server-side. */
  apiSession: string
  /** The API's CSRF token, needed for mutations the UI triggers. */
  apiCsrf: string
  /** The authenticated operator, for rendering and for role checks in the UI. */
  username: string
  role: 'ADMIN' | 'ANALYST' | 'READONLY'
  expiresAt: string
}

// The session payload is stored as a small JSON cookie.
//
// It is HttpOnly, so a script injected into the page cannot read the API session
// value. It is also SameSite=Strict, so it is never sent on a cross-site request,
// which is the first line of defence against CSRF; the double-submit token in
// csrf.ts is the second.

const cookieOptions = {
  httpOnly: true,
  sameSite: 'strict' as const,
  secure: config.secureCookies,
  path: '/',
  maxAge: 60 * 60 * 12,
}

export function encodeSession(session: WebSession): string {
  return Buffer.from(JSON.stringify(session), 'utf8').toString('base64url')
}

export function decodeSession(value: string): WebSession | null {
  try {
    const parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as unknown
    if (!isWebSession(parsed)) return null
    return parsed
  } catch {
    // A malformed cookie is treated as no session, not as an error: the caller
    // redirects to login either way, and an error path here would be a
    // denial-of-service trigger via cookie tampering.
    return null
  }
}

function isWebSession(value: unknown): value is WebSession {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (
    typeof v.apiSession !== 'string' ||
    typeof v.apiCsrf !== 'string' ||
    typeof v.username !== 'string' ||
    typeof v.expiresAt !== 'string'
  )
    return false
  // Strict charset: the decoded web cookie is attacker-controllable (unsigned
  // base64), and apiSession is later interpolated into a Cookie header in
  // lib/api.ts. Reject anything outside the token alphabet so a tampered
  // cookie cannot inject ';', whitespace or CRLF into that header. Real tokens
  // are sess_ + base64url and CSRF is base64url; the test fixtures
  // (sess_value, csrf_value) use the same alphabet.
  if (!/^sess_[A-Za-z0-9_-]{1,200}$/.test(v.apiSession)) return false
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(v.apiCsrf)) return false
  if (!/^[a-z0-9._-]{3,64}$/.test(v.username)) return false
  if (!(v.role === 'ADMIN' || v.role === 'ANALYST' || v.role === 'READONLY')) return false
  if (Number.isNaN(Date.parse(v.expiresAt))) return false
  return true
}

/** Reads the session from the request cookies. */
export async function readSession(): Promise<WebSession | null> {
  assertRuntimeConfig()

  const store = await cookies()
  const raw = store.get(config.cookieName)?.value
  if (!raw) return null

  const session = decodeSession(raw)
  if (!session) return null

  // An expired session is discarded here rather than being sent to the API and
  // rejected there, so the UI redirects to login on the first request instead of
  // rendering an error after a round trip.
  if (new Date(session.expiresAt).getTime() <= Date.now()) return null

  return session
}

/** Writes the session cookie. */
export async function writeSession(session: WebSession): Promise<void> {
  const store = await cookies()
  store.set(config.cookieName, encodeSession(session), cookieOptions)
}

/** Clears the session cookie. */
export async function clearSession(): Promise<void> {
  const store = await cookies()
  store.set(config.cookieName, '', { ...cookieOptions, maxAge: 0 })
}
