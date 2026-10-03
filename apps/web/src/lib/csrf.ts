import 'server-only'

import { cookies } from 'next/headers'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { config } from './config'

// CSRF protection for the browser-to-dashboard boundary.
//
// The dashboard's session cookie is SameSite=Strict, which already prevents it
// from being sent on a cross-site request. This is the second layer: a
// synchroniser token, delivered in a readable cookie and echoed in a header.
//
// A readable cookie is correct here. The value is not a bearer credential; it
// only demonstrates that the caller could read this origin's cookies, which a
// cross-site page cannot do. A cross-site form post cannot set the header at all,
// and a cross-site fetch that tries triggers a preflight this app does not
// answer permissively.

export const CSRF_HEADER = 'x-halimisoc-csrf'

/** Issues a new CSRF token and stores its readable cookie. */
export async function issueCsrfToken(): Promise<string> {
  const token = randomBytes(32).toString('base64url')
  const store = await cookies()
  store.set(config.csrfCookieName, token, {
    httpOnly: false, // must be readable so the page can echo it
    sameSite: 'strict',
    secure: config.secureCookies,
    path: '/',
    maxAge: 60 * 60 * 12,
  })
  return token
}

/** Clears the CSRF cookie. */
export async function clearCsrfToken(): Promise<void> {
  const store = await cookies()
  store.set(config.csrfCookieName, '', {
    httpOnly: false,
    sameSite: 'strict',
    secure: config.secureCookies,
    path: '/',
    maxAge: 0,
  })
}

/**
 * Verifies that a mutating request presented the matching CSRF token.
 *
 * It fails closed on a missing cookie, a missing header, or any length mismatch,
 * and compares in constant time so the token cannot be recovered byte by byte.
 */
export async function verifyCsrf(request: Request): Promise<boolean> {
  const store = await cookies()
  const cookieToken = store.get(config.csrfCookieName)?.value ?? ''
  const headerToken = request.headers.get(CSRF_HEADER) ?? ''

  if (!cookieToken || !headerToken) return false

  const a = Buffer.from(cookieToken)
  const b = Buffer.from(headerToken)
  if (a.length !== b.length) return false

  return timingSafeEqual(a, b)
}
