// @vitest-environment node

import { describe, expect, it } from 'vitest'
import { extractSessionCookie } from '@/lib/api'

// `extractSessionCookie` decides which value the dashboard stores as the API
// session. It is the one piece of parsing between the API's response and this app's
// authentication, so a parser that picked the wrong cookie, or accepted an empty
// one, would be a session-handling defect.

describe('extractSessionCookie', () => {
  it('reads the plain development cookie', () => {
    const header = 'halimisoc_session=abc123; Path=/; HttpOnly; SameSite=Lax'
    expect(extractSessionCookie(header)).toBe('abc123')
  })

  it('reads the __Host- cookie used over TLS', () => {
    const header = '__Host-halimisoc_session=xyz789; Path=/; Secure; HttpOnly; SameSite=Lax'
    expect(extractSessionCookie(header)).toBe('xyz789')
  })

  it('reads the session cookie when it is not first', () => {
    const header = 'other=1; Path=/, halimisoc_session=second; Path=/'
    expect(extractSessionCookie(header)).toBe('second')
  })

  it('treats an empty value as no session', () => {
    // A cleared cookie is a logout, not a session with an empty credential.
    expect(extractSessionCookie('halimisoc_session=; Path=/')).toBeNull()
    expect(extractSessionCookie('__Host-halimisoc_session=; Path=/')).toBeNull()
  })

  it('returns null when no session cookie is present', () => {
    expect(extractSessionCookie('')).toBeNull()
    expect(extractSessionCookie('theme=dark; Path=/')).toBeNull()
    expect(extractSessionCookie('not-a-cookie-at-all')).toBeNull()
  })

  it('does not mistake a look-alike name for the session cookie', () => {
    // A cookie whose name merely contains the session name must not be accepted.
    expect(extractSessionCookie('halimisoc_session_old=stale; Path=/')).toBeNull()
    expect(extractSessionCookie('xhalimisoc_session=stale; Path=/')).toBeNull()
  })

  it('accepts a base64url value unchanged', () => {
    const value = 'aBcD-_.0123456789'
    expect(extractSessionCookie(`halimisoc_session=${value}; Path=/`)).toBe(value)
  })
})
