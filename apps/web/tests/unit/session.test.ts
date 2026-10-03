// @vitest-environment node

import { describe, expect, it } from 'vitest'
import { decodeSession, encodeSession, type WebSession } from '@/lib/session'

// The session codec is the boundary between the browser cookie and the API
// credential. A decode that accepted a malformed payload would be a way to
// influence how the dashboard authenticates, so the negative cases matter more
// than the positive one.

const valid: WebSession = {
  apiSession: 'sess_value',
  apiCsrf: 'csrf_value',
  username: 'admin',
  role: 'ADMIN',
  expiresAt: '2099-01-01T00:00:00Z',
}

describe('session codec', () => {
  it('round-trips a valid session', () => {
    const decoded = decodeSession(encodeSession(valid))
    expect(decoded).toEqual(valid)
  })

  it('rejects anything that is not a valid session', () => {
    const cases: Record<string, string> = {
      empty: '',
      garbage: 'not-base64-json',
      'valid base64, wrong shape': Buffer.from('{"hello":"world"}').toString('base64url'),
      'missing api session': Buffer.from(
        JSON.stringify({ apiCsrf: 'c', username: 'a', role: 'ADMIN', expiresAt: '2099-01-01T00:00:00Z' }),
      ).toString('base64url'),
      'empty api session': Buffer.from(
        JSON.stringify({ apiSession: '', apiCsrf: 'c', username: 'a', role: 'ADMIN', expiresAt: '2099-01-01T00:00:00Z' }),
      ).toString('base64url'),
      'unknown role': Buffer.from(
        JSON.stringify({ apiSession: 's', apiCsrf: 'c', username: 'a', role: 'SUPERUSER', expiresAt: '2099-01-01T00:00:00Z' }),
      ).toString('base64url'),
      'wrong value types': Buffer.from(
        JSON.stringify({ apiSession: 1, apiCsrf: 'c', username: 'a', role: 'ADMIN', expiresAt: '2099-01-01T00:00:00Z' }),
      ).toString('base64url'),
    }

    for (const [name, raw] of Object.entries(cases)) {
      expect(decodeSession(raw), name).toBeNull()
    }
  })

  it('accepts every canonical role', () => {
    for (const role of ['ADMIN', 'ANALYST', 'READONLY'] as const) {
      const decoded = decodeSession(encodeSession({ ...valid, role }))
      expect(decoded?.role, role).toBe(role)
    }
  })

  it('does not leak the payload in plain text', () => {
    // The cookie value is base64, not encrypted. This test documents that the
    // protection is HttpOnly plus the fact that it is not the API credential —
    // not obfuscation.
    const encoded = encodeSession(valid)
    expect(encoded).not.toContain('csrf_value')
  })
})
