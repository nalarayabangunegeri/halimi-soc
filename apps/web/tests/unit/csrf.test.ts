// @vitest-environment node

import { describe, expect, it, vi, beforeEach } from 'vitest'

// CSRF verification is stubbed at the cookie layer so the comparison logic can be
// tested directly. This is the control that decides whether a mutation is allowed,
// so its failing cases are the interesting ones.

const cookieStore = new Map<string, string>()

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (cookieStore.has(name) ? { name, value: cookieStore.get(name) } : undefined),
    set: (name: string, value: string) => {
      cookieStore.set(name, value)
    },
  }),
}))

const { verifyCsrf, CSRF_HEADER, issueCsrfToken, clearCsrfToken } = await import('@/lib/csrf')

function requestWith(token?: string): Request {
  const headers = new Headers()
  if (token !== undefined) headers.set(CSRF_HEADER, token)
  return new Request('http://localhost/api/proxy', { method: 'POST', headers })
}

describe('csrf', () => {
  beforeEach(() => {
    cookieStore.clear()
  })

  it('accepts a matching token', async () => {
    const token = await issueCsrfToken()
    await expect(verifyCsrf(requestWith(token))).resolves.toBe(true)
  })

  it('rejects a mismatched token', async () => {
    await issueCsrfToken()
    await expect(verifyCsrf(requestWith('wrong-value'))).resolves.toBe(false)
  })

  it('fails closed on a missing header', async () => {
    await issueCsrfToken()
    await expect(verifyCsrf(requestWith(undefined))).resolves.toBe(false)
  })

  it('fails closed on a missing cookie', async () => {
    // A header alone must not be enough: that is the whole point of the
    // double-submit pattern.
    expect(cookieStore.size).toBe(0)
    await expect(verifyCsrf(requestWith('anything'))).resolves.toBe(false)
  })

  it('rejects a token of a different length without comparing', async () => {
    const token = await issueCsrfToken()
    await expect(verifyCsrf(requestWith(token + 'x'))).resolves.toBe(false)
    await expect(verifyCsrf(requestWith(token.slice(0, -1)))).resolves.toBe(false)
  })

  it('clears the token', async () => {
    const token = await issueCsrfToken()
    await expect(verifyCsrf(requestWith(token))).resolves.toBe(true)
    await clearCsrfToken()
    await expect(verifyCsrf(requestWith(token))).resolves.toBe(false)
  })

  it('issues a fresh token each time', async () => {
    const first = await issueCsrfToken()
    const second = await issueCsrfToken()
    expect(first).not.toBe(second)
    // A short token would be guessable, which would defeat the control.
    expect(first.length).toBeGreaterThanOrEqual(32)
  })
})
