// @vitest-environment node

import { afterEach, describe, expect, it, vi } from 'vitest'

// The guard is a security control, not a nicety: without it a production build
// will happily send the operator's session cookie over cleartext, and it will
// fail open rather than loudly if the API address was simply never set. Those
// two conditions are exactly the ones an operator would not notice until
// something else broke, so they are asserted here rather than left to
// configuration review.
//
// `config` is derived from process.env at import time, so each case re-imports
// with a controlled environment instead of mutating the shared object.

const base = {
  NODE_ENV: 'production',
  HALIMISOC_API_URL: 'https://api.internal.example',
}

async function load(env: Record<string, string | undefined>) {
  vi.resetModules()
  const keys = [
    'NODE_ENV',
    'NEXT_PHASE',
    'HALIMISOC_API_URL',
    'HALIMISOC_WEB_SECURE_COOKIES',
    'HALIMISOC_WEB_ALLOW_INSECURE_COOKIES',
  ]
  for (const key of keys) delete process.env[key]
  for (const [key, val] of Object.entries(env)) {
    if (val === undefined) delete process.env[key]
    else process.env[key] = val
  }
  return await import('@/lib/config')
}

afterEach(() => {
  for (const key of [
    'NEXT_PHASE',
    'HALIMISOC_API_URL',
    'HALIMISOC_WEB_SECURE_COOKIES',
    'HALIMISOC_WEB_ALLOW_INSECURE_COOKIES',
  ]) {
    delete process.env[key]
  }
  vi.resetModules()
})

describe('production cookie guard', () => {
  it('refuses to serve a session cookie over cleartext', async () => {
    const { assertRuntimeConfig, ConfigError } = await load({
      ...base,
      HALIMISOC_WEB_SECURE_COOKIES: 'false',
    })
    expect(() => assertRuntimeConfig()).toThrow(ConfigError)
    expect(() => assertRuntimeConfig()).toThrow('HALIMISOC_WEB_ALLOW_INSECURE_COOKIES')
  })

  it('serves over cleartext only when the risk is explicitly acknowledged', async () => {
    const { assertRuntimeConfig, config } = await load({
      ...base,
      HALIMISOC_WEB_SECURE_COOKIES: 'false',
      HALIMISOC_WEB_ALLOW_INSECURE_COOKIES: 'true',
    })
    expect(config.secureCookies).toBe(false)
    expect(config.allowInsecureCookies).toBe(true)
    expect(() => assertRuntimeConfig()).not.toThrow()
  })

  it('defaults to secure cookies in production when nothing is configured', async () => {
    const { assertRuntimeConfig, config } = await load(base)
    expect(config.secureCookies).toBe(true)
    expect(() => assertRuntimeConfig()).not.toThrow()
  })

  it('refuses to talk to a silently defaulted API address', async () => {
    const { assertRuntimeConfig, ConfigError } = await load({
      NODE_ENV: 'production',
      HALIMISOC_API_URL: undefined,
    })
    expect(() => assertRuntimeConfig()).toThrow(ConfigError)
    expect(() => assertRuntimeConfig()).toThrow('HALIMISOC_API_URL')
  })

  it('does not require runtime secrets while the build is running', async () => {
    // `next build` runs with NODE_ENV=production and has no reason to hold
    // deployment values. Failing here would break every pipeline that builds
    // before it configures.
    const { assertRuntimeConfig } = await load({
      NODE_ENV: 'production',
      HALIMISOC_API_URL: undefined,
      HALIMISOC_WEB_SECURE_COOKIES: 'false',
      NEXT_PHASE: 'phase-production-build',
    })
    expect(() => assertRuntimeConfig()).not.toThrow()
  })

  it('does not apply the production guard outside production', async () => {
    const { assertRuntimeConfig } = await load({
      NODE_ENV: 'development',
      HALIMISOC_API_URL: undefined,
      HALIMISOC_WEB_SECURE_COOKIES: 'false',
    })
    expect(() => assertRuntimeConfig()).not.toThrow()
  })

  it('keeps the console cookie, API cookie and CSRF cookie distinct', async () => {
    // The proxy relays the API's Set-Cookie to the browser alongside the
    // console's own. If the names collided the console's session would overwrite
    // the API's (or vice versa) and the failure would look like random logouts.
    const { config } = await load(base)
    expect(new Set([config.cookieName, config.apiCookieName, config.csrfCookieName]).size).toBe(3)
  })
})
