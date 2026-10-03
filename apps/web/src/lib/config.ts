// Server-side configuration.
//
// Every value is read on the server only. None of it reaches the browser: the API
// address and the cookie names are implementation details, and publishing them
// would invite a client to try to talk to the API directly.
//
// Design note: this module never throws at import time. `next build` runs with
// NODE_ENV=production, so a module-scope production check would make the build
// require runtime secrets — the build would fail on a machine that has no reason to
// have them, and the failure would look like a code error. Configuration is
// therefore validated where it is used, on the request path, which is where a
// missing value is an actual operational problem.

const isProduction = process.env.NODE_ENV === 'production'

function value(name: string, fallback: string): string {
  const raw = process.env[name]?.trim()
  return raw && raw.length > 0 ? raw : fallback
}

function bool(name: string, fallback: boolean): boolean {
  const raw = process.env[name]?.trim().toLowerCase()
  if (raw === 'true' || raw === '1' || raw === 'yes') return true
  if (raw === 'false' || raw === '0' || raw === 'no') return false
  return fallback
}

// In production, secure cookies default to ON. A missing variable must fail safe:
// defaulting to off would silently send a session cookie over cleartext.
const secureCookiesDefault = isProduction

export const config = {
  /** The API's base URL. Requests to it are made server-side only. */
  apiUrl: value('HALIMISOC_API_URL', 'http://127.0.0.1:8080').replace(/\/+$/, ''),

  /**
   * The cookie name the API uses for its session.
   *
   * It is configured rather than probed. Sending both candidate names would work
   * but would hide a real mismatch between the API's TLS setting and this app's
   * expectation until something else broke.
   */
  apiCookieName: bool('HALIMISOC_API_SECURE_COOKIES', false)
    ? '__Host-halimisoc_session'
    : 'halimisoc_session',

  /** The cookie this app sets. Distinct from the API's, which never leaves here. */
  cookieName: value('HALIMISOC_WEB_COOKIE', 'halimisoc_web_session'),

  /**
   * The readable half of the double-submit CSRF pair.
   *
   * Readable is correct: the value is not a bearer credential, and being readable
   * is what lets the page echo it in a header, which a cross-site page cannot do.
   */
  csrfCookieName: 'halimisoc_csrf',

  secureCookies: bool('HALIMISOC_WEB_SECURE_COOKIES', secureCookiesDefault),

  /**
   * An explicit acknowledgement that the dashboard is served over plain HTTP.
   *
   * This exists because there is a real case for it: a homelab or a training
   * environment on a trusted network, and the end-to-end suite, both run over
   * http://127.0.0.1 where a Secure cookie would never be sent.
   *
   * It is a separate variable rather than an inferred condition on purpose. A guard
   * that silently relaxed itself whenever it detected a test environment would not
   * be a guard; requiring an operator to write down that they are accepting the risk
   * is the difference between a decision and an accident.
   */
  allowInsecureCookies: bool('HALIMISOC_WEB_ALLOW_INSECURE_COOKIES', false),

  isProduction,

  /** Bounds a hung API so a page renders an error instead of hanging. */
  requestTimeoutMs: 10_000,
} as const

/** Thrown when the runtime configuration would be unsafe to serve with. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConfigError'
  }
}

/**
 * Asserts that the configuration is safe to serve with.
 *
 * It is called on the request path, not at import time, for the reason described
 * at the top of this file. Both conditions it checks are ones where continuing
 * would produce a silent security downgrade rather than an obvious outage:
 * a session cookie sent over cleartext, or a dashboard quietly talking to the
 * wrong API because the variable was missing.
 */
export function assertRuntimeConfig(): void {
  if (!config.isProduction) return

  // A production build is not a running server. `next build` runs with
  // NODE_ENV=production and prerenders pages, and the machine doing the build has
  // no reason to hold runtime secrets. Enforcing them here would make the build
  // fail on a correctly configured deployment pipeline, so the check is skipped in
  // the build phase and applies only when a request is actually served.
  if (process.env.NEXT_PHASE === 'phase-production-build') return

  if (!config.secureCookies && !config.allowInsecureCookies) {
    throw new ConfigError(
      'HALIMISOC_WEB_SECURE_COOKIES is false in production, so the session cookie would be sent over cleartext. ' +
        'Either enable it, or set HALIMISOC_WEB_ALLOW_INSECURE_COOKIES=true to acknowledge that this deployment is ' +
        'served over plain HTTP on a trusted network.',
    )
  }
  if (!process.env.HALIMISOC_API_URL?.trim()) {
    throw new ConfigError(
      'HALIMISOC_API_URL must be set in production: the dashboard would silently default to a local API.',
    )
  }
}
