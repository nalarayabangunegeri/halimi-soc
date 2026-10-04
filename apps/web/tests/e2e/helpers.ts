import { expect, type Page, type APIRequestContext } from '@playwright/test'
import { createHmac } from 'node:crypto'

// Shared helpers for the dashboard suite.

export const ADMIN = { username: 'admin', password: 'e2e-dashboard-password' }
export const ENROLL_SECRET = 'e2e-dashboard-enrollment-secret'

// Exported because some assertions have to reach the Go API directly: the
// dashboard is a BFF that deliberately never exposes /api/v1/* to the browser, so
// a relative path against baseURL resolves to a route that does not exist.
export const API = `http://127.0.0.1:${process.env.HALIMISOC_E2E_API_PORT ?? 18090}`

/** Signs in through the dashboard's own login form. */
export async function signIn(page: Page, username = ADMIN.username, password = ADMIN.password): Promise<void> {
  await page.goto('/login')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
}

/**
 * Signs in as an MFA-enrolled operator through the dashboard's two-step form.
 *
 * `getCode` is called after the password step returns MFA_REQUIRED; it receives
 * the TOTP secret captured during enrollment and must return the current code.
 */
export async function signInWithMFA(
  page: Page,
  username: string,
  password: string,
  getCode: () => string,
): Promise<void> {
  await page.goto('/login')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  // The form reveals the second-factor field only when the API answers
  // MFA_REQUIRED: asserting it here proves the prompt is not shown upfront.
  await expect(page.getByLabel('Authenticator code or backup code')).toBeVisible()
  await page.getByLabel('Authenticator code or backup code').fill(getCode())
  await page.getByRole('button', { name: 'Verify and sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
}

/**
 * Enrolls an agent and returns its token.
 *
 * The enrolment goes straight to the API rather than through the dashboard: the API
 * is the contract under test for ingestion, and the dashboard has no enrolment UI in
 * the MVP.
 */
export async function enrollAgent(request: APIRequestContext, host: string): Promise<{ token: string; id: string }> {
  const response = await request.post(`${API}/api/v1/agents/register`, {
    data: { enrollment_secret: ENROLL_SECRET, host, os: 'linux/amd64', version: 'e2e' },
  })
  expect(response.ok(), `enrolment failed: ${response.status()} ${await response.text()}`).toBeTruthy()

  const body = (await response.json()) as { agent_token: string; agent_id: string }
  return { token: body.agent_token, id: body.agent_id }
}

interface SyntheticEvent {
  id: string
  type: string
  time: string
  host: string
  actor?: string
  source: string
  outcome?: string
  severity: string
  network?: { src_ip?: string; src_port?: number }
  raw: string
  attributes?: Record<string, string>
}

/** Builds a successful SSH login event. */
export function sshSuccessEvent(host: string, srcIP: string, at: Date): SyntheticEvent {
  return {
    id: newEventID(),
    type: 'auth.ssh.login_success',
    time: at.toISOString(),
    host,
    actor: 'root',
    source: 'auth.log',
    outcome: 'success',
    severity: 'low',
    network: { src_ip: srcIP, src_port: 41_000 },
    attributes: { parser: 'sshd' },
    raw: `Aug 19 11:21:10 ${host} sshd[2100]: Accepted password for root from ${srcIP} port 41000 ssh2`,
  }
}

/**
 * Builds a failed SSH login event with a fresh, well-formed identifier.
 *
 * The id must be a producer-generated ULID: the server uses it as the idempotency
 * key, so a malformed one is rejected rather than accepted and regenerated.
 */
export function sshFailureEvent(host: string, srcIP: string, at: Date): SyntheticEvent {
  return {
    id: newEventID(),
    type: 'auth.ssh.login_failed',
    time: at.toISOString(),
    host,
    actor: 'root',
    source: 'auth.log',
    outcome: 'failure',
    severity: 'medium',
    network: { src_ip: srcIP, src_port: 51022 },
    attributes: { parser: 'sshd' },
    raw: `Aug 19 11:20:30 ${host} sshd[1823]: Failed password for root from ${srcIP} port 51022 ssh2`,
  }
}

/** Delivers a batch of events as an enrolled agent. */
export async function ingest(
  request: APIRequestContext,
  token: string,
  events: SyntheticEvent[],
): Promise<void> {
  const response = await request.post(`${API}/api/v1/events`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { events },
  })
  expect(response.status(), `ingest failed: ${await response.text()}`).toBe(202)
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
/**
 * Generates a ULID-shaped identifier that matches the server's format.
 *
 * The server validates the id strictly and uses it as the idempotency key, so a
 * fixture cannot take a shortcut here: an id it would reject is an id that would
 * make the test fail for the wrong reason.
 *
 * Layout: 48-bit millisecond timestamp, then 80 bits of randomness, rendered as 26
 * Crockford base32 characters (the two spare leading bits of the 130-bit encoding
 * are the padding).
 */
function newEventID(): string {
  const time = BigInt(Date.now()) & 0xffffffffffffn
  const random = BigInt.asUintN(80, BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)))
  const value = (time << 80n) | random

  let encoded = ''
  for (let i = 25; i >= 0; i--) {
    encoded = CROCKFORD[Number((value >> BigInt(i * 5)) & 31n)] + encoded
  }
  return `evt_${encoded}`
}

/**
 * Computes a TOTP code for a base32 (no-padding) secret.
 *
 * Test-only twin of `internal/mfa`: 6 digits, 30s step, SHA1. Kept here rather
 * than imported so the black-box suite never shares code with the system under
 * test — agreement between two independent implementations is the assertion.
 */
export function totpCode(secret: string, at = Date.now()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = secret.replace(/=+$/, '').toUpperCase()
  const bits: number[] = []
  for (const ch of clean) {
    const v = alphabet.indexOf(ch)
    if (v < 0) throw new Error(`bad base32 character ${ch}`)
    for (let i = 4; i >= 0; i--) bits.push((v >> i) & 1)
  }
  const bytes = new Uint8Array(bits.length >> 3)
  for (let i = 0; i < bytes.length; i++) {
    let b = 0
    for (let j = 0; j < 8; j++) b = (b << 1) | (bits[i * 8 + j] ?? 0)
    bytes[i] = b
  }
  const counter = Math.floor(at / 1000 / 30)
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(counter))
  const mac = createHmac('sha1', Buffer.from(bytes)).update(msg).digest()
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f
  const bin =
    (((mac[offset] ?? 0) & 0x7f) << 24) |
    ((mac[offset + 1] ?? 0) << 16) |
    ((mac[offset + 2] ?? 0) << 8) |
    (mac[offset + 3] ?? 0)
  return String(bin % 1_000_000).padStart(6, '0')
}
