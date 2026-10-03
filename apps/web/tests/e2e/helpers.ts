import { expect, type Page, type APIRequestContext } from '@playwright/test'

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
  await page.getByRole('button', { name: 'Sign in' }).click()
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
