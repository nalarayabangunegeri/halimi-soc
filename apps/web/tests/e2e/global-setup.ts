import { spawn, execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

// Starts the Go API against a test database for the dashboard suite.
//
// It refuses to run without HALIMISOC_TEST_DATABASE_URL, and the database name must
// end in `_test`, matching the Go end-to-end test's guard. A UI test that truncated a
// real database would be a far worse outcome than a skipped test.

const PID_FILE = join(tmpdir(), 'halimisoc-e2e-api.pid')
const LOG_FILE = join(tmpdir(), 'halimisoc-e2e-api.log')

const API_PORT = Number(process.env.HALIMISOC_E2E_API_PORT ?? 18090)
const ADMIN = { username: 'admin', password: 'e2e-dashboard-password' }
const ENROLL_SECRET = 'e2e-dashboard-enrollment-secret'

// Mirrors `appTables` in tests/reset_test.go, which is what the Go end-to-end
// test empties. Both suites share HALIMISOC_TEST_DATABASE_URL.
const APP_TABLES = [
  'audit_logs',
  'incidents',
  'alerts',
  'events',
  'agent_tokens',
  'agents',
  'sessions',
  'users',
]

const repoRoot = resolve(process.cwd(), '..', '..')

/**
 * Empties the application tables before the API starts.
 *
 * Without this the suite is order-dependent on everything else that touches the
 * test database. The API seeds the administrator only when the users table is
 * empty, so a row left by another suite — with a different password — makes every
 * login in this one fail with "invalid credentials" while the product is behaving
 * exactly as configured. Leftover alerts make it worse still: correlation would
 * correctly merge a fresh run's alerts into a previous run's incident, and the
 * "a new incident was created" assertion would fail for the same reason.
 *
 * Resetting here rather than in a test keeps the whole suite runnable in any
 * order and against a database another suite just used.
 *
 * It refuses to run unless the database name ends in `_test`. A truncate against
 * the wrong connection string would destroy real telemetry, and a name check is
 * the cheapest guard that cannot be defeated by a typo in a different variable.
 */
function resetDatabase(dsn: string): void {
  const pathname = new URL(dsn).pathname
  if (!pathname.endsWith('_test')) {
    throw new Error(`Refusing to truncate database ${pathname}: the name must end in _test`)
  }

  const statement = `TRUNCATE TABLE ${APP_TABLES.join(', ')} RESTART IDENTITY CASCADE`
  try {
    execFileSync('psql', [dsn, '-X', '-v', 'ON_ERROR_STOP=1', '-q', '-c', statement], {
      stdio: ['ignore', 'ignore', 'pipe'],
    })
  } catch (error) {
    // A missing table means migrations have not run yet, which is not a failure
    // of this helper: the API applies them at startup.
    const message = error instanceof Error ? error.message : String(error)
    if (message.includes('does not exist')) return
    throw new Error(`reset test database: ${message}`)
  }
}

export default async function globalSetup(): Promise<void> {
  const dsn = process.env.HALIMISOC_TEST_DATABASE_URL
  if (!dsn) {
    throw new Error(
      'HALIMISOC_TEST_DATABASE_URL must be set to run the dashboard end-to-end suite.',
    )
  }
  if (!/_test(\?|$)/.test(new URL(dsn).pathname) && !new URL(dsn).pathname.endsWith('_test')) {
    throw new Error(`Refusing to run against ${new URL(dsn).pathname}: the database name must end in _test`)
  }

  resetDatabase(dsn)

  // The API is built from source so the suite tests the working tree, not a stale
  // binary left over from a previous run.
  const binary = join(tmpdir(), 'halimisoc-e2e-api')
  execFileSync('go', ['build', '-o', binary, './apps/api'], { cwd: repoRoot, stdio: 'inherit' })

  const child = spawn(binary, [], {
    cwd: repoRoot,
    env: {
      ...process.env,
      HALIMISOC_ENV: 'development',
      HALIMISOC_LISTEN_ADDR: `127.0.0.1:${API_PORT}`,
      HALIMISOC_DATABASE_URL: dsn,
      HALIMISOC_ADMIN_USER: ADMIN.username,
      HALIMISOC_ADMIN_PASSWORD: ADMIN.password,
      HALIMISOC_AGENT_ENROLL_SECRET: ENROLL_SECRET,
      HALIMISOC_RULES_PATH: 'packages/rules',
      HALIMISOC_LOG_LEVEL: 'info',
    },
    stdio: 'ignore',
    detached: true,
  })
  child.unref()

  if (!child.pid) throw new Error('the API process did not start')
  writeFileSync(PID_FILE, String(child.pid))

  await waitForReady(`http://127.0.0.1:${API_PORT}/api/v1/readiness`, LOG_FILE)
}

async function waitForReady(url: string, logFile: string): Promise<void> {
  const deadline = Date.now() + 60_000
  let lastError = 'no response'

  while (Date.now() < deadline) {
    try {
      const response = await fetch(url)
      if (response.ok) return
      lastError = `status ${response.status}`
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error)
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }

  throw new Error(`the API did not become ready at ${url} (${lastError}); log: ${logFile}`)
}
