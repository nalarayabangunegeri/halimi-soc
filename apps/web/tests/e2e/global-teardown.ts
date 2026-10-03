import { readFileSync, existsSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const PID_FILE = join(tmpdir(), 'halimisoc-e2e-api.pid')

// Stops the API the setup started.
//
// The pid is written to a file rather than kept in a module variable because
// Playwright runs global setup and teardown in separate contexts.
export default async function globalTeardown(): Promise<void> {
  if (!existsSync(PID_FILE)) return
  const pid = Number(readFileSync(PID_FILE, 'utf8').trim())
  if (Number.isFinite(pid) && pid > 1) {
    try {
      process.kill(pid, 'SIGTERM')
    } catch {
      // Already gone.
    }
  }
  try {
    unlinkSync(PID_FILE)
  } catch {
    // Nothing to clean.
  }
}
