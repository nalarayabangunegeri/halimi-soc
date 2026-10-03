import { defineConfig, devices } from '@playwright/test'

// End-to-end configuration for the dashboard.
//
// Two processes are involved: the Go API and this dashboard. The API is started by
// the global setup (it needs a database and a seeded administrator), and the
// dashboard is started by Playwright's webServer so Playwright can wait for it and
// shut it down.
//
// The suite requires HALIMISOC_TEST_DATABASE_URL and refuses to run without it,
// matching the Go end-to-end test. A UI test that silently ran against a real
// database would be worse than a skipped test.

const WEB_PORT = Number(process.env.HALIMISOC_E2E_WEB_PORT ?? 3100)
const API_PORT = Number(process.env.HALIMISOC_E2E_API_PORT ?? 18090)

export const E2E = {
  webPort: WEB_PORT,
  apiPort: API_PORT,
  baseURL: `http://127.0.0.1:${WEB_PORT}`,
  apiURL: `http://127.0.0.1:${API_PORT}`,
  admin: { username: 'admin', password: 'e2e-dashboard-password' },
  enrollSecret: 'e2e-dashboard-enrollment-secret',
}

export default defineConfig({
  testDir: './tests/e2e',
  // These tests drive real processes and a real database. Running them in parallel
  // would have them fight over the same fixtures and the same connection cap.
  fullyParallel: false,
  workers: 1,

  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },

  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],

  globalSetup: './tests/e2e/global-setup.ts',
  globalTeardown: './tests/e2e/global-teardown.ts',

  use: {
    baseURL: E2E.baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  webServer: {
    // A production build is served, not the dev server: the dev server has
    // different caching and error behaviour, and the point of this suite is to
    // check what the operator will actually run.
    command: `npx next start -p ${WEB_PORT}`,
    url: E2E.baseURL + '/login',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      HALIMISOC_API_URL: E2E.apiURL,
      // The suite drives http://127.0.0.1, where a Secure cookie is never sent.
      // Both variables are set explicitly: the second is the acknowledgement that
      // makes the first acceptable to the runtime guard.
      HALIMISOC_WEB_SECURE_COOKIES: 'false',
      HALIMISOC_WEB_ALLOW_INSECURE_COOKIES: 'true',
      HALIMISOC_API_SECURE_COOKIES: 'false',
      NODE_ENV: 'production',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  },
})
