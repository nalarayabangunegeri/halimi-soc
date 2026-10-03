import { expect, test } from '@playwright/test'
import { API, enrollAgent, ingest, signIn, sshFailureEvent, sshSuccessEvent } from './helpers'

// The dashboard end-to-end suite.
//
// It covers the flows an operator performs, and the security boundaries the UI must
// respect. It is not a rendering test: every assertion is about a decision the
// operator or the system makes.

test.describe('authentication', () => {
  test('redirects an unauthenticated visitor to the login page', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.getByRole('heading', { name: 'HalimiSOC' })).toBeVisible()
  })

  test('rejects bad credentials without revealing whether the account exists', async ({ page }) => {
    await page.goto('/login')

    await page.getByLabel('Username').fill('admin')
    await page.getByLabel('Password').fill('definitely-wrong-password')
    await page.getByRole('button', { name: 'Sign in' }).click()
    const knownAccountError = await page.locator('.error-banner').textContent()

    await page.getByLabel('Username').fill('no-such-operator')
    await page.getByLabel('Password').fill('definitely-wrong-password')
    await page.getByRole('button', { name: 'Sign in' }).click()
    const unknownAccountError = await page.locator('.error-banner').textContent()

    // The two responses must be indistinguishable, or the login form is an account
    // enumeration oracle.
    expect(knownAccountError).toBe(unknownAccountError)
    await expect(page).toHaveURL(/\/login$/)
  })

  test('signs in and out', async ({ page }) => {
    await signIn(page)

    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/login$/)

    // Going back must not restore the session: the cookie is cleared and revoked.
    await page.goto('/alerts')
    await expect(page).toHaveURL(/\/login$/)
  })
})

test.describe('navigation and rendering', () => {
  test.beforeEach(async ({ page }) => {
    await signIn(page)
  })

  test('renders every console page', async ({ page }) => {
    for (const [path, heading] of [
      ['/alerts', 'Alerts'],
      ['/incidents', 'Incidents'],
      ['/events', 'Events'],
      ['/assets', 'Assets'],
      ['/agents', 'Agents'],
      ['/rules', 'Detection rules'],
      ['/audit', 'Audit log'],
    ] as const) {
      await page.goto(path)
      await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible()
    }
  })

  test('lists the loaded detection rules with their severity', async ({ page }) => {
    await page.goto('/rules')
    await expect(page.getByText('ssh-bruteforce').first()).toBeVisible()
    await expect(page.getByText('SSH Brute Force').first()).toBeVisible()
    // Eight rules ship: the SSH/sudo set, the HTTP authentication spike and
    // the firewall port scan.
    await expect(page.getByText('8 rule(s) loaded')).toBeVisible()
    await expect(page.getByText('http-auth-failure-spike').first()).toBeVisible()
    await expect(page.getByText('firewall-port-scan').first()).toBeVisible()
  })

  test('states that severity comes from the rule, not from AI', async ({ page }) => {
    await page.goto('/rules')
    await expect(page.getByText(/Severity comes from the rule, never from the event/)).toBeVisible()
  })
})

test.describe('detection through the UI', () => {
  test('shows a new alert in realtime, without a reload', async ({ page, request }) => {
    const host = `e2e-ui-${Date.now()}`
    await signIn(page)

    const { token } = await enrollAgent(request, host)

    // The alert list is open before anything is ingested, so a passing assertion
    // proves the update arrived over the stream rather than from the initial render.
    await page.goto('/alerts')
    // exact, because "0 alerts" in the card title also contains the word.
    await expect(page.getByRole('heading', { name: 'Alerts', exact: true })).toBeVisible()
    await expect(page.getByText('No alerts match these filters')).toBeVisible()

    const base = new Date(Date.now() - 60_000)
    const events = Array.from({ length: 5 }, (_, i) =>
      sshFailureEvent(host, '203.0.113.90', new Date(base.getTime() + i * 1000)),
    )
    await ingest(request, token, events)

    // No page.reload() anywhere: the stream must drive this.
    await expect(page.getByText('ssh-bruteforce').first()).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText(`host ${host}`).first()).toBeVisible()
    await expect(page.getByText('SSH Brute Force').first()).toBeVisible()

    // The connection indicator reports the live state.
    await expect(page.locator('.live-connected')).toBeVisible()
  })

  test('correlates into an incident with an ordered timeline', async ({ page, request }) => {
    const host = `e2e-inc-${Date.now()}`
    await signIn(page)

    const { token } = await enrollAgent(request, host)
    const base = new Date(Date.now() - 60_000)

    // A brute force, then a successful login, then persistence. This is the shipped
    // scenario in miniature: it must produce an incident whose stages are ordered by
    // the kill chain rather than by arrival.
    await ingest(
      request,
      token,
      Array.from({ length: 5 }, (_, i) =>
        sshFailureEvent(host, '203.0.113.91', new Date(base.getTime() + i * 1000)),
      ),
    )
    await ingest(request, token, [
      sshSuccessEvent(host, '203.0.113.91', new Date(base.getTime() + 40_000)),
    ])

    await page.goto('/incidents')
    await expect(page.getByText(host).first()).toBeVisible({ timeout: 20_000 })

    // The stage chips make the narrative visible in the list.
    await expect(page.getByText('Credential Access').first()).toBeVisible()

    // Open the incident and check the timeline is ordered.
    await page.getByRole('link', { name: /SSH Brute Force|Successful SSH Login/ }).first().click()
    await expect(page.getByRole('heading', { name: 'Timeline' })).toBeVisible()

    const stages = await page.locator('.timeline-item').allTextContents()
    expect(stages.length).toBeGreaterThanOrEqual(2)

    // Credential access precedes initial access, because the events did.
    const credentialIndex = stages.findIndex((s) => s.includes('Credential Access'))
    const initialIndex = stages.findIndex((s) => s.includes('Initial Access'))
    expect(credentialIndex).toBeGreaterThanOrEqual(0)
    expect(initialIndex).toBeGreaterThan(credentialIndex)

    // The page explains why these alerts are one incident.
    await expect(page.getByText(/Correlation basis:/)).toBeVisible()
  })
})

test.describe('triage', () => {
  test('acknowledges an alert and the status survives a reload', async ({ page, request }) => {
    const host = `e2e-triage-${Date.now()}`
    await signIn(page)

    const { token } = await enrollAgent(request, host)
    const base = new Date(Date.now() - 60_000)
    await ingest(
      request,
      token,
      Array.from({ length: 5 }, (_, i) =>
        sshFailureEvent(host, '203.0.113.92', new Date(base.getTime() + i * 1000)),
      ),
    )

    await page.goto(`/alerts?host=${host}`)
    await expect(page.getByText('ssh-bruteforce').first()).toBeVisible({ timeout: 20_000 })

    // Scoped to the row: `getByText('Acknowledged')` also matches the status
    // filter's own ACKNOWLEDGED option, which sits earlier in the DOM and is not
    // visible while the select is closed.
    const row = page.locator('tbody tr').first()
    await row.getByRole('button', { name: 'acknowledged' }).click()
    await expect(row.locator('.badge-status')).toHaveText('Acknowledged')

    // The change is server-side, so it must be visible after a full reload.
    await page.reload()
    await expect(page.locator('tbody tr').first().locator('.badge-status')).toHaveText('Acknowledged')
  })

  test('offers only the transitions the server permits', async ({ page, request }) => {
    const host = `e2e-transitions-${Date.now()}`
    await signIn(page)

    const { token } = await enrollAgent(request, host)
    const base = new Date(Date.now() - 60_000)
    await ingest(
      request,
      token,
      Array.from({ length: 5 }, (_, i) =>
        sshFailureEvent(host, '203.0.113.93', new Date(base.getTime() + i * 1000)),
      ),
    )

    await page.goto(`/alerts?host=${host}`)
    await expect(page.getByText('ssh-bruteforce').first()).toBeVisible({ timeout: 20_000 })

    const row = page.locator('tbody tr').first()
    // From OPEN, the state machine allows exactly these three.
    await expect(row.getByRole('button')).toHaveCount(3)

    await row.getByRole('button', { name: 'resolved' }).click()
    // RESOLVED is terminal, so the row must stop offering transitions.
    await expect(row.getByText('terminal')).toBeVisible()
  })
})

test.describe('advisory analysis', () => {
  test('returns a computed, grounded summary when no provider is configured', async ({ page, request }) => {
    const host = `e2e-ai-${Date.now()}`
    await signIn(page)

    const { token } = await enrollAgent(request, host)
    const base = new Date(Date.now() - 60_000)
    await ingest(
      request,
      token,
      Array.from({ length: 5 }, (_, i) =>
        sshFailureEvent(host, '203.0.113.94', new Date(base.getTime() + i * 1000)),
      ),
    )

    await page.goto('/incidents')
    await expect(page.getByText(host).first()).toBeVisible({ timeout: 20_000 })
    await page.getByRole('link', { name: /SSH Brute Force/ }).first().click()

    await page.getByRole('button', { name: 'Explain this incident' }).click()

    // The panel must state that it is advisory and that it used no provider.
    await expect(page.getByText(/Advisory\./)).toBeVisible()
    // exact, so the badge is matched rather than the advisory notice and the
    // analysis body, both of which contain the word.
    await expect(page.getByText('computed', { exact: true })).toBeVisible()
    await expect(page.getByText(/No AI provider was used/)).toBeVisible()
    await expect(page.getByText(/Evidence supplied to the analysis/)).toBeVisible()
  })

  test('does not change incident state', async ({ page, request }) => {
    const host = `e2e-ai-state-${Date.now()}`
    await signIn(page)

    const { token } = await enrollAgent(request, host)
    const base = new Date(Date.now() - 60_000)
    await ingest(
      request,
      token,
      Array.from({ length: 5 }, (_, i) =>
        sshFailureEvent(host, '203.0.113.95', new Date(base.getTime() + i * 1000)),
      ),
    )

    await page.goto('/incidents')
    await expect(page.getByText(host).first()).toBeVisible({ timeout: 20_000 })
    await page.getByRole('link', { name: /SSH Brute Force/ }).first().click()

    const statusBefore = await page.locator('.badge-status').first().textContent()
    await page.getByRole('button', { name: 'Explain this incident' }).click()
    await expect(page.getByText(/Advisory\./)).toBeVisible()

    await page.reload()
    const statusAfter = await page.locator('.badge-status').first().textContent()
    expect(statusAfter).toBe(statusBefore)
  })
})

test.describe('security boundaries', () => {
  test('sends a per-response CSP nonce that every script it emits carries', async ({ page }) => {
    const violations: string[] = []
    page.on('console', (message) => {
      if (message.text().includes('Content Security Policy') || message.text().includes('Refused')) {
        violations.push(message.text())
      }
    })
    page.on('pageerror', (error) => violations.push(`pageerror: ${error.message}`))

    const response = await page.goto('/login')
    expect(response?.ok()).toBeTruthy()

    const csp = response?.headers()['content-security-policy'] ?? ''
    expect(csp).toContain("script-src 'self'")
    expect(csp).toMatch(/script-src[^;]*'nonce-[^']+'/)
    // A nonce admits exactly this response's inline payload. Admitting every
    // inline script would make the nonce pointless, so `'unsafe-inline'` must
    // not be there alongside it.
    expect(csp).not.toContain("script-src 'unsafe-inline'")
    // The lockdown directives the console depends on.
    expect(csp).toContain("frame-ancestors 'none'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toContain("base-uri 'none'")

    const nonce = csp.match(/script-src[^;]*'nonce-([^']+)'/)?.[1]
    expect(nonce).toBeTruthy()

    // The nonce is cleared from the content attribute by the browser so it cannot
    // be read back out of the DOM and replayed. The IDL property is what reflects
    // the value the browser actually used to decide whether to execute the tag.
    const scriptNonces = await page.$$eval('script', (scripts) =>
      scripts.map((script) => (script as HTMLScriptElement).nonce),
    )
    expect(scriptNonces.length).toBeGreaterThan(0)
    expect(scriptNonces.every((value) => value === nonce)).toBe(true)

    // A nonce that did not match would not raise an assertion — it would refuse to
    // execute and the app would silently fail to hydrate. The console listener
    // above turns that silent failure into a reported one.
    expect(violations).toEqual([])

    await expect(page.getByLabel('Password')).toBeVisible()
  })

  test('requires a CSRF token for a mutation', async ({ page, request }) => {
    await signIn(page)

    // A mutation posted without the double-submit header must be refused, even
    // though the request carries a valid session cookie.
    const response = await page.request.post('/api/proxy', {
      data: { action: 'alert.status', id: 'alt_whatever', payload: { status: 'RESOLVED' } },
    })
    expect(response.status()).toBe(403)
    expect((await response.json()).error.code).toBe('FORBIDDEN')
  })

  test('rejects an unknown proxy action', async ({ page }) => {
    await signIn(page)

    const csrf = await page.evaluate(() => {
      const match = document.cookie.match(/(?:^|;\s*)halimisoc_csrf=([^;]+)/)
      return match?.[1] ?? ''
    })
    expect(csrf).not.toBe('')

    const response = await page.request.post('/api/proxy', {
      headers: { 'x-halimisoc-csrf': csrf },
      data: { action: 'agent.deleteEverything', id: 'agt_1' },
    })
    // The dispatch table is a closed allowlist, so an unknown action is a bad
    // request rather than a passthrough.
    expect(response.status()).toBe(400)
  })

  test('shows mutation controls to an admin', async ({ page, request }) => {
    // The role matrix is enforced server-side and covered by the Go suite. What this
    // asserts is the UI half: an admin is offered the controls, because there is no
    // role for which the server would reject them.
    const host = `e2e-admin-controls-${Date.now()}`
    await signIn(page)

    const { token } = await enrollAgent(request, host)
    const base = new Date(Date.now() - 60_000)
    await ingest(
      request,
      token,
      Array.from({ length: 5 }, (_, i) =>
        sshFailureEvent(host, '203.0.113.96', new Date(base.getTime() + i * 1000)),
      ),
    )

    await page.goto(`/alerts?host=${host}`)
    await expect(page.getByText('ssh-bruteforce').first()).toBeVisible({ timeout: 20_000 })
    await expect(page.locator('tbody tr').first().getByRole('button').first()).toBeVisible()
  })

  test('rejects an agent credential on an operator route', async ({ page, request }) => {
    const { token } = await enrollAgent(request, `e2e-agent-scope-${Date.now()}`)

    // An agent token must not open an operator session or reach operator data.
    // Against the API directly: the dashboard exposes no /api/v1/* to the
    // browser, so a relative path would be resolved by the Next server and 404
    // without ever reaching the authorization check under test.
    const response = await request.get(`${API}/api/v1/alerts`, {
      headers: { Authorization: `Bearer ${token}` },
      failOnStatusCode: false,
    })
    expect(response.status()).toBe(401)
  })
})

test.describe('rule authoring', () => {
  const doc = [
    'id: e2e-authored-rule',
    'version: 1',
    'name: E2E Authored Rule',
    'description: Written through the console proxy',
    'severity: low',
    'match:',
    '  types:',
    '    - auth.ssh.login_failed',
    'threshold:',
    '  count: 1000',
    '  window: 60s',
    'group_by:',
    '  - network.src_ip',
    'cooldown: 5m',
    '',
  ].join('\n')

  test('validates, saves and lists a rule through the proxy', async ({ page }) => {
    await signIn(page)
    const token = await page.evaluate(() => {
      const match = document.cookie.match(/(?:^|;\s*)halimisoc_csrf=([^;]+)/)
      return match?.[1] ?? ''
    })
    expect(token).not.toBe('')

    const headers = { 'x-halimisoc-csrf': token }

    // Invalid YAML is rejected before anything is stored.
    const bad = await page.request.post('/api/proxy', {
      headers,
      data: { action: 'rules.validate', id: '-', payload: { yaml: 'id: nope\n' } },
    })
    expect(bad.status()).toBe(400)

    const good = await page.request.post('/api/proxy', {
      headers,
      data: { action: 'rules.validate', id: '-', payload: { yaml: doc } },
    })
    expect(good.status()).toBe(200)

    const saved = await page.request.post('/api/proxy', {
      headers,
      data: { action: 'rules.save', id: 'e2e-authored-rule', payload: { yaml: doc } },
    })
    expect([200, 201]).toContain(saved.status())

    const reloaded = await page.request.post('/api/proxy', {
      headers,
      data: { action: 'rules.reload', id: '-' },
    })
    expect(reloaded.status()).toBe(200)

    await page.goto('/rules')
    await expect(page.getByText('e2e-authored-rule').first()).toBeVisible()

    // Cleanup so the suite stays order-independent.
    const deleted = await page.request.post('/api/proxy', {
      headers,
      data: { action: 'rules.delete', id: 'e2e-authored-rule' },
    })
    expect(deleted.status()).toBe(200)
    await page.request.post('/api/proxy', { headers, data: { action: 'rules.reload', id: '-' } })
  })

  test('renders the authoring pages', async ({ page }) => {
    await signIn(page)
    await page.goto('/rules/new')
    await expect(page.getByRole('heading', { name: 'New rule', level: 1 })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Validate' })).toBeVisible()
  })
})
